"""
detections/rules.py

Concrete detection rules implementing :class:`detections.base.DetectionRule`.

Each rule is deliberately narrow and single-purpose (Single
Responsibility Principle) and depends only on the shared ``Event``/
``Detection`` data contract (Dependency Inversion) -- rules never talk to
the parser or the EVTX file format directly.

Thresholds (counts, time windows) are configurable per-rule constructor
argument so they can be tuned per-environment without touching rule
logic.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from detections.base import DetectionRule
from mitre.attack_mapping import techniques_for_rule
from utils.logger import get_logger
from utils.models import Detection, Event, Severity
from parser.event_id_registry import logon_type_name

logger = get_logger(__name__)

# Well-known privileged/administrative group names (local + AD built-ins).
_PRIVILEGED_GROUP_KEYWORDS = (
    "admin",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "backup operators",
    "remote desktop users",
)

# Suspicious process names commonly abused for living-off-the-land attacks.
_SUSPICIOUS_PROCESS_NAMES = (
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "psexec.exe",
    "wmic.exe",
    "bitsadmin.exe",
)

# Command-line substrings often indicative of malicious intent.
_SUSPICIOUS_CMDLINE_MARKERS = (
    "-enc",
    "-encodedcommand",
    "downloadstring",
    "iex(",
    "invoke-expression",
    "-nop",
    "-w hidden",
    "-windowstyle hidden",
    "frombase64string",
    "bypass",
)

_ADMIN_SHARE_NAMES = ("c$", "admin$", "ipc$")


def _group_by(events: Iterable[Event], key_fn) -> dict:
    """Group events by an arbitrary key function.

    Args:
        events: Events to group.
        key_fn: Callable mapping an ``Event`` to a hashable group key.

    Returns:
        Dict of key -> list of events (preserving original order within
        each group).
    """
    groups: dict = defaultdict(list)
    for event in events:
        groups[key_fn(event)].append(event)
    return groups


def _within_sliding_window(events: list[Event], window: timedelta, threshold: int) -> list[list[Event]]:
    """Find maximal clusters of >= ``threshold`` events all within ``window``.

    Uses a sliding-window scan over chronologically sorted events (already
    guaranteed by the parser/engine contract) to find, for every position,
    the largest run of events whose time span does not exceed ``window``.
    Only *maximal* clusters are returned: if a smaller qualifying cluster
    is fully contained within a larger one for the same burst of activity,
    only the larger cluster is kept, so a single dense burst produces
    exactly one detection rather than several overlapping near-duplicates.

    Args:
        events: Chronologically sorted events (all assumed relevant/same
            group already).
        window: Maximum allowed time span for a cluster.
        threshold: Minimum number of events required to form a cluster.

    Returns:
        A list of event clusters (each a list of >= ``threshold`` events),
        with no cluster being a strict subset of another.
    """
    n = len(events)
    candidate_ranges: list[tuple[int, int]] = []
    start = 0
    for end in range(n):
        while events[end].timestamp - events[start].timestamp > window:
            start += 1
        if end - start + 1 >= threshold:
            candidate_ranges.append((start, end))

    # Keep only maximal ranges: drop any range fully contained within
    # another candidate range (same or wider start..end span).
    maximal_ranges: list[tuple[int, int]] = []
    for i, (s1, e1) in enumerate(candidate_ranges):
        contained = any(
            (s2 <= s1 and e1 <= e2) and (s2, e2) != (s1, e1)
            for s2, e2 in candidate_ranges
        )
        if not contained:
            maximal_ranges.append((s1, e1))

    # De-duplicate identical ranges that may appear from the scan.
    unique_ranges = sorted(set(maximal_ranges))
    return [events[s : e + 1] for s, e in unique_ranges]


class BruteForceLogonRule(DetectionRule):
    """Detects repeated failed logons (Event ID 4625) against one account."""

    rule_id = "brute_force_logon"
    title = "Brute Force Logon Attempt"

    def __init__(self, threshold: int = 5, window_minutes: int = 10) -> None:
        """Configure detection sensitivity.

        Args:
            threshold: Minimum number of failed logons within the window
                to trigger a detection.
            window_minutes: Sliding time window, in minutes.
        """
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Group failed logons by target user and flag dense clusters."""
        failed = self._events_of_type(events, 4625)
        detections: list[Detection] = []

        grouped = _group_by(failed, key_fn=lambda e: (e.computer, e.target_user))
        for (host, user), user_events in grouped.items():
            if not user:
                continue
            for cluster in _within_sliding_window(user_events, self.window, self.threshold):
                source_ips = sorted({e.source_ip for e in cluster if e.source_ip})
                detections.append(
                    Detection(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            f"{len(cluster)} failed logon attempts against account "
                            f"'{user}' on host '{host}' within "
                            f"{self.window.seconds // 60} minutes "
                            f"(source IP(s): {', '.join(source_ips) or 'unknown'})."
                        ),
                        severity=Severity.MEDIUM if len(cluster) < self.threshold * 2 else Severity.HIGH,
                        events=cluster,
                        mitre_techniques=techniques_for_rule(self.rule_id),
                        host=host,
                        user=user,
                        metadata={"failed_attempts": len(cluster), "source_ips": source_ips},
                    )
                )
        return detections


class SuccessfulLogonAfterBruteForceRule(DetectionRule):
    """Detects a successful logon (4624) shortly following failed attempts (4625) for the same account."""

    rule_id = "successful_logon_after_brute_force"
    title = "Successful Logon Following Failed Attempts"

    def __init__(self, min_failures: int = 3, window_minutes: int = 15) -> None:
        """Configure detection sensitivity.

        Args:
            min_failures: Minimum preceding failures required.
            window_minutes: How far back (from the success) to look for
                failures.
        """
        self.min_failures = min_failures
        self.window = timedelta(minutes=window_minutes)

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Correlate 4624 successes with preceding 4625 failure bursts per account."""
        failed = self._events_of_type(events, 4625)
        success = self._events_of_type(events, 4624)
        detections: list[Detection] = []

        failed_by_user = _group_by(failed, key_fn=lambda e: (e.computer, e.target_user))

        for succ in success:
            key = (succ.computer, succ.target_user)
            if not succ.target_user or key not in failed_by_user:
                continue
            preceding = [
                f
                for f in failed_by_user[key]
                if timedelta() <= succ.timestamp - f.timestamp <= self.window
            ]
            if len(preceding) >= self.min_failures:
                combined = sorted(preceding + [succ], key=lambda e: e.timestamp)
                detections.append(
                    Detection(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            f"Account '{succ.target_user}' successfully logged on to "
                            f"'{succ.computer}' after {len(preceding)} failed attempt(s) "
                            f"in the preceding {self.window.seconds // 60} minutes -- "
                            "consistent with a successful brute-force or password-guessing attack."
                        ),
                        severity=Severity.HIGH,
                        events=combined,
                        mitre_techniques=techniques_for_rule(self.rule_id),
                        host=succ.computer,
                        user=succ.target_user,
                        metadata={"preceding_failures": len(preceding)},
                    )
                )
        return detections


class AccountCreatedRule(DetectionRule):
    """Detects new local/domain user account creation (Event ID 4720)."""

    rule_id = "account_created"
    title = "New User Account Created"

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Flag every 4720 event as a low/medium severity account-creation detection."""
        detections: list[Detection] = []
        for event in self._events_of_type(events, 4720):
            new_user = event.get("TargetUserName")
            creator = event.get("SubjectUserName")
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"User account '{new_user}' was created on '{event.computer}' "
                        f"by '{creator}'."
                    ),
                    severity=Severity.LOW,
                    events=[event],
                    mitre_techniques=techniques_for_rule(self.rule_id),
                    host=event.computer,
                    user=new_user,
                    metadata={"created_by": creator},
                )
            )
        return detections


class AccountAddedToPrivilegedGroupRule(DetectionRule):
    """Detects an account being added to a privileged group (4728/4732/4756)."""

    rule_id = "account_added_to_privileged_group"
    title = "Account Added to Privileged Group"

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Flag group-membership events where the target group looks administrative."""
        detections: list[Detection] = []
        for event in self._events_of_types(events, {4728, 4732, 4756}):
            group_name = event.get("TargetGroupName") or event.get("GroupName")
            member = event.get("MemberName") or event.get("TargetUserName")
            if not group_name:
                continue
            if not any(kw in group_name.lower() for kw in _PRIVILEGED_GROUP_KEYWORDS):
                continue
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"Account '{member}' was added to privileged group "
                        f"'{group_name}' on '{event.computer}'."
                    ),
                    severity=Severity.HIGH,
                    events=[event],
                    mitre_techniques=techniques_for_rule(self.rule_id),
                    host=event.computer,
                    user=member,
                    metadata={"group_name": group_name},
                )
            )
        return detections


class ScheduledTaskPersistenceRule(DetectionRule):
    """Detects scheduled task creation, a common persistence mechanism (4698)."""

    rule_id = "scheduled_task_persistence"
    title = "Scheduled Task Created (Possible Persistence)"

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Flag every 4698 event; content of the task is included for triage."""
        detections: list[Detection] = []
        for event in self._events_of_type(events, 4698):
            task_name = event.get("TaskName")
            subject = event.get("SubjectUserName")
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"Scheduled task '{task_name}' was created on '{event.computer}' "
                        f"by '{subject}'. Scheduled tasks are a common persistence "
                        "and execution mechanism used by attackers."
                    ),
                    severity=Severity.MEDIUM,
                    events=[event],
                    mitre_techniques=techniques_for_rule(self.rule_id),
                    host=event.computer,
                    user=subject,
                    metadata={"task_name": task_name},
                )
            )
        return detections


class ServiceInstallationPersistenceRule(DetectionRule):
    """Detects new Windows service installation (4697 / 7045), a common persistence mechanism."""

    rule_id = "service_installation_persistence"
    title = "New Service Installed (Possible Persistence)"

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Flag every 4697/7045 event with the service binary path when available."""
        detections: list[Detection] = []
        for event in self._events_of_types(events, {4697, 7045}):
            service_name = event.get("ServiceName")
            image_path = event.get("ServiceFileName") or event.get("ImagePath")
            subject = event.get("SubjectUserName")
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"Service '{service_name}' was installed on '{event.computer}' "
                        f"(binary: '{image_path or 'unknown'}'). New service installation "
                        "is a common technique for persistence and privileged execution."
                    ),
                    severity=Severity.MEDIUM,
                    events=[event],
                    mitre_techniques=techniques_for_rule(self.rule_id),
                    host=event.computer,
                    user=subject,
                    metadata={"service_name": service_name, "image_path": image_path},
                )
            )
        return detections


class AuditLogClearedRule(DetectionRule):
    """Detects clearing of the Security event log (1102) -- a strong defense-evasion signal."""

    rule_id = "audit_log_cleared"
    title = "Security Audit Log Cleared"

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Every 1102 event is treated as CRITICAL: log clearing is rarely benign mid-incident."""
        detections: list[Detection] = []
        for event in self._events_of_type(events, 1102):
            subject = event.get("SubjectUserName")
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"The Security event log on '{event.computer}' was cleared by "
                        f"'{subject}'. This is a strong indicator of anti-forensic "
                        "activity intended to hide prior malicious actions."
                    ),
                    severity=Severity.CRITICAL,
                    events=[event],
                    mitre_techniques=techniques_for_rule(self.rule_id),
                    host=event.computer,
                    user=subject,
                )
            )
        return detections


class ExplicitCredentialLogonRule(DetectionRule):
    """Detects logons using explicitly supplied credentials (4648), e.g. 'runas'."""

    rule_id = "explicit_credential_logon"
    title = "Logon Using Explicit Credentials"

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Flag 4648 events, common in lateral movement and credential testing."""
        detections: list[Detection] = []
        for event in self._events_of_type(events, 4648):
            subject = event.get("SubjectUserName")
            target_user = event.get("TargetUserName")
            target_server = event.get("TargetServerName")
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"Process running as '{subject}' on '{event.computer}' used "
                        f"explicit credentials for '{target_user}' to access "
                        f"'{target_server}'. Often seen with 'runas', scheduled tasks, "
                        "or lateral-movement tooling."
                    ),
                    severity=Severity.LOW,
                    events=[event],
                    mitre_techniques=techniques_for_rule(self.rule_id),
                    host=event.computer,
                    user=target_user or subject,
                    metadata={"target_server": target_server},
                )
            )
        return detections


class LateralMovementNetworkLogonRule(DetectionRule):
    """Detects a single account performing network logons (LogonType 3) to many distinct hosts quickly."""

    rule_id = "lateral_movement_network_logon"
    title = "Possible Lateral Movement (Multi-Host Network Logon)"

    def __init__(self, min_hosts: int = 3, window_minutes: int = 30) -> None:
        """Configure detection sensitivity.

        Args:
            min_hosts: Minimum number of distinct hosts required within
                the window to trigger a detection.
            window_minutes: Sliding time window, in minutes.
        """
        self.min_hosts = min_hosts
        self.window = timedelta(minutes=window_minutes)

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Group Type-3 (Network) 4624 logons by user and look for multi-host spread."""
        network_logons = [
            e
            for e in self._events_of_type(events, 4624)
            if e.get("LogonType") == "3" and e.target_user
        ]
        detections: list[Detection] = []

        by_user = _group_by(network_logons, key_fn=lambda e: e.target_user)
        for user, user_events in by_user.items():
            user_events = sorted(user_events, key=lambda e: e.timestamp)
            n = len(user_events)
            start = 0
            for end in range(n):
                while user_events[end].timestamp - user_events[start].timestamp > self.window:
                    start += 1
                window_slice = user_events[start : end + 1]
                distinct_hosts = {e.computer for e in window_slice}
                if len(distinct_hosts) >= self.min_hosts:
                    detections.append(
                        Detection(
                            rule_id=self.rule_id,
                            title=self.title,
                            description=(
                                f"Account '{user}' performed network logons to "
                                f"{len(distinct_hosts)} distinct hosts "
                                f"({', '.join(sorted(distinct_hosts))}) within "
                                f"{self.window.seconds // 60} minutes -- a pattern "
                                "consistent with lateral movement."
                            ),
                            severity=Severity.HIGH,
                            events=window_slice,
                            mitre_techniques=techniques_for_rule(self.rule_id),
                            host=window_slice[-1].computer,
                            user=user,
                            metadata={"distinct_hosts": sorted(distinct_hosts)},
                        )
                    )
                    break  # one detection per user is enough signal
        return detections


class RdpLogonRule(DetectionRule):
    """Detects interactive RDP logons (LogonType 10) via Event ID 4624."""

    rule_id = "rdp_logon"
    title = "Remote Desktop (RDP) Logon"

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Flag Type-10 logons, informational unless combined with other signals downstream."""
        detections: list[Detection] = []
        for event in self._events_of_type(events, 4624):
            if event.get("LogonType") != "10":
                continue
            user = event.target_user
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"Account '{user}' logged on to '{event.computer}' via "
                        f"Remote Desktop from IP '{event.source_ip or 'unknown'}'."
                    ),
                    severity=Severity.LOW,
                    events=[event],
                    mitre_techniques=techniques_for_rule(self.rule_id),
                    host=event.computer,
                    user=user,
                    metadata={"source_ip": event.source_ip},
                )
            )
        return detections


class PossiblePassTheHashRule(DetectionRule):
    """Detects logon patterns consistent with pass-the-hash (NewCredentials logon, Type 9)."""

    rule_id = "possible_pass_the_hash"
    title = "Possible Pass-the-Hash Activity"

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Flag Type-9 (NewCredentials) logons, frequently associated with PtH tooling."""
        detections: list[Detection] = []
        for event in self._events_of_type(events, 4624):
            if event.get("LogonType") != "9":
                continue
            user = event.target_user
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"A 'NewCredentials' (Type 9) logon for account '{user}' was "
                        f"observed on '{event.computer}'. This logon type is frequently "
                        "associated with pass-the-hash tooling (e.g. Mimikatz, "
                        "Impacket) that impersonates a user without their plaintext password."
                    ),
                    severity=Severity.HIGH,
                    events=[event],
                    mitre_techniques=techniques_for_rule(self.rule_id),
                    host=event.computer,
                    user=user,
                )
            )
        return detections


class KerberosPreauthFailureRule(DetectionRule):
    """Detects repeated Kerberos pre-authentication failures (4771), possible AS-REP roasting / brute force."""

    rule_id = "kerberos_preauth_failure"
    title = "Repeated Kerberos Pre-Authentication Failures"

    def __init__(self, threshold: int = 5, window_minutes: int = 10) -> None:
        """Configure detection sensitivity.

        Args:
            threshold: Minimum number of failures within the window.
            window_minutes: Sliding time window, in minutes.
        """
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Group 4771 failures by target account and flag dense clusters."""
        failures = self._events_of_type(events, 4771)
        detections: list[Detection] = []

        grouped = _group_by(failures, key_fn=lambda e: (e.computer, e.target_user))
        for (host, user), user_events in grouped.items():
            if not user:
                continue
            for cluster in _within_sliding_window(user_events, self.window, self.threshold):
                detections.append(
                    Detection(
                        rule_id=self.rule_id,
                        title=self.title,
                        description=(
                            f"{len(cluster)} Kerberos pre-authentication failures for "
                            f"account '{user}' against '{host}' within "
                            f"{self.window.seconds // 60} minutes."
                        ),
                        severity=Severity.MEDIUM,
                        events=cluster,
                        mitre_techniques=techniques_for_rule(self.rule_id),
                        host=host,
                        user=user,
                        metadata={"failures": len(cluster)},
                    )
                )
        return detections


class AccountLockoutRule(DetectionRule):
    """Detects account lockouts (4740), often a side effect of brute-force attacks."""

    rule_id = "account_lockout"
    title = "Account Locked Out"

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Flag every 4740 event."""
        detections: list[Detection] = []
        for event in self._events_of_type(events, 4740):
            user = event.target_user
            caller_host = event.get("TargetDomainName")
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"Account '{user}' was locked out on '{event.computer}' "
                        f"(domain: '{caller_host}'), typically caused by repeated "
                        "failed authentication attempts."
                    ),
                    severity=Severity.MEDIUM,
                    events=[event],
                    mitre_techniques=techniques_for_rule(self.rule_id),
                    host=event.computer,
                    user=user,
                )
            )
        return detections


class SuspiciousProcessCreationRule(DetectionRule):
    """Detects process creation (4688) of commonly-abused living-off-the-land binaries."""

    rule_id = "suspicious_process_creation"
    title = "Suspicious Process Execution"

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Flag 4688 events whose process name or command line looks suspicious."""
        detections: list[Detection] = []
        for event in self._events_of_type(events, 4688):
            process_name = (event.get("NewProcessName") or "").lower()
            cmdline = (event.get("CommandLine") or "").lower()

            name_hit = any(proc in process_name for proc in _SUSPICIOUS_PROCESS_NAMES)
            cmdline_hit = any(marker in cmdline for marker in _SUSPICIOUS_CMDLINE_MARKERS)

            if not (name_hit and cmdline_hit):
                # Require BOTH a suspicious binary AND a suspicious
                # command-line marker to keep false positives low --
                # powershell.exe alone is extremely common and benign.
                continue

            subject = event.get("SubjectUserName")
            parent = event.get("ParentProcessName")
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"Suspicious process executed on '{event.computer}' by "
                        f"'{subject}': '{event.get('NewProcessName')}' "
                        f"(parent: '{parent}'). Command line contains indicators "
                        "commonly associated with obfuscated or malicious execution."
                    ),
                    severity=Severity.HIGH,
                    events=[event],
                    mitre_techniques=techniques_for_rule(self.rule_id),
                    host=event.computer,
                    user=subject,
                    metadata={"process": event.get("NewProcessName"), "command_line": event.get("CommandLine")},
                )
            )
        return detections


class SpecialPrivilegesAssignedRule(DetectionRule):
    """Detects assignment of powerful privileges (4672) to a logon session."""

    rule_id = "special_privileges_assigned"
    title = "Special/Sensitive Privileges Assigned to Logon"

    _SENSITIVE_PRIVILEGES = ("SeDebugPrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeRestorePrivilege")

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Flag 4672 events referencing highly sensitive privileges."""
        detections: list[Detection] = []
        for event in self._events_of_type(events, 4672):
            privileges = event.get("PrivilegeList", "")
            if not any(priv in privileges for priv in self._SENSITIVE_PRIVILEGES):
                continue
            subject = event.get("SubjectUserName")
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"Logon session for '{subject}' on '{event.computer}' was "
                        f"granted sensitive privileges ({privileges.strip() or 'see raw event'}), "
                        "which can be abused to bypass access controls or read "
                        "protected process memory (e.g. LSASS credential dumping)."
                    ),
                    severity=Severity.MEDIUM,
                    events=[event],
                    mitre_techniques=techniques_for_rule(self.rule_id),
                    host=event.computer,
                    user=subject,
                    metadata={"privileges": privileges},
                )
            )
        return detections


class NetworkShareAccessRule(DetectionRule):
    """Detects access to administrative network shares (5140/5145), e.g. C$, ADMIN$."""

    rule_id = "network_share_access"
    title = "Administrative Share Accessed"

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Flag 5140/5145 events targeting well-known admin shares."""
        detections: list[Detection] = []
        for event in self._events_of_types(events, {5140, 5145}):
            share_name = (event.get("ShareName") or "").lower()
            if not any(admin_share in share_name for admin_share in _ADMIN_SHARE_NAMES):
                continue
            subject = event.get("SubjectUserName")
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"Account '{subject}' accessed administrative share "
                        f"'{event.get('ShareName')}' on '{event.computer}' from "
                        f"'{event.get('IpAddress', 'unknown')}'. Admin shares are "
                        "frequently used for lateral movement and remote file staging."
                    ),
                    severity=Severity.MEDIUM,
                    events=[event],
                    mitre_techniques=techniques_for_rule(self.rule_id),
                    host=event.computer,
                    user=subject,
                    metadata={"share_name": event.get("ShareName")},
                )
            )
        return detections


class PasswordResetRule(DetectionRule):
    """Detects administrative password reset attempts (4724)."""

    rule_id = "password_reset"
    title = "Account Password Reset Attempt"

    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Flag every 4724 event."""
        detections: list[Detection] = []
        for event in self._events_of_type(events, 4724):
            target = event.target_user
            subject = event.get("SubjectUserName")
            if target and subject and target.lower() == subject.lower():
                continue  # self-service password reset, generally benign
            detections.append(
                Detection(
                    rule_id=self.rule_id,
                    title=self.title,
                    description=(
                        f"'{subject}' attempted to reset the password for account "
                        f"'{target}' on '{event.computer}'. Unexpected password resets "
                        "by a different account can indicate account takeover."
                    ),
                    severity=Severity.MEDIUM,
                    events=[event],
                    mitre_techniques=techniques_for_rule(self.rule_id),
                    host=event.computer,
                    user=target,
                    metadata={"reset_by": subject},
                )
            )
        return detections


def default_rule_set() -> list[DetectionRule]:
    """Construct the standard, production-default set of detection rules.

    Returns:
        A list of instantiated :class:`DetectionRule` objects with
        sensible default thresholds, ready to register with a
        :class:`detections.base.DetectionEngine`.
    """
    return [
        BruteForceLogonRule(),
        SuccessfulLogonAfterBruteForceRule(),
        AccountCreatedRule(),
        AccountAddedToPrivilegedGroupRule(),
        ScheduledTaskPersistenceRule(),
        ServiceInstallationPersistenceRule(),
        AuditLogClearedRule(),
        ExplicitCredentialLogonRule(),
        LateralMovementNetworkLogonRule(),
        RdpLogonRule(),
        PossiblePassTheHashRule(),
        KerberosPreauthFailureRule(),
        AccountLockoutRule(),
        SuspiciousProcessCreationRule(),
        SpecialPrivilegesAssignedRule(),
        NetworkShareAccessRule(),
        PasswordResetRule(),
    ]
