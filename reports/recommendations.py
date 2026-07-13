"""
reports/recommendations.py

Maps detection rule IDs to actionable SOC analyst recommendations
(investigation steps, containment actions, and hardening guidance).

Keeping this mapping in one place -- rather than embedding advice
strings inside each detection rule -- follows the same Single
Responsibility split used elsewhere in the project: detection rules
decide *what happened*, this module decides *what an analyst should do
about it*. That separation also means recommendation text can be
tuned/extended without touching detection logic at all.
"""

from __future__ import annotations

from utils.logger import get_logger
from utils.models import AttackChain, Detection, Severity

logger = get_logger(__name__)

# --------------------------------------------------------------------------
# Rule-ID -> recommendation list.
#
# Each entry is a short list of concrete, actionable steps an analyst
# can take. Kept deliberately concise (bullet-point length) since these
# are rendered directly into reports.
# --------------------------------------------------------------------------
_RULE_RECOMMENDATIONS: dict[str, list[str]] = {
    "brute_force_logon": [
        "Verify whether the source IP address is expected (VPN egress, known admin workstation, etc.).",
        "Consider temporarily blocking the source IP at the firewall/EDR if it is external or unrecognized.",
        "Confirm the target account has not been compromised; force a password reset if in doubt.",
        "Enable/verify account lockout policy and MFA are enforced for the target account.",
    ],
    "successful_logon_after_brute_force": [
        "Treat as a probable account compromise until proven otherwise -- prioritize this chain for triage.",
        "Force an immediate password reset and revoke active sessions/tokens for the affected account.",
        "Review subsequent activity from this account for signs of privilege escalation or lateral movement.",
        "Enable MFA for the account if not already enforced.",
    ],
    "account_created": [
        "Confirm the account creation was authorized via change management / ticketing records.",
        "Verify the creating account's privileges were expected to include account-creation rights.",
        "If unauthorized, disable the new account immediately and investigate the creating account's session.",
    ],
    "account_added_to_privileged_group": [
        "Validate the privilege escalation against an approved access request.",
        "If unauthorized, remove the account from the privileged group immediately.",
        "Audit recent actions taken by the account since privilege escalation.",
        "Review group membership change auditing/alerting to ensure future changes are caught quickly.",
    ],
    "scheduled_task_persistence": [
        "Inspect the scheduled task's action/command for malicious content before it next triggers.",
        "Disable or delete the task if unauthorized, and preserve a forensic copy first.",
        "Identify and isolate the host if the task executes remote or obfuscated code.",
    ],
    "service_installation_persistence": [
        "Inspect the service binary path/hash against known-good software inventory and threat intel.",
        "Stop and disable the service if unauthorized; do not simply delete without preserving evidence.",
        "Scan the host with EDR/antivirus and consider isolating it pending investigation.",
    ],
    "audit_log_cleared": [
        "Treat as a high-confidence indicator of compromise requiring immediate incident response.",
        "Isolate the affected host from the network pending investigation.",
        "Pull logs from centralized/forwarded log storage (SIEM) to recover the activity that was cleared locally.",
        "Preserve memory and disk forensics before any further changes are made to the host.",
    ],
    "explicit_credential_logon": [
        "Confirm this matches expected administrative behavior (e.g. authorized 'runas' usage).",
        "Review the target server/account for any subsequent unusual activity.",
    ],
    "lateral_movement_network_logon": [
        "Map the full set of hosts accessed by this account and check each for signs of compromise.",
        "Determine whether the account's credentials may have been harvested (e.g. pass-the-hash).",
        "Consider isolating the account (disable/reset) while movement is investigated.",
    ],
    "rdp_logon": [
        "Confirm RDP access from this source is expected (authorized remote-work location, jump host, etc.).",
        "Ensure RDP is not directly exposed to the internet; require VPN/MFA for remote access.",
    ],
    "possible_pass_the_hash": [
        "Treat as a strong indicator of credential theft tooling (e.g. Mimikatz, Impacket).",
        "Reset the affected account's password/krbtgt as appropriate and revoke active sessions.",
        "Hunt for the source process/host that performed the pass-the-hash logon.",
    ],
    "kerberos_preauth_failure": [
        "Determine whether this reflects AS-REP roasting reconnaissance or simple misconfiguration.",
        "Ensure Kerberos pre-authentication is enabled for all accounts where feasible.",
        "Correlate with subsequent successful authentications for the same account.",
    ],
    "account_lockout": [
        "Confirm with the account owner whether the lockout was self-inflicted (forgotten password, stale credential cache).",
        "If unexpected, treat as a possible brute-force side effect and investigate the source.",
    ],
    "suspicious_process_creation": [
        "Retrieve and analyze the full command line and any dropped files associated with this process.",
        "Isolate the host and run a full EDR/antivirus scan.",
        "Determine the parent process chain to identify the initial delivery mechanism.",
    ],
    "special_privileges_assigned": [
        "Confirm the logon session legitimately requires the assigned sensitive privileges.",
        "Monitor for LSASS access or credential-dumping activity from this session.",
    ],
    "network_share_access": [
        "Confirm administrative share access matches expected remote administration activity.",
        "Review files written to or read from the share around the time of access.",
    ],
    "password_reset": [
        "Confirm the password reset was authorized by the account owner or a help-desk ticket.",
        "If unauthorized, treat as probable account takeover and re-secure the account immediately.",
    ],
}

_GENERIC_RECOMMENDATIONS: list[str] = [
    "Validate this activity against expected business/administrative processes.",
    "Escalate to a senior analyst if the activity cannot be confirmed as benign.",
]

_CHAIN_LEVEL_CRITICAL_RECOMMENDATIONS: list[str] = [
    "This chain has been assessed as CRITICAL risk -- initiate formal incident response procedures.",
    "Preserve volatile evidence (memory, active network connections) on all involved hosts before remediation.",
    "Notify incident response leadership and, if required, initiate breach-notification assessment.",
]


def recommendations_for_rule(rule_id: str) -> list[str]:
    """Return the recommended analyst actions for a single detection rule.

    Args:
        rule_id: The detection rule's machine-readable identifier.

    Returns:
        A list of recommendation strings. Falls back to
        :data:`_GENERIC_RECOMMENDATIONS` if no specific guidance is
        registered for the rule (logged at debug level, not a warning,
        since generic guidance is still useful).
    """
    recommendations = _RULE_RECOMMENDATIONS.get(rule_id)
    if not recommendations:
        logger.debug("No specific recommendations registered for rule_id=%s; using generic guidance", rule_id)
        return list(_GENERIC_RECOMMENDATIONS)
    return list(recommendations)


def recommendations_for_detection(detection: Detection) -> list[str]:
    """Return recommended analyst actions for a single detection.

    Args:
        detection: The detection to generate recommendations for.

    Returns:
        A list of recommendation strings for this detection's rule.
    """
    return recommendations_for_rule(detection.rule_id)


def recommendations_for_chain(chain: AttackChain) -> list[str]:
    """Return a de-duplicated, prioritized list of recommendations for an entire chain.

    Combines recommendations from every distinct rule_id present in the
    chain, and prepends chain-level guidance if the chain's overall
    severity is CRITICAL.

    Args:
        chain: The scored attack chain to generate recommendations for.

    Returns:
        An ordered list of recommendation strings, duplicates removed
        while preserving first-seen order.
    """
    seen: list[str] = []
    ordered: list[str] = []

    if chain.risk_severity == Severity.CRITICAL:
        for rec in _CHAIN_LEVEL_CRITICAL_RECOMMENDATIONS:
            if rec not in seen:
                seen.append(rec)
                ordered.append(rec)

    distinct_rule_ids: list[str] = []
    for detection in chain.detections:
        if detection.rule_id not in distinct_rule_ids:
            distinct_rule_ids.append(detection.rule_id)

    for rule_id in distinct_rule_ids:
        for rec in recommendations_for_rule(rule_id):
            if rec not in seen:
                seen.append(rec)
                ordered.append(rec)

    return ordered
