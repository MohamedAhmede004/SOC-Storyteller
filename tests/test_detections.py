"""
tests/test_detections.py

Unit tests for individual detection rules and the DetectionEngine.
"""

from __future__ import annotations

from detections.base import DetectionEngine
from detections.rules import (
    AccountAddedToPrivilegedGroupRule,
    AccountCreatedRule,
    AuditLogClearedRule,
    BruteForceLogonRule,
    LateralMovementNetworkLogonRule,
    PossiblePassTheHashRule,
    ScheduledTaskPersistenceRule,
    ServiceInstallationPersistenceRule,
    SuccessfulLogonAfterBruteForceRule,
    SuspiciousProcessCreationRule,
    default_rule_set,
)
from tests.conftest import make_event
from utils.models import Severity


class TestBruteForceLogonRule:
    def test_detects_dense_failure_cluster(self, brute_force_events) -> None:
        rule = BruteForceLogonRule(threshold=5, window_minutes=10)
        detections = rule.evaluate(brute_force_events)
        assert len(detections) == 1
        assert detections[0].rule_id == "brute_force_logon"
        assert detections[0].user == "alice"
        assert detections[0].metadata["failed_attempts"] == 6

    def test_no_detection_below_threshold(self) -> None:
        events = [make_event(4625, offset_seconds=i * 10, TargetUserName="bob") for i in range(3)]
        rule = BruteForceLogonRule(threshold=5, window_minutes=10)
        assert rule.evaluate(events) == []

    def test_no_detection_when_spread_beyond_window(self) -> None:
        events = [make_event(4625, offset_seconds=i * 700, TargetUserName="carol") for i in range(6)]
        rule = BruteForceLogonRule(threshold=5, window_minutes=10)
        assert rule.evaluate(events) == []


class TestSuccessfulLogonAfterBruteForceRule:
    def test_detects_success_following_failures(self, brute_force_events) -> None:
        rule = SuccessfulLogonAfterBruteForceRule(min_failures=3, window_minutes=15)
        detections = rule.evaluate(brute_force_events)
        assert len(detections) == 1
        assert detections[0].severity == Severity.HIGH

    def test_no_detection_without_success(self) -> None:
        events = [make_event(4625, offset_seconds=i * 10, TargetUserName="dave") for i in range(5)]
        rule = SuccessfulLogonAfterBruteForceRule(min_failures=3, window_minutes=15)
        assert rule.evaluate(events) == []


class TestAccountCreatedRule:
    def test_flags_account_creation(self) -> None:
        event = make_event(4720, TargetUserName="svc_new", SubjectUserName="admin")
        detections = AccountCreatedRule().evaluate([event])
        assert len(detections) == 1
        assert detections[0].user == "svc_new"
        assert detections[0].metadata["created_by"] == "admin"


class TestAccountAddedToPrivilegedGroupRule:
    def test_flags_admin_group_addition(self) -> None:
        event = make_event(4732, MemberName="svc_new", TargetGroupName="Administrators")
        detections = AccountAddedToPrivilegedGroupRule().evaluate([event])
        assert len(detections) == 1
        assert detections[0].severity == Severity.HIGH

    def test_ignores_non_privileged_group(self) -> None:
        event = make_event(4732, MemberName="bob", TargetGroupName="Remote Users")
        detections = AccountAddedToPrivilegedGroupRule().evaluate([event])
        assert detections == []


class TestPersistenceRules:
    def test_scheduled_task_rule(self) -> None:
        event = make_event(4698, TaskName=r"\Microsoft\Windows\Evil", SubjectUserName="x")
        detections = ScheduledTaskPersistenceRule().evaluate([event])
        assert len(detections) == 1
        assert "T1053" in [t.technique_id for t in detections[0].mitre_techniques]

    def test_service_installation_rule(self) -> None:
        event = make_event(4697, ServiceName="EvilSvc", ServiceFileName=r"C:\evil.exe")
        detections = ServiceInstallationPersistenceRule().evaluate([event])
        assert len(detections) == 1
        assert detections[0].metadata["service_name"] == "EvilSvc"


class TestAuditLogClearedRule:
    def test_always_critical(self) -> None:
        event = make_event(1102, SubjectUserName="attacker")
        detections = AuditLogClearedRule().evaluate([event])
        assert len(detections) == 1
        assert detections[0].severity == Severity.CRITICAL


class TestLateralMovementRule:
    def test_detects_multi_host_spread(self) -> None:
        events = [
            make_event(4624, offset_seconds=i * 60, computer=f"HOST-{i}", TargetUserName="mallory", LogonType="3")
            for i in range(4)
        ]
        rule = LateralMovementNetworkLogonRule(min_hosts=3, window_minutes=30)
        detections = rule.evaluate(events)
        assert len(detections) == 1
        assert len(detections[0].metadata["distinct_hosts"]) >= 3

    def test_no_detection_single_host(self) -> None:
        events = [
            make_event(4624, offset_seconds=i * 60, computer="HOST-A", TargetUserName="mallory", LogonType="3")
            for i in range(4)
        ]
        rule = LateralMovementNetworkLogonRule(min_hosts=3, window_minutes=30)
        assert rule.evaluate(events) == []


class TestPossiblePassTheHashRule:
    def test_detects_logon_type_9(self) -> None:
        event = make_event(4624, TargetUserName="alice", LogonType="9")
        detections = PossiblePassTheHashRule().evaluate([event])
        assert len(detections) == 1

    def test_ignores_other_logon_types(self) -> None:
        event = make_event(4624, TargetUserName="alice", LogonType="2")
        assert PossiblePassTheHashRule().evaluate([event]) == []


class TestSuspiciousProcessCreationRule:
    def test_requires_both_name_and_cmdline_marker(self) -> None:
        suspicious = make_event(
            4688,
            NewProcessName=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine="powershell.exe -enc SGVsbG8=",
            SubjectUserName="x",
        )
        benign = make_event(
            4688,
            NewProcessName=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine="powershell.exe -File C:\\scripts\\backup.ps1",
            SubjectUserName="x",
        )
        detections = SuspiciousProcessCreationRule().evaluate([suspicious, benign])
        assert len(detections) == 1
        assert "powershell" in detections[0].metadata["process"].lower()


class TestKerberosPreauthFailureRule:
    def test_detects_dense_failure_cluster(self) -> None:
        from detections.rules import KerberosPreauthFailureRule

        events = [
            make_event(4771, offset_seconds=i * 30, TargetUserName="svc_sql")
            for i in range(5)
        ]
        detections = KerberosPreauthFailureRule(threshold=5, window_minutes=10).evaluate(events)
        assert len(detections) == 1
        assert detections[0].metadata["failures"] == 5

    def test_below_threshold_no_detection(self) -> None:
        from detections.rules import KerberosPreauthFailureRule

        events = [make_event(4771, offset_seconds=i * 30, TargetUserName="svc_sql") for i in range(2)]
        assert KerberosPreauthFailureRule(threshold=5).evaluate(events) == []


class TestAccountLockoutRule:
    def test_flags_lockout_event(self) -> None:
        from detections.rules import AccountLockoutRule

        event = make_event(4740, TargetUserName="alice", TargetDomainName="CORP")
        detections = AccountLockoutRule().evaluate([event])
        assert len(detections) == 1
        assert detections[0].user == "alice"
        assert detections[0].severity == Severity.MEDIUM


class TestSpecialPrivilegesAssignedRule:
    def test_flags_sensitive_privileges(self) -> None:
        from detections.rules import SpecialPrivilegesAssignedRule

        event = make_event(4672, SubjectUserName="alice", PrivilegeList="SeDebugPrivilege SeBackupPrivilege")
        detections = SpecialPrivilegesAssignedRule().evaluate([event])
        assert len(detections) == 1
        assert "SeDebugPrivilege" in detections[0].metadata["privileges"]

    def test_ignores_non_sensitive_privileges(self) -> None:
        from detections.rules import SpecialPrivilegesAssignedRule

        event = make_event(4672, SubjectUserName="alice", PrivilegeList="SeChangeNotifyPrivilege")
        assert SpecialPrivilegesAssignedRule().evaluate([event]) == []


class TestNetworkShareAccessRule:
    def test_flags_admin_share(self) -> None:
        from detections.rules import NetworkShareAccessRule

        event = make_event(5140, SubjectUserName="alice", ShareName=r"\\*\C$")
        detections = NetworkShareAccessRule().evaluate([event])
        assert len(detections) == 1
        assert detections[0].metadata["share_name"] == r"\\*\C$"

    def test_ignores_non_admin_share(self) -> None:
        from detections.rules import NetworkShareAccessRule

        event = make_event(5140, SubjectUserName="alice", ShareName=r"\\*\Public")
        assert NetworkShareAccessRule().evaluate([event]) == []


class TestPasswordResetRule:
    def test_flags_reset_by_different_account(self) -> None:
        from detections.rules import PasswordResetRule

        event = make_event(4724, TargetUserName="alice", SubjectUserName="admin_bob")
        detections = PasswordResetRule().evaluate([event])
        assert len(detections) == 1
        assert detections[0].metadata["reset_by"] == "admin_bob"

    def test_ignores_self_service_reset(self) -> None:
        from detections.rules import PasswordResetRule

        event = make_event(4724, TargetUserName="alice", SubjectUserName="alice")
        assert PasswordResetRule().evaluate([event]) == []


class TestRdpLogonRule:
    def test_flags_type_10_logon(self) -> None:
        from detections.rules import RdpLogonRule

        event = make_event(4624, TargetUserName="alice", LogonType="10", IpAddress="10.0.0.9")
        detections = RdpLogonRule().evaluate([event])
        assert len(detections) == 1
        assert detections[0].metadata["source_ip"] == "10.0.0.9"

    def test_ignores_other_logon_types(self) -> None:
        from detections.rules import RdpLogonRule

        event = make_event(4624, TargetUserName="alice", LogonType="3")
        assert RdpLogonRule().evaluate([event]) == []


class TestExplicitCredentialLogonRule:
    def test_flags_explicit_credential_use(self) -> None:
        from detections.rules import ExplicitCredentialLogonRule

        event = make_event(
            4648, SubjectUserName="alice", TargetUserName="administrator", TargetServerName="SRV-1"
        )
        detections = ExplicitCredentialLogonRule().evaluate([event])
        assert len(detections) == 1
        assert detections[0].metadata["target_server"] == "SRV-1"


class TestDetectionEngine:
    def test_runs_all_registered_rules(self, brute_force_events) -> None:
        engine = DetectionEngine().register_all(default_rule_set())
        assert len(engine.registered_rule_ids) == len(default_rule_set())
        detections = engine.run(brute_force_events)
        rule_ids = {d.rule_id for d in detections}
        assert "brute_force_logon" in rule_ids
        assert "successful_logon_after_brute_force" in rule_ids

    def test_empty_input_produces_no_detections(self) -> None:
        engine = DetectionEngine().register_all(default_rule_set())
        assert engine.run([]) == []

    def test_isolates_failing_rule(self) -> None:
        """A broken rule should not prevent other rules from running."""
        from detections.base import DetectionRule
        from utils.models import Detection

        class BrokenRule(DetectionRule):
            rule_id = "broken_rule"
            title = "Broken"

            def evaluate(self, events):
                raise RuntimeError("boom")

        engine = DetectionEngine()
        engine.register(BrokenRule())
        engine.register(AccountCreatedRule())
        event = make_event(4720, TargetUserName="new_user")
        detections = engine.run([event])
        assert len(detections) == 1
        assert detections[0].rule_id == "account_created"
