"""
tests/test_models.py

Unit tests for :mod:`utils.models` -- the shared domain model contract
(Event, Detection, AttackChain, Severity, MitreTechnique).
"""

from __future__ import annotations

from datetime import datetime, timezone

from tests.conftest import make_event
from utils.models import AttackChain, Detection, MitreTechnique, Severity


class TestSeverity:
    def test_weight_ordering(self) -> None:
        assert Severity.INFO.weight < Severity.LOW.weight
        assert Severity.LOW.weight < Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight < Severity.HIGH.weight
        assert Severity.HIGH.weight < Severity.CRITICAL.weight


class TestEvent:
    def test_get_returns_default_for_missing_field(self) -> None:
        event = make_event(4624, TargetUserName="alice")
        assert event.get("NonExistentField", "fallback") == "fallback"

    def test_target_user_prefers_target_over_subject(self) -> None:
        event = make_event(4624, TargetUserName="alice", SubjectUserName="bob")
        assert event.target_user == "alice"

    def test_target_user_falls_back_to_subject(self) -> None:
        event = make_event(4720, SubjectUserName="admin")
        assert event.target_user == "admin"

    def test_source_ip_passthrough(self) -> None:
        event = make_event(4624, IpAddress="10.0.0.1")
        assert event.source_ip == "10.0.0.1"

    def test_to_dict_is_json_serializable(self) -> None:
        import json

        event = make_event(4624, TargetUserName="alice")
        payload = event.to_dict()
        json.dumps(payload)  # must not raise
        assert payload["event_id"] == 4624
        assert payload["event_data"]["TargetUserName"] == "alice"


class TestDetection:
    def test_derives_first_last_seen_from_events(self) -> None:
        events = [make_event(4625, offset_seconds=i * 10) for i in range(3)]
        detection = Detection(
            rule_id="r", title="t", description="d", severity=Severity.LOW, events=events
        )
        assert detection.first_seen == events[0].timestamp
        assert detection.last_seen == events[-1].timestamp

    def test_derives_host_and_user_from_events(self) -> None:
        events = [make_event(4624, computer="HOST-X", TargetUserName="alice")]
        detection = Detection(
            rule_id="r", title="t", description="d", severity=Severity.LOW, events=events
        )
        assert detection.host == "HOST-X"
        assert detection.user == "alice"

    def test_explicit_host_user_not_overridden(self) -> None:
        events = [make_event(4624, computer="HOST-X", TargetUserName="alice")]
        detection = Detection(
            rule_id="r",
            title="t",
            description="d",
            severity=Severity.LOW,
            events=events,
            host="HOST-OVERRIDE",
            user="bob",
        )
        assert detection.host == "HOST-OVERRIDE"
        assert detection.user == "bob"

    def test_empty_events_does_not_crash(self) -> None:
        detection = Detection(rule_id="r", title="t", description="d", severity=Severity.LOW, events=[])
        assert detection.first_seen is None
        assert detection.last_seen is None


class TestAttackChain:
    def _detection(self, offset_seconds: int, host: str = "HOST-A", user: str = "alice") -> Detection:
        events = [make_event(4624, offset_seconds=offset_seconds, computer=host, TargetUserName=user)]
        return Detection(rule_id="r", title="t", description="d", severity=Severity.LOW, events=events)

    def test_derives_time_bounds_and_users(self) -> None:
        detections = [self._detection(0, user="alice"), self._detection(60, user="bob")]
        chain = AttackChain(chain_id="c1", detections=detections)
        assert chain.host == "HOST-A"
        assert chain.users == ["alice", "bob"]
        assert chain.start_time < chain.end_time

    def test_all_events_sorted_chronologically(self) -> None:
        detections = [self._detection(60), self._detection(0)]
        chain = AttackChain(chain_id="c1", detections=detections)
        events = chain.all_events
        assert events[0].timestamp <= events[1].timestamp

    def test_mitre_techniques_deduplicated(self) -> None:
        tech = MitreTechnique(technique_id="T1110", name="Brute Force", tactic="Credential Access")
        d1 = Detection(
            rule_id="r1",
            title="t",
            description="d",
            severity=Severity.LOW,
            events=[make_event(4625, offset_seconds=0)],
            mitre_techniques=[tech],
        )
        d2 = Detection(
            rule_id="r2",
            title="t",
            description="d",
            severity=Severity.LOW,
            events=[make_event(4625, offset_seconds=10)],
            mitre_techniques=[tech],
        )
        chain = AttackChain(chain_id="c1", detections=[d1, d2])
        assert len(chain.mitre_techniques) == 1


class TestMitreTechnique:
    def test_str_representation(self) -> None:
        tech = MitreTechnique(technique_id="T1110", name="Brute Force", tactic="Credential Access")
        assert "T1110" in str(tech)
        assert "Brute Force" in str(tech)
