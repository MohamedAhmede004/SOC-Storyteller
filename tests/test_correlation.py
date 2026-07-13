"""
tests/test_correlation.py

Unit tests for :mod:`correlation.correlation_engine`.
"""

from __future__ import annotations

import pytest

from correlation.correlation_engine import CorrelationEngine
from tests.conftest import make_event
from utils.exceptions import CorrelationError
from utils.models import Detection, Severity


def _detection(rule_id: str, host: str, user: str, offset_seconds: int, event_id: int = 4624) -> Detection:
    """Build a minimal Detection for correlation testing."""
    event = make_event(event_id, offset_seconds=offset_seconds, computer=host, TargetUserName=user)
    return Detection(
        rule_id=rule_id,
        title=rule_id,
        description="test",
        severity=Severity.MEDIUM,
        events=[event],
        host=host,
        user=user,
    )


class TestCorrelationEngine:
    def test_empty_input_returns_empty(self) -> None:
        assert CorrelationEngine().correlate([]) == []

    def test_same_host_and_close_time_merges(self) -> None:
        detections = [
            _detection("rule_a", "HOST-A", "alice", 0),
            _detection("rule_b", "HOST-A", "alice", 60),
        ]
        chains = CorrelationEngine(max_gap_minutes=60).correlate(detections)
        assert len(chains) == 1
        assert len(chains[0].detections) == 2

    def test_different_host_and_user_stay_separate(self) -> None:
        detections = [
            _detection("rule_a", "HOST-A", "alice", 0),
            _detection("rule_b", "HOST-B", "bob", 10),
        ]
        chains = CorrelationEngine(max_gap_minutes=60).correlate(detections)
        assert len(chains) == 2

    def test_time_gap_exceeding_max_gap_stays_separate(self) -> None:
        detections = [
            _detection("rule_a", "HOST-A", "alice", 0),
            _detection("rule_b", "HOST-A", "alice", 4000),  # ~66 minutes later
        ]
        chains = CorrelationEngine(max_gap_minutes=60).correlate(detections)
        assert len(chains) == 2

    def test_transitive_identity_pivot_merges_chain(self) -> None:
        """alice on HOST-A links to svc_new (created by alice) which then acts alone."""
        d1 = _detection("brute_force", "HOST-A", "alice", 0)
        d2 = _detection("account_created", "HOST-A", "svc_new", 60)
        d3 = _detection("log_cleared", "HOST-A", "svc_new", 120)
        chains = CorrelationEngine(max_gap_minutes=60).correlate([d1, d2, d3])
        assert len(chains) == 1
        assert len(chains[0].detections) == 3
        assert set(chains[0].users) == {"alice", "svc_new"}

    def test_raises_when_missing_timestamps(self) -> None:
        detection = Detection(
            rule_id="rule_a",
            title="x",
            description="x",
            severity=Severity.LOW,
            events=[],
            host="HOST-A",
            user="alice",
            first_seen=None,
            last_seen=None,
        )
        with pytest.raises(CorrelationError):
            CorrelationEngine().correlate([detection])

    def test_chains_sorted_by_start_time(self) -> None:
        d_later = _detection("rule_a", "HOST-B", "carol", 5000)
        d_earlier = _detection("rule_b", "HOST-A", "alice", 0)
        chains = CorrelationEngine().correlate([d_later, d_earlier])
        assert chains[0].host == "HOST-A"
        assert chains[1].host == "HOST-B"
