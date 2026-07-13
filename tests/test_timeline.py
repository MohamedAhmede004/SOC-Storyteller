"""
tests/test_timeline.py

Unit tests for :mod:`timeline.timeline_builder`.
"""

from __future__ import annotations

import pytest

from tests.conftest import make_event
from timeline.timeline_builder import TimelineBuilder
from utils.models import AttackChain, Detection, Severity


def _detection(offset_seconds: int, rule_id: str = "r") -> Detection:
    events = [make_event(4624, offset_seconds=offset_seconds, TargetUserName="alice")]
    return Detection(rule_id=rule_id, title="t", description="d", severity=Severity.MEDIUM, events=events)


class TestBuildFromChain:
    def test_entries_sorted_chronologically(self) -> None:
        chain = AttackChain(chain_id="c1", detections=[_detection(60), _detection(0)])
        entries = TimelineBuilder().build_from_chain(chain)
        assert entries[0].timestamp <= entries[1].timestamp

    def test_entry_fields_populated(self) -> None:
        chain = AttackChain(chain_id="c1", detections=[_detection(0, rule_id="brute_force_logon")])
        entries = TimelineBuilder().build_from_chain(chain)
        assert entries[0].rule_id == "brute_force_logon"
        assert entries[0].user == "alice"
        assert 4624 in entries[0].event_ids

    def test_raises_for_detection_without_timestamp_or_events(self) -> None:
        bad_detection = Detection(
            rule_id="r", title="t", description="d", severity=Severity.LOW, events=[], first_seen=None
        )
        with pytest.raises(ValueError):
            TimelineBuilder()._entry_from_detection(bad_detection)


class TestBuildFromChains:
    def test_merges_across_chains_chronologically(self) -> None:
        chain1 = AttackChain(chain_id="c1", detections=[_detection(100)])
        chain2 = AttackChain(chain_id="c2", detections=[_detection(0)])
        entries = TimelineBuilder().build_from_chains([chain1, chain2])
        assert entries[0].timestamp <= entries[1].timestamp
        assert len(entries) == 2


class TestRenderText:
    def test_render_text_produces_one_line_per_entry(self) -> None:
        chain = AttackChain(chain_id="c1", detections=[_detection(0), _detection(60)])
        builder = TimelineBuilder()
        entries = builder.build_from_chain(chain)
        text = builder.render_text(entries)
        assert len(text.splitlines()) == 2

    def test_format_line_contains_key_fields(self) -> None:
        chain = AttackChain(chain_id="c1", detections=[_detection(0, rule_id="brute_force_logon")])
        entry = TimelineBuilder().build_from_chain(chain)[0]
        line = entry.format_line()
        assert "MEDIUM" in line
        assert "TEST-HOST" in line
