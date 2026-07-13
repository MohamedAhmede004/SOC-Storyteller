"""
tests/conftest.py

Shared pytest fixtures for SOC Storyteller's test suite.

Tests build synthetic ``Event`` objects directly (rather than requiring
real binary .evtx files) so the full pipeline can be exercised quickly
and deterministically in CI.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from utils.models import Event

_BASE_TIME = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_id: int,
    offset_seconds: int = 0,
    computer: str = "TEST-HOST",
    record_id: int | None = None,
    **event_data: str,
) -> Event:
    """Build a synthetic :class:`Event` for use in tests.

    Args:
        event_id: The Windows Event ID.
        offset_seconds: Seconds after the fixed test base time.
        computer: Hostname for the event.
        record_id: Optional explicit record ID (defaults to a value
            derived from ``offset_seconds`` to keep them unique/ordered).
        **event_data: Arbitrary EventData fields (e.g. TargetUserName="alice").

    Returns:
        A fully constructed :class:`Event`.
    """
    return Event(
        event_id=event_id,
        record_id=record_id if record_id is not None else 1000 + offset_seconds,
        timestamp=_BASE_TIME + timedelta(seconds=offset_seconds),
        channel="Security",
        computer=computer,
        provider="Microsoft-Windows-Security-Auditing",
        level="Information",
        event_data=event_data,
    )


@pytest.fixture
def base_time() -> datetime:
    """Fixed base timestamp used across tests for reproducibility."""
    return _BASE_TIME


@pytest.fixture(scope="module")
def sample_xml_path() -> Path:
    """Path to the bundled synthetic multi-stage attack scenario XML file."""
    return Path(__file__).parent.parent / "sample_logs" / "attack_scenario.xml"


@pytest.fixture
def brute_force_events() -> list[Event]:
    """Six failed logons followed by one success for account 'alice'."""
    events = [
        make_event(4625, offset_seconds=i * 20, TargetUserName="alice", LogonType="3", IpAddress="198.51.100.5")
        for i in range(6)
    ]
    events.append(
        make_event(4624, offset_seconds=140, TargetUserName="alice", LogonType="3", IpAddress="198.51.100.5")
    )
    return events
