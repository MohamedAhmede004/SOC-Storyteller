"""
timeline/timeline_builder.py

Builds chronological timeline views of an incident, either across a
single :class:`utils.models.AttackChain` or an entire set of chains.

The timeline is a presentation-oriented structure -- it doesn't
introduce new analysis, it just orders and formats existing Detection/
Event data for human consumption in reports and the UI.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from utils.logger import get_logger
from utils.models import AttackChain, Detection, Severity

logger = get_logger(__name__)


@dataclass
class TimelineEntry:
    """A single chronological entry in a rendered timeline.

    Attributes:
        timestamp: When this entry occurred.
        host: The host involved.
        user: The user account involved, if any.
        rule_id: The detection rule that produced this entry.
        title: Short human-readable title.
        description: Full human-readable description.
        severity: Severity of the underlying detection.
        event_ids: The raw Windows Event IDs contributing to this entry.
    """

    timestamp: datetime
    host: str
    user: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    event_ids: list[int]

    def format_line(self) -> str:
        """Render this entry as a single formatted text line.

        Returns:
            A string like:
            ``2024-01-15 13:45:30 UTC | HIGH | HOST-A | alice | Brute Force Logon Attempt``
        """
        ts = self.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        user_part = f" | {self.user}" if self.user else ""
        return f"{ts} | {self.severity.value:<8} | {self.host}{user_part} | {self.title}"


class TimelineBuilder:
    """Builds ordered :class:`TimelineEntry` sequences from detections/chains."""

    def build_from_chain(self, chain: AttackChain) -> list[TimelineEntry]:
        """Build a chronological timeline for a single attack chain.

        Args:
            chain: The attack chain to render.

        Returns:
            A list of :class:`TimelineEntry`, sorted chronologically.
        """
        entries = [self._entry_from_detection(d) for d in chain.detections]
        entries.sort(key=lambda e: e.timestamp)
        return entries

    def build_from_chains(self, chains: list[AttackChain]) -> list[TimelineEntry]:
        """Build a single merged chronological timeline across multiple chains.

        Args:
            chains: All attack chains to include.

        Returns:
            A list of :class:`TimelineEntry`, sorted chronologically
            across the entire incident.
        """
        entries: list[TimelineEntry] = []
        for chain in chains:
            entries.extend(self.build_from_chain(chain))
        entries.sort(key=lambda e: e.timestamp)
        logger.info("Built merged timeline with %d entries across %d chain(s)", len(entries), len(chains))
        return entries

    @staticmethod
    def _entry_from_detection(detection: Detection) -> TimelineEntry:
        """Convert a single Detection into a TimelineEntry.

        Args:
            detection: The detection to convert.

        Returns:
            The corresponding :class:`TimelineEntry`.

        Raises:
            ValueError: If the detection has no usable timestamp (neither
                ``first_seen`` nor any contributing event timestamp).
        """
        timestamp = detection.first_seen
        if timestamp is None and detection.events:
            timestamp = min(e.timestamp for e in detection.events)
        if timestamp is None:
            raise ValueError(
                f"Detection '{detection.rule_id}' has no timestamp information "
                "(first_seen is None and it has no events)"
            )
        return TimelineEntry(
            timestamp=timestamp,
            host=detection.host,
            user=detection.user,
            rule_id=detection.rule_id,
            title=detection.title,
            description=detection.description,
            severity=detection.severity,
            event_ids=sorted({e.event_id for e in detection.events}),
        )

    def render_text(self, entries: list[TimelineEntry]) -> str:
        """Render a list of timeline entries as a plain-text block.

        Args:
            entries: Timeline entries, typically already sorted
                chronologically.

        Returns:
            A newline-joined string, one formatted line per entry.
        """
        return "\n".join(entry.format_line() for entry in entries)
