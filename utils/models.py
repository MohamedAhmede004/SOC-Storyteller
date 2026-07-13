"""
utils/models.py

Core domain models shared across the entire SOC Storyteller pipeline.

These dataclasses form the "contract" between modules:

    EVTX file --> [parser] --> list[Event]
    list[Event] --> [detections] --> list[Detection]
    list[Detection] --> [correlation] --> list[AttackChain]
    list[AttackChain] --> [risk_engine] --> RiskScore (per chain)
    list[AttackChain] + RiskScore --> [reports] --> Report

Keeping these models in one place (rather than duplicating small
"Event-like" classes in every module) avoids duplicated code and keeps
every module independent from the *implementation* details of the
others -- they only depend on this shared, stable data contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Severity(Enum):
    """Qualitative severity level used by detections and risk scoring."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> int:
        """Numeric weight used by the risk engine for score aggregation.

        Returns:
            An integer weight, higher meaning more severe. These are the
            base point values the risk engine multiplies/aggregates when
            computing an overall attack-chain risk score.
        """
        return {
            Severity.INFO: 1,
            Severity.LOW: 5,
            Severity.MEDIUM: 15,
            Severity.HIGH: 30,
            Severity.CRITICAL: 50,
        }[self]


@dataclass(frozen=True)
class MitreTechnique:
    """A single MITRE ATT&CK technique (or sub-technique) reference.

    Attributes:
        technique_id: e.g. ``"T1110"`` or ``"T1110.001"``.
        name: Human-readable technique name, e.g. "Brute Force".
        tactic: The ATT&CK tactic this technique belongs to, e.g.
            ``"Credential Access"``.
        url: Link to the official MITRE ATT&CK page for the technique.
    """

    technique_id: str
    name: str
    tactic: str
    url: str = ""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.technique_id} ({self.name}) [{self.tactic}]"


@dataclass
class Event:
    """A single, normalized Windows Event Log record.

    This is the canonical representation produced by the parser layer
    for *every* supported event ID. Downstream modules (detections,
    correlation, timeline, reports) only ever interact with ``Event``
    objects, never with raw EVTX/XML structures -- this keeps the parser
    the single place that understands the raw log format.

    Attributes:
        event_id: The Windows Event ID (e.g. 4624, 4688).
        record_id: The EVTX record number (unique within a single log
            file), useful for traceability back to the source file.
        timestamp: UTC timestamp the event was generated.
        channel: The log channel, e.g. ``"Security"`` or ``"System"``.
        computer: The hostname that generated the event.
        provider: The event provider/source name.
        level: Raw Windows level string (e.g. "Information", "Warning").
        event_data: A dict of all EventData/UserData fields extracted
            from the raw XML, keyed by field name (e.g. ``"TargetUserName"``,
            ``"IpAddress"``, ``"LogonType"``).
        raw_xml: The original raw XML string, retained for auditability
            and for report appendices ("show me the raw evidence").
        source_file: Path (as string) of the .evtx file this event came
            from, useful when correlating across multiple log exports.
    """

    event_id: int
    record_id: int
    timestamp: datetime
    channel: str
    computer: str
    provider: str
    level: str
    event_data: dict[str, str] = field(default_factory=dict)
    raw_xml: str = ""
    source_file: str = ""

    def get(self, field_name: str, default: str = "") -> str:
        """Safely fetch an EventData field.

        Args:
            field_name: Name of the field, e.g. ``"TargetUserName"``.
            default: Value returned if the field is absent.

        Returns:
            The field's string value, or ``default`` if not present.
        """
        return self.event_data.get(field_name, default)

    @property
    def target_user(self) -> str:
        """Best-effort extraction of the "target"/subject user for this event."""
        return self.get("TargetUserName") or self.get("SubjectUserName")

    @property
    def source_ip(self) -> str:
        """Best-effort extraction of the source IP address, if present."""
        ip = self.get("IpAddress")
        if ip in ("", "-", "::1", "127.0.0.1"):
            return ip
        return ip

    def to_dict(self) -> dict[str, Any]:
        """Serialize this event to a plain dict (for JSON export).

        Returns:
            A JSON-serializable dictionary representation of the event.
        """
        return {
            "event_id": self.event_id,
            "record_id": self.record_id,
            "timestamp": self.timestamp.isoformat(),
            "channel": self.channel,
            "computer": self.computer,
            "provider": self.provider,
            "level": self.level,
            "event_data": self.event_data,
            "source_file": self.source_file,
        }


@dataclass
class Detection:
    """The result of a single detection rule firing on one or more events.

    Attributes:
        rule_id: Stable machine-readable identifier, e.g.
            ``"brute_force_logon"``.
        title: Human-readable title, e.g. "Brute Force Logon Attempt".
        description: Longer human-readable explanation of what was seen.
        severity: The :class:`Severity` of this specific detection.
        events: The Event objects that triggered/support this detection.
        mitre_techniques: MITRE ATT&CK techniques associated with this
            detection.
        host: The computer/host this detection pertains to.
        user: The primary user account involved, if applicable.
        first_seen: Timestamp of the earliest contributing event.
        last_seen: Timestamp of the latest contributing event.
        metadata: Free-form extra details (counts, thresholds, etc.)
            useful for narrative generation and reporting.
    """

    rule_id: str
    title: str
    description: str
    severity: Severity
    events: list[Event]
    mitre_techniques: list[MitreTechnique] = field(default_factory=list)
    host: str = ""
    user: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Derive first/last seen timestamps and host/user if not supplied."""
        if self.events:
            timestamps = [e.timestamp for e in self.events]
            if self.first_seen is None:
                self.first_seen = min(timestamps)
            if self.last_seen is None:
                self.last_seen = max(timestamps)
            if not self.host:
                self.host = self.events[0].computer
            if not self.user:
                self.user = next(
                    (e.target_user for e in self.events if e.target_user), ""
                )


@dataclass
class AttackChain:
    """A correlated sequence of detections that tell a single "story".

    An attack chain groups related :class:`Detection` objects (typically
    sharing a host and/or user account within a bounded time window) into
    a coherent narrative unit, e.g.: "Brute force -> successful logon ->
    privilege escalation -> persistence -> log clearing".

    Attributes:
        chain_id: Stable unique identifier for this chain.
        detections: Ordered (chronological) list of detections in the chain.
        host: Primary host involved.
        users: Set of user accounts involved across the chain.
        start_time: Timestamp of the first event in the chain.
        end_time: Timestamp of the last event in the chain.
        narrative: Human-readable story text (populated by the narrative
            generator; empty until then).
        risk_score: Numeric risk score (populated by the risk engine).
        risk_severity: Overall :class:`Severity` for the chain (populated
            by the risk engine).
    """

    chain_id: str
    detections: list[Detection]
    host: str = ""
    users: list[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    narrative: str = ""
    risk_score: float = 0.0
    risk_severity: Optional[Severity] = None

    def __post_init__(self) -> None:
        """Derive host/users/time bounds from contributing detections."""
        if self.detections:
            if not self.host:
                self.host = self.detections[0].host
            if not self.users:
                seen: list[str] = []
                for d in self.detections:
                    if d.user and d.user not in seen:
                        seen.append(d.user)
                self.users = seen
            starts = [d.first_seen for d in self.detections if d.first_seen]
            ends = [d.last_seen for d in self.detections if d.last_seen]
            if starts and self.start_time is None:
                self.start_time = min(starts)
            if ends and self.end_time is None:
                self.end_time = max(ends)

    @property
    def mitre_techniques(self) -> list[MitreTechnique]:
        """All unique MITRE techniques referenced across this chain's detections."""
        seen_ids: set[str] = set()
        techniques: list[MitreTechnique] = []
        for detection in self.detections:
            for tech in detection.mitre_techniques:
                if tech.technique_id not in seen_ids:
                    seen_ids.add(tech.technique_id)
                    techniques.append(tech)
        return techniques

    @property
    def all_events(self) -> list[Event]:
        """Flattened, chronologically sorted list of every event in the chain."""
        events: list[Event] = []
        for detection in self.detections:
            events.extend(detection.events)
        return sorted(events, key=lambda e: e.timestamp)
