"""
detections/base.py

Abstract base class for detection rules, plus the ``DetectionEngine``
that runs a collection of rules against a parsed event stream.

Design (Strategy pattern + Open/Closed Principle):
    Each concrete detection rule is a small, self-contained class
    implementing :meth:`DetectionRule.evaluate`. New detections are added
    by writing a new subclass and registering it with
    :class:`DetectionEngine` -- no existing code needs to change
    (Open/Closed). The engine itself has zero knowledge of *what* any
    individual rule looks for (Single Responsibility / Dependency
    Inversion): it only knows how to run a list of ``DetectionRule``
    objects and collect their results.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from utils.exceptions import DetectionRuleError
from utils.logger import get_logger
from utils.models import Detection, Event

logger = get_logger(__name__)


class DetectionRule(ABC):
    """Base class every concrete detection rule must implement.

    Attributes:
        rule_id: Stable, machine-readable identifier for the rule
            (used for MITRE mapping lookups and report grouping). Must
            be unique across all registered rules.
        title: Short human-readable title.
    """

    rule_id: str = "base_rule"
    title: str = "Unnamed Rule"

    @abstractmethod
    def evaluate(self, events: list[Event]) -> list[Detection]:
        """Evaluate this rule against a chronological list of events.

        Implementations should be pure functions of ``events`` (no
        hidden state carried between calls) so rules can be safely
        reused/re-run.

        Args:
            events: All parsed events, sorted chronologically, typically
                already filtered to a single host by the caller.

        Returns:
            A list of zero or more :class:`Detection` objects. Returning
            an empty list means the rule found nothing.

        Raises:
            DetectionRuleError: If the rule cannot evaluate due to
                unexpected/malformed input.
        """
        raise NotImplementedError

    def _events_of_type(self, events: list[Event], event_id: int) -> list[Event]:
        """Convenience helper: filter events down to a single Event ID.

        Args:
            events: Events to filter.
            event_id: The Windows Event ID to keep.

        Returns:
            Filtered list, preserving original order.
        """
        return [e for e in events if e.event_id == event_id]

    def _events_of_types(self, events: list[Event], event_ids: set[int]) -> list[Event]:
        """Convenience helper: filter events down to a set of Event IDs.

        Args:
            events: Events to filter.
            event_ids: Set of Windows Event IDs to keep.

        Returns:
            Filtered list, preserving original order.
        """
        return [e for e in events if e.event_id in event_ids]


class DetectionEngine:
    """Runs a registered collection of :class:`DetectionRule` objects.

    Example:
        >>> engine = DetectionEngine()
        >>> engine.register(BruteForceLogonRule())
        >>> detections = engine.run(events)
    """

    def __init__(self) -> None:
        """Initialize an empty detection engine with no rules registered."""
        self._rules: list[DetectionRule] = []

    def register(self, rule: DetectionRule) -> "DetectionEngine":
        """Register a detection rule with the engine.

        Args:
            rule: A :class:`DetectionRule` instance.

        Returns:
            ``self``, to allow fluent chaining of ``.register(...)`` calls.
        """
        self._rules.append(rule)
        logger.debug("Registered detection rule: %s (%s)", rule.rule_id, rule.title)
        return self

    def register_all(self, rules: list[DetectionRule]) -> "DetectionEngine":
        """Register multiple detection rules at once.

        Args:
            rules: List of :class:`DetectionRule` instances.

        Returns:
            ``self``, to allow fluent chaining.
        """
        for rule in rules:
            self.register(rule)
        return self

    @property
    def registered_rule_ids(self) -> list[str]:
        """List of rule_id values currently registered, in registration order."""
        return [rule.rule_id for rule in self._rules]

    def run(self, events: list[Event]) -> list[Detection]:
        """Run every registered rule against the given events.

        A failure in one rule does not prevent other rules from running;
        the failing rule's error is logged and it simply contributes no
        detections.

        Args:
            events: Chronologically sorted events to analyze.

        Returns:
            A combined, chronologically sorted list of all detections
            produced by all registered rules.
        """
        if not self._rules:
            logger.warning("DetectionEngine.run() called with no rules registered")

        all_detections: list[Detection] = []
        for rule in self._rules:
            try:
                results = rule.evaluate(events)
                logger.info(
                    "Rule '%s' produced %d detection(s)", rule.rule_id, len(results)
                )
                all_detections.extend(results)
            except DetectionRuleError as exc:
                logger.error("Detection rule '%s' failed: %s", rule.rule_id, exc)
            except Exception as exc:  # noqa: BLE001 - isolate rule failures
                logger.error(
                    "Unexpected error in detection rule '%s': %s", rule.rule_id, exc
                )

        all_detections.sort(key=lambda d: d.first_seen or d.events[0].timestamp)
        return all_detections
