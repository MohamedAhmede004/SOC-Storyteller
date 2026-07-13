"""
correlation/correlation_engine.py

Groups individual :class:`utils.models.Detection` objects into
:class:`utils.models.AttackChain` objects -- the step from "a pile of
alerts" to "a story".

Correlation strategy:
    Detections are linked into the same chain when they share an
    "identity" (same host, or same user account) AND occur within a
    configurable maximum time gap of each other. This is implemented as
    a union-find (disjoint-set) style clustering over a similarity graph,
    which handles the common real-world case where a chain pivots
    identity partway through (e.g. attacker compromises `alice` on
    HOST-A, creates a new local admin account `svc_backup`, and the rest
    of the chain continues under that new identity).

This keeps the correlation logic independent of any specific detection
rule (Dependency Inversion) -- it operates purely on the shared
Detection/Event contract.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from utils.exceptions import CorrelationError
from utils.logger import get_logger
from utils.models import AttackChain, Detection

logger = get_logger(__name__)


class CorrelationEngine:
    """Correlates flat detection lists into coherent attack chains.

    Example:
        >>> engine = CorrelationEngine(max_gap_minutes=60)
        >>> chains = engine.correlate(detections)
    """

    def __init__(self, max_gap_minutes: int = 60) -> None:
        """Configure correlation sensitivity.

        Args:
            max_gap_minutes: Maximum allowed time gap, in minutes,
                between two detections for them to be considered part of
                the same ongoing chain (even if they share host/user).
                Larger values merge more activity into fewer, longer
                chains; smaller values produce more, shorter chains.
        """
        self.max_gap = timedelta(minutes=max_gap_minutes)

    def correlate(self, detections: list[Detection]) -> list[AttackChain]:
        """Cluster detections into attack chains.

        Args:
            detections: All detections produced by the detection engine,
                across all hosts. Order does not matter (they are
                re-sorted internally).

        Returns:
            A list of :class:`AttackChain` objects, each containing one
            or more related detections, sorted by chain start time.

        Raises:
            CorrelationError: If a detection is missing required time
                information needed for correlation.
        """
        if not detections:
            logger.info("No detections provided to correlate; returning empty chain list.")
            return []

        for d in detections:
            if d.first_seen is None or d.last_seen is None:
                raise CorrelationError(
                    f"Detection '{d.rule_id}' is missing first_seen/last_seen timestamps"
                )

        ordered = sorted(detections, key=lambda d: d.first_seen)
        n = len(ordered)
        parent = list(range(n))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        # Build union-find links: connect any two detections that share
        # an identity (host or any overlapping user) and fall within the
        # allowed time gap. This is O(n^2) in the worst case, which is
        # acceptable for typical incident-scale detection counts (tens
        # to low thousands); very large deployments should pre-bucket by
        # host before calling this method.
        for i in range(n):
            for j in range(i + 1, n):
                if self._are_related(ordered[i], ordered[j]):
                    union(i, j)

        clusters: dict[int, list[Detection]] = {}
        for idx in range(n):
            root = find(idx)
            clusters.setdefault(root, []).append(ordered[idx])

        chains: list[AttackChain] = []
        for cluster_detections in clusters.values():
            cluster_detections.sort(key=lambda d: d.first_seen)
            chain = AttackChain(
                chain_id=f"chain-{uuid.uuid4().hex[:8]}",
                detections=cluster_detections,
            )
            chains.append(chain)

        chains.sort(key=lambda c: c.start_time or c.detections[0].first_seen)
        logger.info(
            "Correlated %d detections into %d attack chain(s)", len(detections), len(chains)
        )
        return chains

    def _are_related(self, a: Detection, b: Detection) -> bool:
        """Determine whether two detections belong in the same chain.

        Two detections are considered related if they share the same
        host, OR share the same user account, AND the time gap between
        them (measured from the closer pair of endpoints) does not
        exceed :attr:`max_gap`.

        Args:
            a: First detection.
            b: Second detection.

        Returns:
            True if the detections should be merged into the same chain.
        """
        same_host = bool(a.host) and a.host == b.host
        same_user = bool(a.user) and bool(b.user) and a.user.lower() == b.user.lower()

        if not (same_host or same_user):
            return False

        gap = self._time_gap(a, b)
        return gap <= self.max_gap

    @staticmethod
    def _time_gap(a: Detection, b: Detection) -> timedelta:
        """Compute the minimal time gap between two detections' time ranges.

        Args:
            a: First detection.
            b: Second detection.

        Returns:
            Zero if the ranges overlap, otherwise the gap between the
            closer pair of endpoints.
        """
        if a.first_seen <= b.last_seen and b.first_seen <= a.last_seen:
            return timedelta(0)
        if a.last_seen < b.first_seen:
            return b.first_seen - a.last_seen
        return a.first_seen - b.last_seen
