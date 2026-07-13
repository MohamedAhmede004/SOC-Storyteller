"""
risk_engine/risk_calculator.py

Computes a numeric risk score (0-100) and overall :class:`Severity` for
each attack chain, and can rank/aggregate scores across an entire
incident (a set of chains).

Scoring model:
    score = base_severity_component + technique_diversity_bonus
            + multi_stage_bonus + critical_detection_bonus

    * base_severity_component: sum of each detection's severity weight
      (see :attr:`Severity.weight`), diminishing-returns capped so a
      chain with 50 identical LOW detections doesn't outscore a chain
      with 3 well-correlated HIGH/CRITICAL detections.
    * technique_diversity_bonus: rewards chains that span multiple
      distinct MITRE ATT&CK tactics (recon -> credential access ->
      persistence is scarier than 5 detections of the same tactic).
    * multi_stage_bonus: rewards chains with several distinct rule_ids
      firing (i.e. actually a "chain", not repeated noise from one rule).
    * critical_detection_bonus: any CRITICAL-severity detection (e.g.
      audit log cleared) adds a flat bonus, since a single such event is
      disproportionately significant regardless of chain length.

The final score is clamped to [0, 100] and mapped to a qualitative
:class:`Severity` band for reporting.
"""

from __future__ import annotations

import math

from utils.exceptions import RiskCalculationError
from utils.logger import get_logger
from utils.models import AttackChain, Severity

logger = get_logger(__name__)

# Score thresholds mapping a numeric score to a qualitative severity band.
_SEVERITY_BANDS: list[tuple[float, Severity]] = [
    (85.0, Severity.CRITICAL),
    (60.0, Severity.HIGH),
    (35.0, Severity.MEDIUM),
    (15.0, Severity.LOW),
    (0.0, Severity.INFO),
]

_MAX_SCORE = 100.0
_DIVERSITY_BONUS_PER_TACTIC = 6.0
_MULTI_STAGE_BONUS_PER_RULE = 5.0
_CRITICAL_DETECTION_BONUS = 20.0


class RiskCalculator:
    """Computes risk scores for attack chains.

    Example:
        >>> calc = RiskCalculator()
        >>> scored_chains = calc.score_chains(chains)
        >>> scored_chains[0].risk_score
        78.5
    """

    def score_chain(self, chain: AttackChain) -> AttackChain:
        """Compute and attach a risk score/severity to a single chain.

        Mutates and returns the same ``AttackChain`` instance for
        convenience (its ``risk_score`` and ``risk_severity`` fields are
        populated in place).

        Args:
            chain: The attack chain to score.

        Returns:
            The same chain, with ``risk_score`` and ``risk_severity`` set.

        Raises:
            RiskCalculationError: If the chain has no detections.
        """
        if not chain.detections:
            raise RiskCalculationError(f"Chain '{chain.chain_id}' has no detections to score")

        base_component = self._base_severity_component(chain)
        diversity_bonus = self._technique_diversity_bonus(chain)
        stage_bonus = self._multi_stage_bonus(chain)
        critical_bonus = self._critical_detection_bonus(chain)

        raw_score = base_component + diversity_bonus + stage_bonus + critical_bonus
        final_score = max(0.0, min(_MAX_SCORE, raw_score))

        chain.risk_score = round(final_score, 1)
        chain.risk_severity = self._severity_for_score(final_score)

        logger.debug(
            "Scored chain %s: base=%.1f diversity=%.1f stage=%.1f critical=%.1f -> %.1f (%s)",
            chain.chain_id,
            base_component,
            diversity_bonus,
            stage_bonus,
            critical_bonus,
            final_score,
            chain.risk_severity.value,
        )
        return chain

    def score_chains(self, chains: list[AttackChain]) -> list[AttackChain]:
        """Score multiple chains and return them sorted by descending risk.

        Args:
            chains: List of attack chains to score.

        Returns:
            The same chains (scored in place), sorted so the highest-risk
            chain appears first.
        """
        for chain in chains:
            self.score_chain(chain)
        return sorted(chains, key=lambda c: c.risk_score, reverse=True)

    def overall_incident_score(self, chains: list[AttackChain]) -> float:
        """Aggregate a single overall risk score across all chains in an incident.

        Uses a "diminishing returns" aggregation (not a simple sum) so
        that ten low-risk chains do not automatically outrank one
        critical chain, while still acknowledging that multiple
        concurrent chains represent a broader compromise.

        Args:
            chains: All scored attack chains for the incident. Chains
                that have not yet been scored (``risk_score == 0.0`` and
                no severity) will be scored automatically.

        Returns:
            An aggregate score in the range [0, 100].
        """
        if not chains:
            return 0.0

        for chain in chains:
            if chain.risk_severity is None:
                self.score_chain(chain)

        scores = sorted((c.risk_score for c in chains), reverse=True)
        top_score = scores[0]
        # Each additional chain contributes a shrinking fraction of its
        # own score to the aggregate (harmonic-style dampening).
        remainder = sum(score / (i + 2) for i, score in enumerate(scores[1:]))
        aggregate = top_score + remainder
        return round(min(_MAX_SCORE, aggregate), 1)

    # ----------------------------------------------------------------
    # Internal scoring components
    # ----------------------------------------------------------------

    @staticmethod
    def _base_severity_component(chain: AttackChain) -> float:
        """Sum detection severity weights with logarithmic diminishing returns.

        Args:
            chain: The attack chain being scored.

        Returns:
            The base severity score component.
        """
        total_weight = sum(d.severity.weight for d in chain.detections)
        # log-dampen raw weight sum so very long chains of low-severity
        # noise don't dominate the score; log base chosen empirically so
        # a single HIGH (weight 30) detection lands around ~30 points.
        if total_weight <= 0:
            return 0.0
        return min(70.0, 10 * math.log2(total_weight + 1))

    @staticmethod
    def _technique_diversity_bonus(chain: AttackChain) -> float:
        """Reward chains spanning multiple distinct MITRE ATT&CK tactics.

        Args:
            chain: The attack chain being scored.

        Returns:
            Bonus points proportional to distinct tactics observed.
        """
        tactics: set[str] = set()
        for technique in chain.mitre_techniques:
            for tactic in technique.tactic.split(","):
                tactics.add(tactic.strip())
        # First tactic is "free" (every chain has at least one); bonus
        # applies to each *additional* distinct tactic.
        extra_tactics = max(0, len(tactics) - 1)
        return extra_tactics * _DIVERSITY_BONUS_PER_TACTIC

    @staticmethod
    def _multi_stage_bonus(chain: AttackChain) -> float:
        """Reward chains composed of multiple distinct detection rules.

        Args:
            chain: The attack chain being scored.

        Returns:
            Bonus points proportional to distinct rule_ids in the chain.
        """
        distinct_rules = {d.rule_id for d in chain.detections}
        extra_rules = max(0, len(distinct_rules) - 1)
        return extra_rules * _MULTI_STAGE_BONUS_PER_RULE

    @staticmethod
    def _critical_detection_bonus(chain: AttackChain) -> float:
        """Flat bonus if any single detection in the chain is CRITICAL severity.

        Args:
            chain: The attack chain being scored.

        Returns:
            A flat bonus if a CRITICAL detection is present, else 0.
        """
        if any(d.severity == Severity.CRITICAL for d in chain.detections):
            return _CRITICAL_DETECTION_BONUS
        return 0.0

    @staticmethod
    def _severity_for_score(score: float) -> Severity:
        """Map a numeric score to a qualitative severity band.

        Args:
            score: The final numeric risk score.

        Returns:
            The corresponding :class:`Severity`.
        """
        for threshold, severity in _SEVERITY_BANDS:
            if score >= threshold:
                return severity
        return Severity.INFO
