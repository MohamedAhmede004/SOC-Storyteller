"""
reports/narrative_generator.py

Turns a correlated :class:`utils.models.AttackChain` into a
human-readable "attack story" -- the feature that gives SOC Storyteller
its name.

The generator is template-based (not an LLM call) so it runs fully
offline with only free/open-source dependencies and produces
deterministic, auditable output suitable for a SOC report. It stitches
each detection's existing description into a chronological narrative,
adding connective language and a summary/impact section.
"""

from __future__ import annotations

from utils.logger import get_logger
from utils.models import AttackChain, Detection, Severity

logger = get_logger(__name__)

# Connective phrases used to stitch consecutive story beats together,
# cycled through in order to avoid repetitive "Then... Then... Then..."
# prose.
_CONNECTORS = [
    "Next,",
    "Shortly after,",
    "Following this,",
    "Subsequently,",
    "The activity then continued as",
    "This was followed by",
]


class NarrativeGenerator:
    """Generates human-readable attack narratives from attack chains."""

    def generate(self, chain: AttackChain) -> str:
        """Generate a full narrative for a single attack chain.

        Args:
            chain: The attack chain to narrate. Should already be
                risk-scored (via :class:`risk_engine.risk_calculator.RiskCalculator`)
                for the summary section to be meaningful; if not scored,
                the summary simply omits risk commentary.

        Returns:
            A multi-paragraph human-readable narrative string. Also
            stored on ``chain.narrative`` for convenience.
        """
        opening = self._build_opening(chain)
        body = self._build_body(chain)
        closing = self._build_closing(chain)

        narrative = "\n\n".join(part for part in (opening, body, closing) if part)
        chain.narrative = narrative
        return narrative

    def generate_all(self, chains: list[AttackChain]) -> list[AttackChain]:
        """Generate narratives for a list of chains, in place.

        Args:
            chains: List of attack chains to narrate.

        Returns:
            The same list, with each chain's ``narrative`` field populated.
        """
        for chain in chains:
            self.generate(chain)
        return chains

    # ----------------------------------------------------------------
    # Internal narrative construction
    # ----------------------------------------------------------------

    @staticmethod
    def _build_opening(chain: AttackChain) -> str:
        """Build the introductory paragraph identifying actors, host, and time span.

        Args:
            chain: The attack chain being narrated.

        Returns:
            The opening paragraph text.
        """
        users = ", ".join(f"'{u}'" for u in chain.users) if chain.users else "an unidentified account"
        start = chain.start_time.strftime("%Y-%m-%d %H:%M:%S UTC") if chain.start_time else "an unknown time"
        end = chain.end_time.strftime("%Y-%m-%d %H:%M:%S UTC") if chain.end_time else "an unknown time"
        duration_note = ""
        if chain.start_time and chain.end_time:
            delta = chain.end_time - chain.start_time
            total_minutes = max(0, int(delta.total_seconds() // 60))
            duration_note = f" spanning approximately {total_minutes} minute(s)"

        return (
            f"Between {start} and {end}{duration_note}, activity involving "
            f"{users} was observed on host '{chain.host}'. The following "
            f"sequence of {len(chain.detections)} correlated detection(s) "
            "reconstructs what appears to have happened, in chronological order."
        )

    @staticmethod
    def _build_body(chain: AttackChain) -> str:
        """Build the chronological "story beats" paragraph sequence.

        Args:
            chain: The attack chain being narrated.

        Returns:
            The narrative body text, one sentence per detection, stitched
            with connective phrases.
        """
        sentences: list[str] = []
        for i, detection in enumerate(chain.detections):
            timestamp = (
                detection.first_seen.strftime("%H:%M:%S UTC")
                if detection.first_seen
                else "an unknown time"
            )
            connector = "" if i == 0 else f"{_CONNECTORS[(i - 1) % len(_CONNECTORS)]} "
            severity_tag = f"[{detection.severity.value}]"
            sentences.append(
                f"{connector}at {timestamp}, {severity_tag} {detection.description}"
            )
        return " ".join(sentences)

    @staticmethod
    def _build_closing(chain: AttackChain) -> str:
        """Build the closing summary/impact paragraph, including risk and MITRE context.

        Args:
            chain: The attack chain being narrated.

        Returns:
            The closing paragraph text.
        """
        technique_names = ", ".join(
            f"{t.technique_id} ({t.name})" for t in chain.mitre_techniques
        )
        risk_note = ""
        if chain.risk_severity is not None:
            risk_note = (
                f" This chain has been assessed as {chain.risk_severity.value} risk "
                f"(score: {chain.risk_score}/100)."
            )

        has_critical = any(d.severity == Severity.CRITICAL for d in chain.detections)
        urgency_note = (
            " Immediate investigation and containment is strongly recommended given "
            "the presence of critical-severity indicators."
            if has_critical
            else " Analysts should validate these findings against known-good "
            "administrative activity before escalating."
        )

        mitre_note = (
            f" Observed behavior maps to MITRE ATT&CK technique(s): {technique_names}."
            if technique_names
            else ""
        )

        return (
            f"In summary, this chain represents a {len(chain.detections)}-stage "
            f"sequence of events on '{chain.host}'.{mitre_note}{risk_note}{urgency_note}"
        )
