#!/usr/bin/env python3
"""
main.py

SOC Storyteller -- CLI entry point.

Orchestrates the full pipeline:

    EVTX file(s)
        -> EvtxParser            (parser/evtx_parser.py)
        -> DetectionEngine       (detections/base.py + detections/rules.py)
        -> CorrelationEngine     (correlation/correlation_engine.py)
        -> RiskCalculator        (risk_engine/risk_calculator.py)
        -> NarrativeGenerator    (reports/narrative_generator.py)
        -> ReportGenerator       (reports/report_generator.py)

Usage:
    python main.py --input sample_logs/security.evtx --output reports/incident
    python main.py --input-dir sample_logs/ --format html --output reports/incident
    python main.py --input sample_logs/security.evtx --format json --verbose

Run `python main.py --help` for the full list of options.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from correlation.correlation_engine import CorrelationEngine
from detections.base import DetectionEngine
from detections.rules import default_rule_set
from parser.evtx_parser import EvtxParser
from reports.narrative_generator import NarrativeGenerator
from reports.report_generator import ReportGenerator
from risk_engine.risk_calculator import RiskCalculator
from utils.exceptions import SocStorytellerError
from utils.logger import configure_logging, get_logger
from utils.models import Event

logger = get_logger(__name__)


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser.

    Returns:
        A fully configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="soc-storyteller",
        description="Turn Windows Event Logs into attack narratives.",
    )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--input", type=Path, help="Path to a single .evtx file to analyze."
    )
    input_group.add_argument(
        "--input-dir", type=Path, help="Path to a directory of .evtx files to analyze."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/incident_report"),
        help="Output report path WITHOUT extension (extension is added based on --format). "
        "Default: output/incident_report",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "html", "json", "pdf", "all"],
        default="markdown",
        help="Report output format. Default: markdown",
    )
    parser.add_argument(
        "--max-gap-minutes",
        type=int,
        default=60,
        help="Maximum time gap (minutes) allowed between related detections "
        "when correlating attack chains. Default: 60",
    )
    parser.add_argument(
        "--title",
        type=str,
        default="SOC Storyteller Incident Report",
        help="Title to use in the generated report.",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose (DEBUG) logging."
    )
    parser.add_argument(
        "--log-file", type=Path, default=None, help="Optional path to also write logs to a file."
    )
    return parser


def load_events(args: argparse.Namespace) -> list[Event]:
    """Load and parse events based on the CLI arguments.

    Args:
        args: Parsed CLI arguments.

    Returns:
        A chronologically sorted list of parsed :class:`Event` objects.

    Raises:
        SocStorytellerError: If parsing fails for any configured input.
    """
    evtx_parser = EvtxParser()
    if args.input is not None:
        return evtx_parser.parse(args.input)
    return evtx_parser.parse_directory(args.input_dir)


def run_pipeline(events: list[Event], max_gap_minutes: int) -> tuple[list, float]:
    """Run detection -> correlation -> risk scoring -> narrative generation.

    Args:
        events: Parsed events to analyze.
        max_gap_minutes: Correlation time-gap tolerance, in minutes.

    Returns:
        A tuple of ``(scored_and_narrated_chains, overall_incident_score)``.
    """
    detection_engine = DetectionEngine().register_all(default_rule_set())
    detections = detection_engine.run(events)
    logger.info("Total detections found: %d", len(detections))

    if not detections:
        return [], 0.0

    correlation_engine = CorrelationEngine(max_gap_minutes=max_gap_minutes)
    chains = correlation_engine.correlate(detections)

    risk_calculator = RiskCalculator()
    scored_chains = risk_calculator.score_chains(chains)
    overall_score = risk_calculator.overall_incident_score(scored_chains)

    narrative_generator = NarrativeGenerator()
    narrative_generator.generate_all(scored_chains)

    return scored_chains, overall_score


def write_reports(chains: list, overall_score: float, args: argparse.Namespace) -> list[Path]:
    """Render and write the requested report format(s) to disk.

    Args:
        chains: Scored, narrated attack chains.
        overall_score: Overall incident risk score.
        args: Parsed CLI arguments (uses ``format``, ``output``, ``title``).

    Returns:
        List of output file paths that were written.
    """
    generator = ReportGenerator()
    formats = ["markdown", "html", "json", "pdf"] if args.format == "all" else [args.format]
    written: list[Path] = []

    extension_map = {"markdown": ".md", "html": ".html", "json": ".json", "pdf": ".pdf"}
    renderer_map = {
        "markdown": generator.render_markdown,
        "html": generator.render_html,
        "json": lambda c, **kw: generator.render_json(c, overall_score=kw.get("overall_score")),
        "pdf": generator.render_pdf,
    }

    for fmt in formats:
        if fmt == "json":
            content = renderer_map[fmt](chains, overall_score=overall_score)
        else:
            content = renderer_map[fmt](chains, title=args.title, overall_score=overall_score)
        output_path = args.output.with_suffix(extension_map[fmt])
        generator.save(content, output_path)
        written.append(output_path)

    return written


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Optional argument list (for testing); defaults to
            ``sys.argv[1:]`` when None.

    Returns:
        Process exit code: 0 on success, 1 on failure, 2 if no attack
        chains were found (not an error, but nothing to report).
    """
    args = build_arg_parser().parse_args(argv)
    configure_logging(verbose=args.verbose, log_file=args.log_file)

    try:
        logger.info("Starting SOC Storyteller pipeline")
        events = load_events(args)
        logger.info("Loaded %d total events", len(events))

        if not events:
            logger.warning("No supported events found in input. Nothing to analyze.")
            return 2

        chains, overall_score = run_pipeline(events, args.max_gap_minutes)

        if not chains:
            logger.info("No attack chains detected. Environment appears clean for the analyzed period.")
            return 2

        written_paths = write_reports(chains, overall_score, args)

        print("\n=== SOC Storyteller Summary ===")
        print(f"Events analyzed:      {len(events)}")
        print(f"Attack chains found:  {len(chains)}")
        print(f"Overall risk score:   {overall_score}/100")
        print("Reports written:")
        for path in written_paths:
            print(f"  - {path}")
        print("================================\n")

        return 0

    except SocStorytellerError as exc:
        logger.error("SOC Storyteller failed: %s", exc)
        return 1
    except Exception as exc:  # noqa: BLE001 - top-level safety net for CLI usage
        logger.exception("Unexpected error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
