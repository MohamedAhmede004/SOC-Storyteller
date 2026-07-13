"""
tests/test_integration.py

End-to-end integration test exercising the full pipeline:

    EVTX/XML sample -> parser -> detections -> correlation
        -> risk scoring -> narrative -> reports (md/html/json/pdf)

This complements the module-level unit tests by verifying the pieces
actually compose correctly together, using the bundled synthetic attack
scenario so it runs deterministically in CI with no external files.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from correlation.correlation_engine import CorrelationEngine
from detections.base import DetectionEngine
from detections.rules import default_rule_set
from parser.evtx_parser import EvtxParser
from reports.narrative_generator import NarrativeGenerator
from reports.report_generator import ReportGenerator
from risk_engine.risk_calculator import RiskCalculator
from utils.models import Severity


@pytest.fixture(scope="module")
def scenario_events(sample_xml_path: Path):
    """Parse the bundled synthetic attack scenario once for this test module."""
    if not sample_xml_path.exists():
        pytest.skip("Sample scenario not generated; run sample_logs/generate_sample_data.py")
    return EvtxParser().parse_xml_events_file(sample_xml_path)


@pytest.fixture(scope="module")
def scenario_chains(scenario_events):
    """Run the full detection -> correlation -> risk -> narrative pipeline."""
    engine = DetectionEngine().register_all(default_rule_set())
    detections = engine.run(scenario_events)
    chains = CorrelationEngine(max_gap_minutes=60).correlate(detections)
    scored = RiskCalculator().score_chains(chains)
    NarrativeGenerator().generate_all(scored)
    return scored


class TestFullPipeline:
    def test_events_parsed(self, scenario_events) -> None:
        assert len(scenario_events) > 10

    def test_detections_produced(self, scenario_events) -> None:
        engine = DetectionEngine().register_all(default_rule_set())
        detections = engine.run(scenario_events)
        assert len(detections) > 5
        rule_ids = {d.rule_id for d in detections}
        # Confirm several distinct attack stages were detected.
        assert "brute_force_logon" in rule_ids
        assert "audit_log_cleared" in rule_ids
        assert "account_added_to_privileged_group" in rule_ids

    def test_single_correlated_chain_produced(self, scenario_chains) -> None:
        # The synthetic scenario is a single continuous attack on one
        # host/user-pivot, so it should correlate into exactly one chain.
        assert len(scenario_chains) == 1

    def test_chain_is_critical_due_to_log_clearing(self, scenario_chains) -> None:
        chain = scenario_chains[0]
        assert chain.risk_severity == Severity.CRITICAL
        assert chain.risk_score > 0

    def test_narrative_generated(self, scenario_chains) -> None:
        chain = scenario_chains[0]
        assert len(chain.narrative) > 100
        assert "jsmith" in chain.narrative or "svc_update" in chain.narrative

    def test_mitre_techniques_present(self, scenario_chains) -> None:
        chain = scenario_chains[0]
        technique_ids = {t.technique_id for t in chain.mitre_techniques}
        assert "T1070.001" in technique_ids  # Clear Windows Event Logs
        assert "T1110" in technique_ids  # Brute Force

    def test_markdown_report_generation(self, scenario_chains) -> None:
        md = ReportGenerator().render_markdown(scenario_chains, title="Integration Test Report")
        assert "# Integration Test Report" in md
        assert "CRITICAL" in md

    def test_html_report_generation(self, scenario_chains) -> None:
        html_text = ReportGenerator().render_html(scenario_chains)
        assert html_text.startswith("<!DOCTYPE html>")

    def test_json_report_round_trips(self, scenario_chains) -> None:
        json_text = ReportGenerator().render_json(scenario_chains)
        payload = json.loads(json_text)
        assert payload["chain_count"] == len(scenario_chains)

    def test_pdf_report_generation(self, scenario_chains) -> None:
        pdf_bytes = ReportGenerator().render_pdf(scenario_chains)
        assert pdf_bytes.startswith(b"%PDF")

    def test_reports_writable_to_disk(self, scenario_chains, tmp_path) -> None:
        generator = ReportGenerator()
        md_path = generator.save(generator.render_markdown(scenario_chains), tmp_path / "r.md")
        pdf_path = generator.save(generator.render_pdf(scenario_chains), tmp_path / "r.pdf")
        assert md_path.exists()
        assert pdf_path.exists()
        assert pdf_path.read_bytes().startswith(b"%PDF")
