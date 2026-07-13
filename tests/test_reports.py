"""
tests/test_reports.py

Unit tests for :mod:`reports.report_generator`,
:mod:`reports.narrative_generator`, and :mod:`reports.recommendations`.
"""

from __future__ import annotations

import json

import pytest

from reports.narrative_generator import NarrativeGenerator
from reports.recommendations import (
    recommendations_for_chain,
    recommendations_for_detection,
    recommendations_for_rule,
)
from reports.report_generator import ReportGenerator
from risk_engine.risk_calculator import RiskCalculator
from tests.conftest import make_event
from utils.exceptions import ReportGenerationError
from utils.models import AttackChain, Detection, MitreTechnique, Severity


def _sample_chain() -> AttackChain:
    """Build a small, fully-populated attack chain for report tests."""
    tech = MitreTechnique(technique_id="T1110", name="Brute Force", tactic="Credential Access")
    d1 = Detection(
        rule_id="brute_force_logon",
        title="Brute Force Logon Attempt",
        description="6 failed logons against 'alice'.",
        severity=Severity.MEDIUM,
        events=[make_event(4625, offset_seconds=0, TargetUserName="alice")],
        mitre_techniques=[tech],
        host="HOST-A",
        user="alice",
    )
    d2 = Detection(
        rule_id="audit_log_cleared",
        title="Security Audit Log Cleared",
        description="Log cleared by 'alice'.",
        severity=Severity.CRITICAL,
        events=[make_event(1102, offset_seconds=120, TargetUserName="alice")],
        host="HOST-A",
        user="alice",
    )
    chain = AttackChain(chain_id="chain-test01", detections=[d1, d2])
    RiskCalculator().score_chain(chain)
    NarrativeGenerator().generate(chain)
    return chain


class TestNarrativeGenerator:
    def test_narrative_contains_host_and_users(self) -> None:
        chain = _sample_chain()
        assert "HOST-A" in chain.narrative
        assert "alice" in chain.narrative

    def test_narrative_mentions_critical_urgency(self) -> None:
        chain = _sample_chain()
        assert "Immediate investigation" in chain.narrative

    def test_generate_all_populates_every_chain(self) -> None:
        chains = [_sample_chain(), _sample_chain()]
        for c in chains:
            c.narrative = ""  # reset
        NarrativeGenerator().generate_all(chains)
        assert all(c.narrative for c in chains)


class TestRecommendations:
    def test_known_rule_returns_specific_guidance(self) -> None:
        recs = recommendations_for_rule("audit_log_cleared")
        assert any("incident response" in r.lower() or "isolate" in r.lower() for r in recs)

    def test_unknown_rule_returns_generic_guidance(self) -> None:
        recs = recommendations_for_rule("totally_made_up_rule")
        assert len(recs) > 0

    def test_recommendations_for_detection_delegates_to_rule(self) -> None:
        detection = Detection(
            rule_id="audit_log_cleared",
            title="t",
            description="d",
            severity=Severity.CRITICAL,
            events=[make_event(1102)],
        )
        assert recommendations_for_detection(detection) == recommendations_for_rule("audit_log_cleared")

    def test_chain_recommendations_include_critical_guidance(self) -> None:
        chain = _sample_chain()
        recs = recommendations_for_chain(chain)
        assert any("incident response" in r.lower() for r in recs)

    def test_chain_recommendations_deduplicated(self) -> None:
        chain = _sample_chain()
        recs = recommendations_for_chain(chain)
        assert len(recs) == len(set(recs))


class TestReportGeneratorMarkdown:
    def test_raises_on_empty_chain_list(self) -> None:
        with pytest.raises(ReportGenerationError):
            ReportGenerator().render_markdown([])

    def test_contains_title_and_chain_id(self) -> None:
        chain = _sample_chain()
        md = ReportGenerator().render_markdown([chain], title="Test Report")
        assert "# Test Report" in md
        assert chain.chain_id in md

    def test_contains_recommended_actions_section(self) -> None:
        chain = _sample_chain()
        md = ReportGenerator().render_markdown([chain])
        assert "### Recommended Actions" in md

    def test_contains_mitre_techniques(self) -> None:
        chain = _sample_chain()
        md = ReportGenerator().render_markdown([chain])
        assert "T1110" in md

    def test_appendix_lists_raw_events(self) -> None:
        chain = _sample_chain()
        md = ReportGenerator().render_markdown([chain])
        assert "Appendix: Raw Event Reference" in md
        assert "4625" in md


class TestReportGeneratorHtml:
    def test_produces_valid_html_shell(self) -> None:
        chain = _sample_chain()
        html_text = ReportGenerator().render_html([chain], title="Test Report")
        assert html_text.startswith("<!DOCTYPE html>")
        assert "<title>Test Report</title>" in html_text
        assert "</html>" in html_text

    def test_escapes_html_special_characters(self) -> None:
        chain = _sample_chain()
        chain.detections[0].description = "Suspicious <script>alert(1)</script> & stuff"
        chain.narrative = chain.detections[0].description
        html_text = ReportGenerator().render_html([chain])
        assert "<script>alert(1)</script>" not in html_text


class TestReportGeneratorJson:
    def test_produces_valid_json(self) -> None:
        chain = _sample_chain()
        json_text = ReportGenerator().render_json([chain], overall_score=87.5)
        payload = json.loads(json_text)
        assert payload["overall_risk_score"] == 87.5
        assert payload["chain_count"] == 1
        assert payload["chains"][0]["chain_id"] == chain.chain_id

    def test_json_includes_recommendations(self) -> None:
        chain = _sample_chain()
        payload = json.loads(ReportGenerator().render_json([chain]))
        assert "recommendations" in payload["chains"][0]
        assert len(payload["chains"][0]["recommendations"]) > 0


class TestReportGeneratorPdf:
    def test_produces_pdf_bytes(self) -> None:
        chain = _sample_chain()
        pdf_bytes = ReportGenerator().render_pdf([chain], title="Test PDF Report")
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF")
        assert len(pdf_bytes) > 500

    def test_raises_on_empty_chain_list(self) -> None:
        with pytest.raises(ReportGenerationError):
            ReportGenerator().render_pdf([])


class TestReportGeneratorSave:
    def test_saves_text_content(self, tmp_path) -> None:
        output_path = tmp_path / "report.md"
        ReportGenerator.save("# Hello", output_path)
        assert output_path.read_text() == "# Hello"

    def test_saves_binary_content(self, tmp_path) -> None:
        output_path = tmp_path / "report.pdf"
        ReportGenerator.save(b"%PDF-1.4 fake", output_path)
        assert output_path.read_bytes() == b"%PDF-1.4 fake"

    def test_creates_parent_directories(self, tmp_path) -> None:
        output_path = tmp_path / "nested" / "dir" / "report.md"
        ReportGenerator.save("content", output_path)
        assert output_path.exists()
