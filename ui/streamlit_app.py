"""
ui/streamlit_app.py

Lightweight, free, open-source web UI for SOC Storyteller, built with
Streamlit. Lets an analyst upload one or more .evtx files, runs the full
detection/correlation/risk/narrative pipeline, and displays results
interactively (attack chains, timelines, MITRE mapping, and downloadable
reports) without needing the command line.

Run with:
    streamlit run ui/streamlit_app.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Allow running via `streamlit run ui/streamlit_app.py` from the repo root
# by ensuring the project root is on sys.path (Streamlit executes this
# file directly rather than as a package).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import streamlit as st  # noqa: E402

from correlation.correlation_engine import CorrelationEngine  # noqa: E402
from detections.base import DetectionEngine  # noqa: E402
from detections.rules import default_rule_set  # noqa: E402
from parser.evtx_parser import EvtxParser  # noqa: E402
from reports.narrative_generator import NarrativeGenerator  # noqa: E402
from reports.report_generator import ReportGenerator  # noqa: E402
from risk_engine.risk_calculator import RiskCalculator  # noqa: E402
from timeline.timeline_builder import TimelineBuilder  # noqa: E402
from utils.exceptions import SocStorytellerError  # noqa: E402
from utils.models import AttackChain, Event  # noqa: E402

_SEVERITY_COLOR = {
    "CRITICAL": "#d62728",
    "HIGH": "#ff7f0e",
    "MEDIUM": "#f1c232",
    "LOW": "#1f77b4",
    "INFO": "#888888",
}


def _parse_uploaded_files(uploaded_files) -> list[Event]:
    """Parse uploaded .evtx files (in-memory) into a combined event list.

    Args:
        uploaded_files: List of Streamlit ``UploadedFile`` objects.

    Returns:
        A chronologically sorted list of parsed :class:`Event` objects.
    """
    parser = EvtxParser()
    all_events: list[Event] = []

    with tempfile.TemporaryDirectory() as tmp_dir:
        for uploaded in uploaded_files:
            tmp_path = Path(tmp_dir) / uploaded.name
            tmp_path.write_bytes(uploaded.getbuffer())
            all_events.extend(parser.parse(tmp_path))

    all_events.sort(key=lambda e: e.timestamp)
    return all_events


def _run_pipeline(events: list[Event], max_gap_minutes: int) -> tuple[list[AttackChain], float]:
    """Run the full detection -> correlation -> risk -> narrative pipeline.

    Args:
        events: Parsed events to analyze.
        max_gap_minutes: Correlation time-gap tolerance, in minutes.

    Returns:
        Tuple of ``(scored_and_narrated_chains, overall_incident_score)``.
    """
    engine = DetectionEngine().register_all(default_rule_set())
    detections = engine.run(events)
    if not detections:
        return [], 0.0

    chains = CorrelationEngine(max_gap_minutes=max_gap_minutes).correlate(detections)
    calculator = RiskCalculator()
    scored_chains = calculator.score_chains(chains)
    overall_score = calculator.overall_incident_score(scored_chains)
    NarrativeGenerator().generate_all(scored_chains)
    return scored_chains, overall_score


def _render_chain(chain: AttackChain) -> None:
    """Render a single attack chain as an expandable Streamlit section.

    Args:
        chain: The scored, narrated attack chain to display.
    """
    severity = chain.risk_severity.value if chain.risk_severity else "UNSCORED"
    color = _SEVERITY_COLOR.get(severity, "#888888")

    header = f"{chain.chain_id} -- {chain.host} -- {severity} ({chain.risk_score}/100)"
    with st.expander(header, expanded=(severity in ("CRITICAL", "HIGH"))):
        st.markdown(
            f"<span style='color:{color}; font-weight:bold;'>{severity}</span> "
            f"&nbsp;|&nbsp; Users: {', '.join(chain.users) or 'N/A'} "
            f"&nbsp;|&nbsp; {chain.start_time} -> {chain.end_time}",
            unsafe_allow_html=True,
        )

        st.subheader("Attack Narrative")
        st.write(chain.narrative)

        if chain.mitre_techniques:
            st.subheader("MITRE ATT&CK Techniques")
            for tech in chain.mitre_techniques:
                st.markdown(f"- [{tech.technique_id}]({tech.url}) -- {tech.name} ({tech.tactic})")

        st.subheader("Timeline")
        entries = TimelineBuilder().build_from_chain(chain)
        st.table(
            [
                {
                    "Time": e.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "Severity": e.severity.value,
                    "Rule": e.rule_id,
                    "Description": e.description,
                }
                for e in entries
            ]
        )


def main() -> None:
    """Streamlit application entry point."""
    st.set_page_config(page_title="SOC Storyteller", page_icon="🛡️", layout="wide")
    st.title("🛡️ SOC Storyteller")
    st.caption("Turning Windows Event Logs into Attack Narratives")

    with st.sidebar:
        st.header("Configuration")
        max_gap_minutes = st.slider(
            "Correlation window (minutes)",
            min_value=5,
            max_value=240,
            value=60,
            step=5,
            help="Maximum time gap allowed between related detections when building attack chains.",
        )
        uploaded_files = st.file_uploader(
            "Upload .evtx file(s)", type=["evtx"], accept_multiple_files=True
        )
        run_clicked = st.button("Analyze", type="primary", disabled=not uploaded_files)

    if not uploaded_files:
        st.info("Upload one or more Windows .evtx files in the sidebar to begin.")
        return

    if not run_clicked:
        st.info(f"{len(uploaded_files)} file(s) ready. Click **Analyze** to run the pipeline.")
        return

    try:
        with st.spinner("Parsing EVTX files..."):
            events = _parse_uploaded_files(uploaded_files)

        if not events:
            st.warning("No supported events were found in the uploaded file(s).")
            return

        with st.spinner("Running detections, correlation, and risk scoring..."):
            chains, overall_score = _run_pipeline(events, max_gap_minutes)

        if not chains:
            st.success("No attack chains detected -- environment appears clean for the analyzed period.")
            return

        col1, col2, col3 = st.columns(3)
        col1.metric("Events Analyzed", len(events))
        col2.metric("Attack Chains", len(chains))
        col3.metric("Overall Risk Score", f"{overall_score}/100")

        st.divider()
        st.header("Attack Chains")
        for chain in chains:
            _render_chain(chain)

        st.divider()
        st.header("Download Report")
        report_generator = ReportGenerator()
        md_report = report_generator.render_markdown(chains, overall_score=overall_score)
        html_report = report_generator.render_html(chains, overall_score=overall_score)
        json_report = report_generator.render_json(chains, overall_score=overall_score)
        pdf_report = report_generator.render_pdf(chains, overall_score=overall_score)

        dl1, dl2, dl3, dl4 = st.columns(4)
        dl1.download_button("Download Markdown", md_report, file_name="soc_report.md")
        dl2.download_button("Download HTML", html_report, file_name="soc_report.html")
        dl3.download_button("Download JSON", json_report, file_name="soc_report.json")
        dl4.download_button(
            "Download PDF", pdf_report, file_name="soc_report.pdf", mime="application/pdf"
        )

    except SocStorytellerError as exc:
        st.error(f"Analysis failed: {exc}")


if __name__ == "__main__":
    main()
