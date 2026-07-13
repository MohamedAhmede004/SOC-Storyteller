"""
reports/report_generator.py

Renders a full SOC incident report from a list of scored, narrated
:class:`utils.models.AttackChain` objects.

Three output formats are supported, all built from free/standard-library
tooling only:
    * Markdown (``.md``)  -- primary format, easy to read/version-control.
    * HTML (``.html``)    -- self-contained, styled, shareable in a browser.
    * JSON (``.json``)    -- machine-readable export for tooling/SIEM ingestion.

The Markdown renderer is the "source of truth" formatting logic; the
HTML renderer wraps it with minimal styling rather than duplicating
content-construction logic (no duplicated code between formats).
"""

from __future__ import annotations

import html
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from utils.exceptions import ReportGenerationError
from utils.logger import get_logger
from utils.models import AttackChain, Severity
from timeline.timeline_builder import TimelineBuilder
from reports.recommendations import recommendations_for_chain

logger = get_logger(__name__)

_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class ReportGenerator:
    """Generates SOC incident reports in Markdown, HTML, and JSON.

    Example:
        >>> generator = ReportGenerator()
        >>> markdown_text = generator.render_markdown(chains, title="Incident 2024-01")
        >>> generator.save(markdown_text, Path("reports/incident.md"))
    """

    def __init__(self) -> None:
        """Initialize the report generator with its timeline helper."""
        self._timeline_builder = TimelineBuilder()

    # ----------------------------------------------------------------
    # Markdown
    # ----------------------------------------------------------------

    def render_markdown(
        self,
        chains: list[AttackChain],
        title: str = "SOC Storyteller Incident Report",
        overall_score: float | None = None,
    ) -> str:
        """Render a full Markdown incident report.

        Args:
            chains: Scored and narrated attack chains, ideally already
                sorted by descending risk (as returned by
                ``RiskCalculator.score_chains``).
            title: Report title.
            overall_score: Optional overall incident risk score (0-100)
                to display in the executive summary.

        Returns:
            The complete report as a Markdown string.

        Raises:
            ReportGenerationError: If no chains are provided.
        """
        if not chains:
            raise ReportGenerationError("Cannot generate a report with zero attack chains")

        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines: list[str] = [f"# {title}", "", f"*Generated: {generated_at}*", ""]

        lines.extend(self._render_executive_summary_md(chains, overall_score))
        lines.append("---")
        lines.append("")

        for i, chain in enumerate(chains, start=1):
            lines.extend(self._render_chain_md(chain, index=i))
            lines.append("---")
            lines.append("")

        lines.extend(self._render_appendix_md(chains))

        return "\n".join(lines)

    def _render_executive_summary_md(
        self, chains: list[AttackChain], overall_score: float | None
    ) -> list[str]:
        """Render the executive summary section (Markdown lines).

        Args:
            chains: All attack chains in the report.
            overall_score: Optional overall incident risk score.

        Returns:
            List of Markdown lines for this section.
        """
        severity_counts: dict[str, int] = {}
        for chain in chains:
            sev = chain.risk_severity.value if chain.risk_severity else "UNSCORED"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        total_events = sum(len(c.all_events) for c in chains)
        total_hosts = len({c.host for c in chains})
        total_users = len({u for c in chains for u in c.users})

        lines = ["## Executive Summary", ""]
        if overall_score is not None:
            lines.append(f"**Overall Incident Risk Score:** {overall_score}/100")
            lines.append("")
        lines.append(f"- **Attack chains identified:** {len(chains)}")
        lines.append(f"- **Total correlated events:** {total_events}")
        lines.append(f"- **Hosts involved:** {total_hosts}")
        lines.append(f"- **User accounts involved:** {total_users}")
        lines.append("")
        lines.append("**Chains by severity:**")
        lines.append("")
        for sev, count in sorted(severity_counts.items(), key=lambda kv: kv[0]):
            lines.append(f"- {sev}: {count}")
        lines.append("")
        return lines

    def _render_chain_md(self, chain: AttackChain, index: int) -> list[str]:
        """Render a single attack chain section (Markdown lines).

        Args:
            chain: The attack chain to render.
            index: 1-based display index for this chain in the report.

        Returns:
            List of Markdown lines for this chain's section.
        """
        emoji = _SEVERITY_EMOJI.get(chain.risk_severity, "⚪") if chain.risk_severity else "⚪"
        severity_label = chain.risk_severity.value if chain.risk_severity else "UNSCORED"

        lines = [
            f"## {emoji} Attack Chain {index}: {chain.chain_id}",
            "",
            f"**Host:** {chain.host}  ",
            f"**User(s):** {', '.join(chain.users) or 'N/A'}  ",
            f"**Risk Score:** {chain.risk_score}/100 ({severity_label})  ",
            f"**Time Span:** {self._fmt(chain.start_time)} -> {self._fmt(chain.end_time)}  ",
            "",
        ]

        if chain.mitre_techniques:
            lines.append("**MITRE ATT&CK Techniques:**")
            lines.append("")
            for tech in chain.mitre_techniques:
                lines.append(f"- [{tech.technique_id}]({tech.url}) -- {tech.name} ({tech.tactic})")
            lines.append("")

        lines.append("### Attack Narrative")
        lines.append("")
        lines.append(chain.narrative or "*Narrative not generated.*")
        lines.append("")

        lines.append("### Timeline")
        lines.append("")
        lines.append("| Time | Severity | Rule | Description |")
        lines.append("|------|----------|------|-------------|")
        for entry in self._timeline_builder.build_from_chain(chain):
            desc = entry.description.replace("|", "\\|")
            lines.append(
                f"| {entry.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} "
                f"| {entry.severity.value} | {entry.rule_id} | {desc} |"
            )
        lines.append("")

        lines.append("### Recommended Actions")
        lines.append("")
        for rec in recommendations_for_chain(chain):
            lines.append(f"- {rec}")
        lines.append("")

        return lines

    def _render_appendix_md(self, chains: list[AttackChain]) -> list[str]:
        """Render the raw-events appendix (Markdown lines).

        Args:
            chains: All attack chains in the report.

        Returns:
            List of Markdown lines for the appendix section.
        """
        lines = ["## Appendix: Raw Event Reference", ""]
        lines.append("| Event ID | Record ID | Timestamp | Host | Chain |")
        lines.append("|----------|-----------|-----------|------|-------|")
        for chain in chains:
            for event in chain.all_events:
                lines.append(
                    f"| {event.event_id} | {event.record_id} "
                    f"| {event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} "
                    f"| {event.computer} | {chain.chain_id} |"
                )
        lines.append("")
        return lines

    @staticmethod
    def _fmt(dt: datetime | None) -> str:
        """Format an optional datetime as a display string.

        Args:
            dt: The datetime to format, or None.

        Returns:
            A formatted string, or "N/A" if ``dt`` is None.
        """
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "N/A"

    # ----------------------------------------------------------------
    # HTML
    # ----------------------------------------------------------------

    def render_html(
        self,
        chains: list[AttackChain],
        title: str = "SOC Storyteller Incident Report",
        overall_score: float | None = None,
    ) -> str:
        """Render a self-contained styled HTML incident report.

        Reuses :meth:`render_markdown` for content and wraps a minimal
        Markdown-to-HTML conversion in a styled page shell, avoiding
        duplicated report-content logic between formats.

        Args:
            chains: Scored and narrated attack chains.
            title: Report title.
            overall_score: Optional overall incident risk score (0-100).

        Returns:
            A complete, self-contained HTML document string.
        """
        markdown_text = self.render_markdown(chains, title=title, overall_score=overall_score)
        body_html = self._markdown_to_html(markdown_text)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{html.escape(title)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
          max-width: 960px; margin: 40px auto; padding: 0 20px; color: #1a1a1a;
          background: #fafafa; line-height: 1.55; }}
  h1 {{ border-bottom: 3px solid #2b2b2b; padding-bottom: 10px; }}
  h2 {{ margin-top: 40px; border-bottom: 1px solid #ddd; padding-bottom: 6px; }}
  h3 {{ margin-top: 24px; color: #333; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0 24px 0; font-size: 0.92em; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; }}
  th {{ background: #2b2b2b; color: #fff; }}
  tr:nth-child(even) {{ background: #f0f0f0; }}
  code {{ background: #eee; padding: 1px 5px; border-radius: 3px; }}
  hr {{ border: none; border-top: 2px solid #ddd; margin: 30px 0; }}
  a {{ color: #0b5fff; }}
  ul {{ margin: 8px 0; }}
</style>
</head>
<body>
{body_html}
</body>
</html>"""

    @staticmethod
    def _markdown_to_html(markdown_text: str) -> str:
        """Convert the specific Markdown subset used by this module into HTML.

        This is a deliberately small, dependency-free converter (no
        third-party Markdown library required) that handles exactly the
        constructs :meth:`render_markdown` produces: headers, bold,
        tables, links, list items, and paragraphs. It is not a
        general-purpose Markdown parser.

        Args:
            markdown_text: Markdown text as produced by
                :meth:`render_markdown`.

        Returns:
            An HTML fragment (no ``<html>``/``<body>`` wrapper).
        """
        import re

        lines = markdown_text.split("\n")
        html_lines: list[str] = []
        in_table = False
        in_list = False

        def inline(text: str) -> str:
            text = html.escape(text)
            text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
            text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
            text = re.sub(r"\[(.+?)\]\((.+?)\)", r'<a href="\2" target="_blank">\1</a>', text)
            text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
            return text

        for raw_line in lines:
            line = raw_line.rstrip()
            stripped = line.strip()

            if stripped.startswith("|"):
                cells = [c.strip() for c in stripped.strip("|").split("|")]
                if all(set(c) <= {"-", " "} for c in cells) and cells:
                    continue  # skip markdown table separator row
                if not in_table:
                    html_lines.append("<table>")
                    in_table = True
                    tag = "th"
                else:
                    tag = "td"
                row = "".join(f"<{tag}>{inline(c)}</{tag}>" for c in cells)
                html_lines.append(f"<tr>{row}</tr>")
                continue
            elif in_table:
                html_lines.append("</table>")
                in_table = False

            if stripped.startswith("- "):
                if not in_list:
                    html_lines.append("<ul>")
                    in_list = True
                html_lines.append(f"<li>{inline(stripped[2:])}</li>")
                continue
            elif in_list:
                html_lines.append("</ul>")
                in_list = False

            if stripped == "---":
                html_lines.append("<hr>")
            elif stripped.startswith("### "):
                html_lines.append(f"<h3>{inline(stripped[4:])}</h3>")
            elif stripped.startswith("## "):
                html_lines.append(f"<h2>{inline(stripped[3:])}</h2>")
            elif stripped.startswith("# "):
                html_lines.append(f"<h1>{inline(stripped[2:])}</h1>")
            elif stripped.startswith("*") and stripped.endswith("*") and len(stripped) > 1:
                html_lines.append(f"<p><em>{inline(stripped.strip('*'))}</em></p>")
            elif stripped:
                html_lines.append(f"<p>{inline(stripped)}</p>")

        if in_table:
            html_lines.append("</table>")
        if in_list:
            html_lines.append("</ul>")

        return "\n".join(html_lines)

    # ----------------------------------------------------------------
    # JSON
    # ----------------------------------------------------------------

    def render_json(
        self, chains: list[AttackChain], overall_score: float | None = None
    ) -> str:
        """Render a machine-readable JSON export of the incident report.

        Args:
            chains: Scored and narrated attack chains.
            overall_score: Optional overall incident risk score.

        Returns:
            A pretty-printed JSON string.
        """
        payload: dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_risk_score": overall_score,
            "chain_count": len(chains),
            "chains": [self._chain_to_dict(chain) for chain in chains],
        }
        return json.dumps(payload, indent=2, default=str)

    @staticmethod
    def _chain_to_dict(chain: AttackChain) -> dict[str, Any]:
        """Serialize a single AttackChain (and its detections/events) to a dict.

        Args:
            chain: The attack chain to serialize.

        Returns:
            A JSON-serializable dictionary.
        """
        return {
            "chain_id": chain.chain_id,
            "host": chain.host,
            "users": chain.users,
            "start_time": chain.start_time.isoformat() if chain.start_time else None,
            "end_time": chain.end_time.isoformat() if chain.end_time else None,
            "risk_score": chain.risk_score,
            "risk_severity": chain.risk_severity.value if chain.risk_severity else None,
            "narrative": chain.narrative,
            "recommendations": recommendations_for_chain(chain),
            "mitre_techniques": [
                {"id": t.technique_id, "name": t.name, "tactic": t.tactic, "url": t.url}
                for t in chain.mitre_techniques
            ],
            "detections": [
                {
                    "rule_id": d.rule_id,
                    "title": d.title,
                    "description": d.description,
                    "severity": d.severity.value,
                    "host": d.host,
                    "user": d.user,
                    "first_seen": d.first_seen.isoformat() if d.first_seen else None,
                    "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                    "metadata": d.metadata,
                    "events": [e.to_dict() for e in d.events],
                }
                for d in chain.detections
            ],
        }

    # ----------------------------------------------------------------
    # PDF
    # ----------------------------------------------------------------

    def render_pdf(
        self,
        chains: list[AttackChain],
        title: str = "SOC Storyteller Incident Report",
        overall_score: float | None = None,
    ) -> bytes:
        """Render a professional PDF incident report.

        Built directly with ReportLab's flowable/Platypus layout engine
        (rather than converting the HTML/Markdown output) so pagination,
        headers, and tables render cleanly on paper -- HTML-to-PDF
        converters generally require heavyweight system dependencies
        (Cairo/Pango) that are unnecessary for a text-and-tables report
        like this one.

        Args:
            chains: Scored and narrated attack chains.
            title: Report title.
            overall_score: Optional overall incident risk score (0-100).

        Returns:
            The rendered PDF file content as raw bytes.

        Raises:
            ReportGenerationError: If no chains are provided, or if the
                optional ``reportlab`` dependency is not installed.
        """
        if not chains:
            raise ReportGenerationError("Cannot generate a report with zero attack chains")

        try:
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_LEFT
            from reportlab.lib.pagesizes import LETTER
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                PageBreak,
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )
        except ImportError as exc:  # pragma: no cover - environment issue
            raise ReportGenerationError(
                "reportlab is not installed. Run `pip install reportlab` to enable PDF export."
            ) from exc

        import io

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=LETTER,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
            title=title,
        )

        styles = getSampleStyleSheet()
        styles.add(
            ParagraphStyle(
                name="SocBody", parent=styles["BodyText"], fontSize=9.5, leading=13, alignment=TA_LEFT
            )
        )
        severity_colors = {
            "CRITICAL": colors.HexColor("#d62728"),
            "HIGH": colors.HexColor("#ff7f0e"),
            "MEDIUM": colors.HexColor("#e0b400"),
            "LOW": colors.HexColor("#1f77b4"),
            "INFO": colors.HexColor("#888888"),
        }

        story: list[Any] = [
            Paragraph(title, styles["Title"]),
            Paragraph(
                f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                styles["Italic"],
            ),
            Spacer(1, 14),
        ]

        # Executive summary
        story.append(Paragraph("Executive Summary", styles["Heading1"]))
        total_events = sum(len(c.all_events) for c in chains)
        summary_rows = [
            ["Overall Incident Risk Score", f"{overall_score}/100" if overall_score is not None else "N/A"],
            ["Attack Chains Identified", str(len(chains))],
            ["Total Correlated Events", str(total_events)],
            ["Hosts Involved", str(len({c.host for c in chains}))],
            ["User Accounts Involved", str(len({u for c in chains for u in c.users}))],
        ]
        summary_table = Table(summary_rows, colWidths=[2.8 * inch, 3.2 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#2b2b2b")),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(summary_table)
        story.append(Spacer(1, 10))

        for i, chain in enumerate(chains, start=1):
            story.append(PageBreak())
            severity_label = chain.risk_severity.value if chain.risk_severity else "UNSCORED"
            sev_color = severity_colors.get(severity_label, colors.grey)

            story.append(Paragraph(f"Attack Chain {i}: {chain.chain_id}", styles["Heading1"]))
            meta_style = ParagraphStyle(
                name="Meta", parent=styles["BodyText"], textColor=sev_color, fontSize=11, spaceAfter=6
            )
            story.append(
                Paragraph(
                    f"<b>{severity_label}</b> &nbsp;|&nbsp; Risk Score: {chain.risk_score}/100 "
                    f"&nbsp;|&nbsp; Host: {chain.host}",
                    meta_style,
                )
            )
            story.append(
                Paragraph(
                    f"Users: {', '.join(chain.users) or 'N/A'} &nbsp;|&nbsp; "
                    f"{self._fmt(chain.start_time)} &rarr; {self._fmt(chain.end_time)}",
                    styles["SocBody"],
                )
            )
            story.append(Spacer(1, 8))

            if chain.mitre_techniques:
                story.append(Paragraph("MITRE ATT&CK Techniques", styles["Heading2"]))
                for tech in chain.mitre_techniques:
                    story.append(
                        Paragraph(f"&bull; {tech.technique_id} -- {tech.name} ({tech.tactic})", styles["SocBody"])
                    )
                story.append(Spacer(1, 8))

            story.append(Paragraph("Attack Narrative", styles["Heading2"]))
            story.append(Paragraph(html.escape(chain.narrative or "Narrative not generated."), styles["SocBody"]))
            story.append(Spacer(1, 8))

            story.append(Paragraph("Timeline", styles["Heading2"]))
            timeline_rows = [["Time", "Severity", "Rule", "Description"]]
            for entry in self._timeline_builder.build_from_chain(chain):
                timeline_rows.append(
                    [
                        entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                        entry.severity.value,
                        entry.rule_id,
                        Paragraph(html.escape(entry.description), styles["SocBody"]),
                    ]
                )
            timeline_table = Table(
                timeline_rows, colWidths=[1.3 * inch, 0.7 * inch, 1.4 * inch, 2.6 * inch], repeatRows=1
            )
            timeline_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2b2b2b")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
                    ]
                )
            )
            story.append(timeline_table)
            story.append(Spacer(1, 8))

            story.append(Paragraph("Recommended Actions", styles["Heading2"]))
            for rec in recommendations_for_chain(chain):
                story.append(Paragraph(f"&bull; {html.escape(rec)}", styles["SocBody"]))

        doc.build(story)
        return buffer.getvalue()

    # ----------------------------------------------------------------
    # Persistence
    # ----------------------------------------------------------------

    @staticmethod
    def save(content: str | bytes, output_path: Path) -> Path:
        """Write rendered report content to disk.

        Args:
            content: The rendered report content -- text (Markdown,
                HTML, or JSON) or raw bytes (PDF).
            output_path: Destination file path. Parent directories are
                created automatically.

        Returns:
            The resolved output path.

        Raises:
            ReportGenerationError: If the file cannot be written.
        """
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                output_path.write_bytes(content)
            else:
                output_path.write_text(content, encoding="utf-8")
        except OSError as exc:
            raise ReportGenerationError(f"Failed to write report to {output_path}: {exc}") from exc
        logger.info("Report written to %s", output_path)
        return output_path
