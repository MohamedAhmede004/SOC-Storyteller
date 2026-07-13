"""
tests/test_main_cli.py

Tests for the ``main.py`` CLI entry point, run against the bundled
synthetic sample scenario (converted to a temp .xml -- the CLI itself
only knows how to read real .evtx via --input, so these tests exercise
argument parsing and the orchestration helper functions directly rather
than shelling out to a real .evtx file).
"""

from __future__ import annotations

from pathlib import Path

import pytest

import main as cli
from parser.evtx_parser import EvtxParser


class TestArgParser:
    def test_requires_input_or_input_dir(self) -> None:
        parser = cli.build_arg_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_input_and_input_dir_mutually_exclusive(self) -> None:
        parser = cli.build_arg_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--input", "a.evtx", "--input-dir", "somedir"])

    def test_defaults(self) -> None:
        parser = cli.build_arg_parser()
        args = parser.parse_args(["--input", "a.evtx"])
        assert args.format == "markdown"
        assert args.max_gap_minutes == 60
        assert args.output == Path("output/incident_report")

    def test_format_accepts_pdf(self) -> None:
        parser = cli.build_arg_parser()
        args = parser.parse_args(["--input", "a.evtx", "--format", "pdf"])
        assert args.format == "pdf"


class TestRunPipeline:
    def test_run_pipeline_on_sample_scenario(self, sample_xml_path: Path) -> None:
        if not sample_xml_path.exists():
            pytest.skip("Sample scenario not generated")
        events = EvtxParser().parse_xml_events_file(sample_xml_path)
        chains, overall_score = cli.run_pipeline(events, max_gap_minutes=60)
        assert len(chains) >= 1
        assert overall_score > 0
        assert all(c.narrative for c in chains)

    def test_run_pipeline_empty_events_returns_empty(self) -> None:
        chains, overall_score = cli.run_pipeline([], max_gap_minutes=60)
        assert chains == []
        assert overall_score == 0.0


class TestLoadEvents:
    def test_load_events_uses_input_dir_when_set(self, monkeypatch) -> None:
        calls = {}

        def fake_parse_directory(self, directory):
            calls["directory"] = directory
            return []

        monkeypatch.setattr(EvtxParser, "parse_directory", fake_parse_directory)
        args = cli.build_arg_parser().parse_args(["--input-dir", "some/dir"])
        cli.load_events(args)
        assert calls["directory"] == Path("some/dir")


class TestWriteReports:
    def test_writes_all_formats(self, sample_xml_path: Path, tmp_path) -> None:
        if not sample_xml_path.exists():
            pytest.skip("Sample scenario not generated")
        events = EvtxParser().parse_xml_events_file(sample_xml_path)
        chains, overall_score = cli.run_pipeline(events, max_gap_minutes=60)

        args = cli.build_arg_parser().parse_args(
            ["--input", "unused.evtx", "--format", "all", "--output", str(tmp_path / "report")]
        )
        written = cli.write_reports(chains, overall_score, args)
        assert len(written) == 4
        for path in written:
            assert path.exists()
            assert path.stat().st_size > 0


class TestMainEntrypoint:
    def test_main_returns_1_for_missing_file(self) -> None:
        exit_code = cli.main(["--input", "/nonexistent/file.evtx"])
        assert exit_code == 1

    def test_main_returns_2_for_no_events(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(cli, "load_events", lambda args: [])
        exit_code = cli.main(["--input", "unused.evtx", "--output", str(tmp_path / "r")])
        assert exit_code == 2

    def test_main_returns_2_for_no_chains(self, monkeypatch, tmp_path) -> None:
        from tests.conftest import make_event

        monkeypatch.setattr(cli, "load_events", lambda args: [make_event(4634)])  # logoff, no rule matches
        exit_code = cli.main(["--input", "unused.evtx", "--output", str(tmp_path / "r")])
        assert exit_code == 2

    def test_main_returns_0_on_success(self, sample_xml_path: Path, tmp_path, monkeypatch) -> None:
        if not sample_xml_path.exists():
            pytest.skip("Sample scenario not generated")

        # main.py only knows how to read real .evtx via EvtxParser.parse();
        # patch load_events to reuse the XML-fixture loader for this test.
        def fake_load_events(args):
            return EvtxParser().parse_xml_events_file(sample_xml_path)

        monkeypatch.setattr(cli, "load_events", fake_load_events)
        exit_code = cli.main(
            ["--input", "unused.evtx", "--format", "json", "--output", str(tmp_path / "report")]
        )
        assert exit_code == 0
        assert (tmp_path / "report.json").exists()
