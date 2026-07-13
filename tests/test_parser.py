"""
tests/test_parser.py

Unit tests for :mod:`parser.evtx_parser` and :mod:`parser.event_id_registry`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from parser.event_id_registry import describe, is_supported, logon_type_name
from parser.evtx_parser import EvtxParser
from utils.exceptions import EvtxFileNotFoundError, EvtxParsingError

_SAMPLE_EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4624</EventID>
    <Version>1</Version>
    <Level>0</Level>
    <Task>0</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-01-01T08:00:00.1234567Z" />
    <EventRecordID>42</EventRecordID>
    <Correlation />
    <Execution ProcessID="4" ThreadID="8" />
    <Channel>Security</Channel>
    <Computer>HOST-A</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">10.0.0.5</Data>
  </EventData>
</Event>"""


class TestEventIdRegistry:
    """Tests for parser/event_id_registry.py."""

    def test_is_supported_known_id(self) -> None:
        assert is_supported(4624) is True

    def test_is_supported_unknown_id(self) -> None:
        assert is_supported(9999) is False

    def test_describe_known_id(self) -> None:
        assert "logged on" in describe(4624)

    def test_describe_unknown_id(self) -> None:
        assert "Unrecognized" in describe(9999)

    def test_logon_type_name_known(self) -> None:
        assert logon_type_name("10") == "RemoteInteractive (RDP)"

    def test_logon_type_name_unknown(self) -> None:
        assert logon_type_name("999") == "Unknown"


class TestEvtxParserXmlRecord:
    """Tests for EvtxParser.parse_xml_record (the core XML->Event logic)."""

    def test_parses_supported_event(self) -> None:
        parser = EvtxParser()
        event = parser.parse_xml_record(_SAMPLE_EVENT_XML, source_file="test.evtx")
        assert event is not None
        assert event.event_id == 4624
        assert event.record_id == 42
        assert event.computer == "HOST-A"
        assert event.get("TargetUserName") == "alice"
        assert event.get("LogonType") == "3"
        assert event.source_ip == "10.0.0.5"
        assert event.source_file == "test.evtx"

    def test_skips_unsupported_event_id(self) -> None:
        xml = _SAMPLE_EVENT_XML.replace("<EventID>4624</EventID>", "<EventID>9999</EventID>")
        parser = EvtxParser()
        event = parser.parse_xml_record(xml)
        assert event is None

    def test_raises_on_malformed_xml(self) -> None:
        parser = EvtxParser()
        with pytest.raises(EvtxParsingError):
            parser.parse_xml_record("<Event><System>not closed")

    def test_raises_on_missing_system_element(self) -> None:
        parser = EvtxParser()
        with pytest.raises(EvtxParsingError):
            parser.parse_xml_record(
                '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"></Event>'
            )

    def test_timestamp_is_utc_and_correct(self) -> None:
        parser = EvtxParser()
        event = parser.parse_xml_record(_SAMPLE_EVENT_XML)
        assert event.timestamp.year == 2026
        assert event.timestamp.hour == 8
        assert event.timestamp.tzinfo is not None

    def test_level_mapping(self) -> None:
        parser = EvtxParser()
        event = parser.parse_xml_record(_SAMPLE_EVENT_XML)
        assert event.level == "LogAlways"  # Level 0


class TestEvtxParserFileHandling:
    """Tests for file-based parsing entry points."""

    def test_parse_raises_for_missing_file(self) -> None:
        parser = EvtxParser()
        with pytest.raises(EvtxFileNotFoundError):
            parser.parse(Path("/nonexistent/path/file.evtx"))

    def test_parse_directory_raises_for_missing_dir(self) -> None:
        parser = EvtxParser()
        with pytest.raises(EvtxFileNotFoundError):
            parser.parse_directory(Path("/nonexistent/directory"))

    def test_parse_xml_events_file_raises_for_missing_file(self) -> None:
        parser = EvtxParser()
        with pytest.raises(EvtxFileNotFoundError):
            parser.parse_xml_events_file(Path("/nonexistent/sample.xml"))

    def test_parse_rejects_file_missing_evtx_magic_header(self, tmp_path) -> None:
        fake_file = tmp_path / "not_really.evtx"
        fake_file.write_text("<Events><Event/></Events>")
        parser = EvtxParser()
        with pytest.raises(EvtxParsingError, match="magic header"):
            parser.parse(fake_file)

    def test_iter_parse_rejects_file_missing_evtx_magic_header(self, tmp_path) -> None:
        fake_file = tmp_path / "not_really.evtx"
        fake_file.write_bytes(b"totally not evtx")
        parser = EvtxParser()
        with pytest.raises(EvtxParsingError, match="magic header"):
            list(parser.iter_parse(fake_file))

    def test_parse_xml_events_file_loads_sample_scenario(self, sample_xml_path: Path) -> None:
        if not sample_xml_path.exists():
            pytest.skip("Sample scenario not generated; run sample_logs/generate_sample_data.py")
        parser = EvtxParser()
        events = parser.parse_xml_events_file(sample_xml_path)
        assert len(events) > 0
        # Events must be chronologically sorted.
        timestamps = [e.timestamp for e in events]
        assert timestamps == sorted(timestamps)
        # Every event must be a supported event ID.
        for event in events:
            assert is_supported(event.event_id)


class _FakeRecord:
    """Stand-in for python-evtx's Record object, exposing only what EvtxParser uses."""

    def __init__(self, xml_str: str, record_num: int = 1) -> None:
        self._xml = xml_str
        self._record_num = record_num

    def xml(self) -> str:
        return self._xml

    def record_num(self) -> int:
        return self._record_num


class _FakeEvtxLog:
    """Stand-in for python-evtx's ``Evtx.Evtx`` context manager."""

    def __init__(self, path: str) -> None:
        self._path = path

    def __enter__(self) -> "_FakeEvtxLog":
        return self

    def __exit__(self, *exc_info) -> None:
        return None

    def records(self):
        yield _FakeRecord(_SAMPLE_EVENT_XML, record_num=1)
        # A malformed record to exercise the skip/strict-mode paths.
        yield _FakeRecord("<Event><System>not closed", record_num=2)


def _install_fake_evtx_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install a fake ``Evtx.Evtx`` module into sys.modules for this test.

    Avoids requiring a real binary .evtx file (impractical to fabricate
    without a Windows host) while still exercising the real
    parse()/parse_directory()/iter_parse() code paths end-to-end.
    """
    import sys
    import types

    fake_module = types.ModuleType("Evtx.Evtx")
    fake_module.Evtx = _FakeEvtxLog  # type: ignore[attr-defined]
    fake_package = types.ModuleType("Evtx")
    fake_package.Evtx = fake_module  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "Evtx", fake_package)
    monkeypatch.setitem(sys.modules, "Evtx.Evtx", fake_module)


class TestEvtxParserWithMockedEvtxLibrary:
    """Exercises the real .evtx-reading code paths using a fake python-evtx backend."""

    def test_parse_returns_events_and_skips_malformed(self, tmp_path, monkeypatch) -> None:
        _install_fake_evtx_module(monkeypatch)
        fake_file = tmp_path / "fake.evtx"
        fake_file.write_bytes(b"ElfFile\x00" + b"padding" * 8)

        parser = EvtxParser(strict=False)
        events = parser.parse(fake_file)
        assert len(events) == 1
        assert events[0].event_id == 4624
        assert events[0].source_file == str(fake_file)

    def test_parse_strict_mode_raises_on_malformed_record(self, tmp_path, monkeypatch) -> None:
        _install_fake_evtx_module(monkeypatch)
        fake_file = tmp_path / "fake.evtx"
        fake_file.write_bytes(b"ElfFile\x00" + b"padding" * 8)

        parser = EvtxParser(strict=True)
        with pytest.raises(EvtxParsingError):
            parser.parse(fake_file)

    def test_parse_directory_combines_multiple_files(self, tmp_path, monkeypatch) -> None:
        _install_fake_evtx_module(monkeypatch)
        (tmp_path / "a.evtx").write_bytes(b"ElfFile\x00" + b"padding" * 8)
        (tmp_path / "b.evtx").write_bytes(b"ElfFile\x00" + b"padding" * 8)

        parser = EvtxParser()
        events = parser.parse_directory(tmp_path)
        assert len(events) == 2  # one supported event per fake file

    def test_iter_parse_yields_events_lazily(self, tmp_path, monkeypatch) -> None:
        _install_fake_evtx_module(monkeypatch)
        fake_file = tmp_path / "fake.evtx"
        fake_file.write_bytes(b"ElfFile\x00" + b"padding" * 8)

        parser = EvtxParser()
        events = list(parser.iter_parse(fake_file))
        assert len(events) == 1
        assert events[0].event_id == 4624

    def test_iter_parse_raises_for_missing_file(self) -> None:
        parser = EvtxParser()
        with pytest.raises(EvtxFileNotFoundError):
            list(parser.iter_parse(Path("/nonexistent/file.evtx")))
