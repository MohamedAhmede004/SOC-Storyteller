"""
parser/evtx_parser.py

Reads Windows .evtx files and converts each record into a normalized
:class:`utils.models.Event`.

Design notes:
    * Uses the free/open-source ``python-evtx`` library to decode the
      binary EVTX container format into per-record XML strings.
    * The XML is then parsed with the standard-library
      ``xml.etree.ElementTree`` -- no extra dependency needed for that
      step.
    * Unsupported event IDs (per
      :mod:`parser.event_id_registry`) are skipped early so downstream
      modules only ever see events that are actually useful for
      storytelling. This keeps memory usage bounded on large exports.
    * :meth:`EvtxParser.parse_xml_record` is exposed as a public method
      (not just an internal helper) so tests and tooling can build
      ``Event`` objects directly from hand-crafted XML without needing a
      real binary .evtx file on disk.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from utils.exceptions import EvtxFileNotFoundError, EvtxParsingError
from utils.logger import get_logger
from utils.models import Event
from parser.event_id_registry import is_supported

logger = get_logger(__name__)

# The XML namespace Windows uses for all Event Log XML.
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Windows numeric "Level" -> human string, per the EVTX schema.
_LEVEL_NAMES: dict[str, str] = {
    "0": "LogAlways",
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information",
    "5": "Verbose",
}

# Every valid binary .evtx file begins with this 8-byte magic signature.
# python-evtx itself does not validate this and will silently report zero
# records for a non-EVTX file, which is confusing for end users -- we
# check it ourselves up front so a wrong/corrupt file fails fast with a
# clear error instead of a silent "0 events parsed".
_EVTX_MAGIC = b"ElfFile\x00"


class EvtxParser:
    """Parses .evtx files into normalized :class:`Event` objects.

    Example:
        >>> parser = EvtxParser()
        >>> events = parser.parse(Path("sample_logs/security.evtx"))
        >>> len(events) > 0
        True
    """

    def __init__(self, strict: bool = False) -> None:
        """Initialize the parser.

        Args:
            strict: If True, malformed individual records raise
                :class:`EvtxParsingError` instead of being logged and
                skipped. Defaults to False so a handful of corrupted
                records in a large export do not abort the whole run.
        """
        self.strict = strict

    @staticmethod
    def _validate_evtx_header(file_path: Path) -> None:
        """Verify a file begins with the binary EVTX magic signature.

        ``python-evtx`` does not validate this itself -- pointing it at a
        non-EVTX file (wrong extension, truncated download, accidentally
        passing an XML export) silently yields zero records rather than
        an error, which is confusing to debug. Checking the signature
        ourselves turns that into a clear, immediate failure.

        Args:
            file_path: Path to the file to check.

        Raises:
            EvtxParsingError: If the file does not start with the
                expected EVTX magic bytes.
        """
        try:
            with open(file_path, "rb") as fh:
                header = fh.read(len(_EVTX_MAGIC))
        except OSError as exc:
            raise EvtxParsingError(f"Could not read {file_path}: {exc}") from exc

        if header != _EVTX_MAGIC:
            raise EvtxParsingError(
                f"{file_path} does not look like a valid binary .evtx file "
                f"(missing EVTX magic header). If this is an XML export, use "
                "parse_xml_events_file() instead."
            )

    def parse(self, file_path: Path) -> list[Event]:
        """Parse an .evtx file into a list of normalized events.

        Unsupported event IDs (not present in
        :data:`parser.event_id_registry.SUPPORTED_EVENT_IDS`) are
        skipped and counted, but do not cause failure.

        Args:
            file_path: Path to the ``.evtx`` file.

        Returns:
            A list of :class:`Event` objects, sorted chronologically.

        Raises:
            EvtxFileNotFoundError: If ``file_path`` does not exist.
            EvtxParsingError: If the file cannot be opened/parsed as
                EVTX at all.
        """
        if not file_path.exists():
            raise EvtxFileNotFoundError(f"EVTX file not found: {file_path}")
        self._validate_evtx_header(file_path)

        # Imported lazily so unit tests that only exercise
        # parse_xml_record() don't require the binary EVTX file to exist
        # or even require successful import in restricted environments.
        try:
            import Evtx.Evtx as Evtx  # python-evtx
        except ImportError as exc:  # pragma: no cover - environment issue
            raise EvtxParsingError(
                "python-evtx is not installed. Run `pip install python-evtx`."
            ) from exc

        events: list[Event] = []
        skipped_unsupported = 0
        skipped_errors = 0

        logger.info("Parsing EVTX file: %s", file_path)
        try:
            with Evtx.Evtx(str(file_path)) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        event = self.parse_xml_record(
                            xml_str, source_file=str(file_path)
                        )
                        if event is None:
                            skipped_unsupported += 1
                            continue
                        events.append(event)
                    except EvtxParsingError:
                        skipped_errors += 1
                        if self.strict:
                            raise
                        logger.warning(
                            "Skipping malformed record %s in %s",
                            getattr(record, "record_num", lambda: "?")(),
                            file_path,
                        )
        except EvtxParsingError:
            raise
        except Exception as exc:  # noqa: BLE001 - wrap any low-level parser failure
            raise EvtxParsingError(f"Failed to parse EVTX file {file_path}: {exc}") from exc

        events.sort(key=lambda e: e.timestamp)
        logger.info(
            "Parsed %d events from %s (skipped %d unsupported, %d malformed)",
            len(events),
            file_path.name,
            skipped_unsupported,
            skipped_errors,
        )
        return events

    def parse_directory(self, directory: Path, pattern: str = "*.evtx") -> list[Event]:
        """Parse every matching .evtx file in a directory.

        Args:
            directory: Directory to search.
            pattern: Glob pattern for matching files. Defaults to
                ``"*.evtx"``.

        Returns:
            A single chronologically sorted list combining events from
            every matched file.

        Raises:
            EvtxFileNotFoundError: If ``directory`` does not exist.
        """
        if not directory.exists():
            raise EvtxFileNotFoundError(f"Directory not found: {directory}")

        all_events: list[Event] = []
        matched_files = sorted(directory.glob(pattern))
        logger.info("Found %d EVTX file(s) in %s", len(matched_files), directory)

        for file_path in matched_files:
            all_events.extend(self.parse(file_path))

        all_events.sort(key=lambda e: e.timestamp)
        return all_events

    def parse_xml_record(self, xml_str: str, source_file: str = "") -> Optional[Event]:
        """Parse a single raw Windows Event XML string into an ``Event``.

        This is the core, reusable parsing logic. It is used both
        internally by :meth:`parse` (fed by python-evtx) and directly by
        tests / tooling that want to construct events from hand-written
        XML fixtures without a real binary .evtx file.

        Args:
            xml_str: The raw ``<Event>...</Event>`` XML string.
            source_file: Optional path/name of the originating file, for
                traceability.

        Returns:
            A normalized :class:`Event`, or ``None`` if the event ID is
            not in the supported registry (i.e. intentionally skipped).

        Raises:
            EvtxParsingError: If the XML is malformed or missing
                required fields (EventID, TimeCreated, EventRecordID).
        """
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as exc:
            raise EvtxParsingError(f"Malformed event XML: {exc}") from exc

        system = root.find("e:System", _NS)
        if system is None:
            raise EvtxParsingError("Event XML missing <System> element")

        event_id = self._require_int(system, "e:EventID", xml_str)
        if not is_supported(event_id):
            return None

        record_id = self._require_int(system, "e:EventRecordID", xml_str)
        timestamp = self._parse_timestamp(system)
        channel = self._text(system, "e:Channel", default="Security")
        computer = self._text(system, "e:Computer", default="UNKNOWN")
        provider_elem = system.find("e:Provider", _NS)
        provider = (
            provider_elem.get("Name", "UNKNOWN") if provider_elem is not None else "UNKNOWN"
        )
        level_code = self._text(system, "e:Level", default="4")
        level = _LEVEL_NAMES.get(level_code, level_code)

        event_data = self._extract_event_data(root)

        return Event(
            event_id=event_id,
            record_id=record_id,
            timestamp=timestamp,
            channel=channel,
            computer=computer,
            provider=provider,
            level=level,
            event_data=event_data,
            raw_xml=xml_str,
            source_file=source_file,
        )

    # ----------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------

    @staticmethod
    def _text(element: ET.Element, path: str, default: str = "") -> str:
        """Safely extract text content from a child element."""
        child = element.find(path, _NS)
        if child is None or child.text is None:
            return default
        return child.text.strip()

    @staticmethod
    def _require_int(element: ET.Element, path: str, xml_str: str) -> int:
        """Extract and parse a required integer field, raising if absent/invalid."""
        child = element.find(path, _NS)
        if child is None or child.text is None:
            raise EvtxParsingError(f"Missing required field {path} in event XML")
        try:
            return int(child.text.strip())
        except ValueError as exc:
            raise EvtxParsingError(f"Non-integer value for {path}: {child.text!r}") from exc

    @staticmethod
    def _parse_timestamp(system: ET.Element) -> datetime:
        """Extract and parse the TimeCreated SystemTime attribute as UTC."""
        time_elem = system.find("e:TimeCreated", _NS)
        if time_elem is None or "SystemTime" not in time_elem.attrib:
            raise EvtxParsingError("Missing TimeCreated/SystemTime in event XML")
        raw_time = time_elem.attrib["SystemTime"]
        # Windows uses e.g. "2024-01-15T13:45:30.1234567Z". Python's
        # fromisoformat (3.11+) handles "Z" and truncated microseconds
        # inconsistently across versions, so normalize manually.
        raw_time = raw_time.rstrip("Z")
        if "." in raw_time:
            main, frac = raw_time.split(".", 1)
            frac = (frac + "000000")[:6]  # pad/truncate to microseconds
            raw_time = f"{main}.{frac}"
            fmt = "%Y-%m-%dT%H:%M:%S.%f"
        else:
            fmt = "%Y-%m-%dT%H:%M:%S"
        try:
            dt = datetime.strptime(raw_time, fmt)
        except ValueError as exc:
            raise EvtxParsingError(f"Unparseable timestamp: {raw_time!r}") from exc
        return dt.replace(tzinfo=timezone.utc)

    @staticmethod
    def _extract_event_data(root: ET.Element) -> dict[str, str]:
        """Extract all <Data Name="..."> fields from EventData or UserData."""
        data: dict[str, str] = {}

        event_data_elem = root.find("e:EventData", _NS)
        if event_data_elem is not None:
            for data_elem in event_data_elem.findall("e:Data", _NS):
                name = data_elem.get("Name")
                text = (data_elem.text or "").strip()
                if name:
                    data[name] = text

        # Some events (e.g. scheduled task creation) use <UserData> with
        # nested, event-specific elements instead of <EventData><Data>.
        user_data_elem = root.find("e:UserData", _NS)
        if user_data_elem is not None:
            for child in user_data_elem.iter():
                tag = child.tag.split("}")[-1]  # strip namespace
                if tag in ("UserData",) or list(child):
                    continue  # skip containers, only leaf values
                if child.text and child.text.strip():
                    data[tag] = child.text.strip()

        return data

    def iter_parse(self, file_path: Path) -> Iterator[Event]:
        """Memory-friendly generator variant of :meth:`parse`.

        Yields events one at a time instead of building a full list in
        memory, useful for very large EVTX exports.

        Args:
            file_path: Path to the ``.evtx`` file.

        Yields:
            Normalized :class:`Event` objects in file order (not
            necessarily globally chronological if the source file itself
            is out of order).

        Raises:
            EvtxFileNotFoundError: If ``file_path`` does not exist.
            EvtxParsingError: If the file cannot be opened as EVTX.
        """
        if not file_path.exists():
            raise EvtxFileNotFoundError(f"EVTX file not found: {file_path}")
        self._validate_evtx_header(file_path)

        try:
            import Evtx.Evtx as Evtx
        except ImportError as exc:  # pragma: no cover
            raise EvtxParsingError(
                "python-evtx is not installed. Run `pip install python-evtx`."
            ) from exc

        try:
            with Evtx.Evtx(str(file_path)) as log:
                for record in log.records():
                    try:
                        event = self.parse_xml_record(
                            record.xml(), source_file=str(file_path)
                        )
                    except EvtxParsingError:
                        if self.strict:
                            raise
                        continue
                    if event is not None:
                        yield event
        except EvtxParsingError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise EvtxParsingError(f"Failed to parse EVTX file {file_path}: {exc}") from exc

    def parse_xml_events_file(self, file_path: Path) -> list[Event]:
        """Parse a file containing an ``<Events>`` wrapper of raw ``<Event>`` XML.

        This is NOT the binary .evtx format -- it is a convenience format
        used for the bundled synthetic samples in ``sample_logs/`` and
        for unit tests, so that the full pipeline can be exercised and
        demonstrated without requiring a real Windows host to export a
        binary .evtx file. Each ``<Event>`` child is parsed with
        :meth:`parse_xml_record`, exactly as if it had come from a real
        EVTX file.

        Args:
            file_path: Path to an XML file whose root element is
                ``<Events>`` containing one or more ``<Event>`` children
                (each using the standard Windows Event Schema namespace).

        Returns:
            A chronologically sorted list of normalized :class:`Event`
            objects.

        Raises:
            EvtxFileNotFoundError: If ``file_path`` does not exist.
            EvtxParsingError: If the file is not well-formed XML.
        """
        if not file_path.exists():
            raise EvtxFileNotFoundError(f"Sample XML file not found: {file_path}")

        try:
            tree = ET.parse(str(file_path))
        except ET.ParseError as exc:
            raise EvtxParsingError(f"Malformed sample XML file {file_path}: {exc}") from exc

        root = tree.getroot()
        events: list[Event] = []
        skipped = 0
        for event_elem in root.findall("e:Event", _NS):
            xml_str = ET.tostring(event_elem, encoding="unicode")
            event = self.parse_xml_record(xml_str, source_file=str(file_path))
            if event is None:
                skipped += 1
                continue
            events.append(event)

        events.sort(key=lambda e: e.timestamp)
        logger.info(
            "Parsed %d events from sample XML file %s (skipped %d unsupported)",
            len(events),
            file_path.name,
            skipped,
        )
        return events
