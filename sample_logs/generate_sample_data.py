#!/usr/bin/env python3
"""
sample_logs/generate_sample_data.py

Generates a synthetic, multi-stage attack scenario as Windows Event XML,
written to ``sample_logs/attack_scenario.xml``.

Producing a real *binary* .evtx file requires either a live Windows host
(``wevtutil epl ...``) or re-implementing Microsoft's proprietary binary
XML chunk format from scratch -- not practical or reliable to fabricate
here. Instead, this script emits the same information Windows itself
would put in each event (System + EventData fields) as plain XML,
wrapped in an ``<Events>`` root. This file is consumed by
:meth:`parser.evtx_parser.EvtxParser.parse_xml_events_file`, which feeds
it through the exact same parsing/normalization code path used for real
EVTX files -- so the rest of the pipeline (detections, correlation, risk
scoring, narrative, reports) is exercised identically to how it would be
against a real export.

To analyze a REAL .evtx file instead, just point ``main.py --input`` at
it directly; no code changes needed.

Scenario modeled (fictional, for demonstration only):
    1. Attacker brute-forces the 'jsmith' account from an external-looking
       IP against WKSTN-07.
    2. Brute force succeeds -- attacker gains a foothold as 'jsmith'.
    3. Attacker creates a new local account 'svc_update' via a suspicious
       PowerShell process.
    4. 'svc_update' is added to the local Administrators group.
    5. Attacker installs a persistence service and a scheduled task.
    6. Attacker moves laterally to SRV-DB01 using explicit credentials
       and an admin share.
    7. Attacker clears the Security event log to cover their tracks.

Run with:
    python sample_logs/generate_sample_data.py
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_OUTPUT_PATH = Path(__file__).parent / "attack_scenario.xml"

_BASE_TIME = datetime(2026, 6, 14, 2, 10, 0, tzinfo=timezone.utc)


def _fmt_time(dt: datetime) -> str:
    """Format a datetime as a Windows EVTX-style SystemTime string.

    Args:
        dt: The timestamp to format.

    Returns:
        A string like ``"2026-06-14T02:10:00.0000000Z"``.
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


def _build_event(
    event_id: int,
    record_id: int,
    timestamp: datetime,
    computer: str,
    channel: str,
    data: dict[str, str],
    provider: str = "Microsoft-Windows-Security-Auditing",
    level: str = "0",
) -> str:
    """Build a single ``<Event>`` XML string matching the Windows Event Schema.

    Args:
        event_id: The Windows Event ID.
        record_id: The EVTX record number.
        timestamp: When the event occurred.
        computer: The hostname generating the event.
        channel: The log channel (e.g. "Security", "System").
        data: EventData field name -> value mapping.
        provider: The event provider name.
        level: Raw numeric level string.

    Returns:
        A formatted ``<Event>...</Event>`` XML string.
    """
    data_xml = "\n".join(
        f'    <Data Name="{escape(k)}">{escape(v)}</Data>' for k, v in data.items()
    )
    return f"""  <Event xmlns="{_NS}">
    <System>
      <Provider Name="{escape(provider)}" />
      <EventID>{event_id}</EventID>
      <Version>1</Version>
      <Level>{level}</Level>
      <Task>0</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8020000000000000</Keywords>
      <TimeCreated SystemTime="{_fmt_time(timestamp)}" />
      <EventRecordID>{record_id}</EventRecordID>
      <Correlation />
      <Execution ProcessID="4" ThreadID="8" />
      <Channel>{escape(channel)}</Channel>
      <Computer>{escape(computer)}</Computer>
      <Security />
    </System>
    <EventData>
{data_xml}
    </EventData>
  </Event>"""


def build_scenario() -> list[str]:
    """Construct the full list of ``<Event>`` XML strings for the demo scenario.

    Returns:
        A list of XML event strings in chronological order.
    """
    events: list[str] = []
    t = _BASE_TIME
    record_id = 1000
    attacker_ip = "203.0.113.77"
    workstation = "WKSTN-07"
    db_server = "SRV-DB01"

    # --- Stage 1: Brute force against 'jsmith' (6 failed attempts) ---
    for i in range(6):
        t += timedelta(seconds=25)
        record_id += 1
        events.append(
            _build_event(
                4625,
                record_id,
                t,
                workstation,
                "Security",
                {
                    "SubjectUserSid": "S-1-0-0",
                    "SubjectUserName": "-",
                    "SubjectDomainName": "-",
                    "TargetUserName": "jsmith",
                    "TargetDomainName": "CORP",
                    "Status": "0xC000006D",
                    "FailureReason": "%%2313",
                    "LogonType": "3",
                    "IpAddress": attacker_ip,
                    "IpPort": "51422",
                },
            )
        )

    # --- Stage 2: Successful logon as 'jsmith' ---
    t += timedelta(seconds=40)
    record_id += 1
    events.append(
        _build_event(
            4624,
            record_id,
            t,
            workstation,
            "Security",
            {
                "SubjectUserSid": "S-1-0-0",
                "SubjectUserName": "-",
                "TargetUserSid": "S-1-5-21-111-222-333-1105",
                "TargetUserName": "jsmith",
                "TargetDomainName": "CORP",
                "LogonType": "3",
                "IpAddress": attacker_ip,
                "IpPort": "51430",
            },
        )
    )

    # Special privileges assigned to the new logon session.
    t += timedelta(seconds=5)
    record_id += 1
    events.append(
        _build_event(
            4672,
            record_id,
            t,
            workstation,
            "Security",
            {
                "SubjectUserSid": "S-1-5-21-111-222-333-1105",
                "SubjectUserName": "jsmith",
                "SubjectDomainName": "CORP",
                "PrivilegeList": "SeDebugPrivilege SeBackupPrivilege",
            },
        )
    )

    # --- Stage 3: Suspicious PowerShell used to create a new account ---
    t += timedelta(minutes=2)
    record_id += 1
    events.append(
        _build_event(
            4688,
            record_id,
            t,
            workstation,
            "Security",
            {
                "SubjectUserName": "jsmith",
                "SubjectDomainName": "CORP",
                "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "ParentProcessName": r"C:\Windows\explorer.exe",
                "CommandLine": (
                    "powershell.exe -NoP -W Hidden -Enc "
                    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA"
                ),
            },
        )
    )

    # --- Stage 4: New local account 'svc_update' created ---
    t += timedelta(seconds=20)
    record_id += 1
    events.append(
        _build_event(
            4720,
            record_id,
            t,
            workstation,
            "Security",
            {
                "SubjectUserName": "jsmith",
                "SubjectDomainName": "CORP",
                "TargetUserName": "svc_update",
                "TargetDomainName": "WKSTN-07",
                "TargetSid": "S-1-5-21-111-222-333-1106",
            },
        )
    )

    # --- Stage 5: 'svc_update' added to local Administrators group ---
    t += timedelta(seconds=15)
    record_id += 1
    events.append(
        _build_event(
            4732,
            record_id,
            t,
            workstation,
            "Security",
            {
                "SubjectUserName": "jsmith",
                "SubjectDomainName": "CORP",
                "MemberName": "svc_update",
                "TargetGroupName": "Administrators",
                "TargetDomainName": "Builtin",
            },
        )
    )

    # --- Stage 6: Persistence -- service installed ---
    t += timedelta(seconds=45)
    record_id += 1
    events.append(
        _build_event(
            4697,
            record_id,
            t,
            workstation,
            "Security",
            {
                "SubjectUserName": "svc_update",
                "SubjectDomainName": "WKSTN-07",
                "ServiceName": "WinUpdateHelper",
                "ServiceFileName": r"C:\Users\Public\svchost_update.exe",
            },
        )
    )

    # --- Stage 6b: Persistence -- scheduled task created ---
    t += timedelta(seconds=30)
    record_id += 1
    events.append(
        _build_event(
            4698,
            record_id,
            t,
            workstation,
            "Security",
            {
                "SubjectUserName": "svc_update",
                "SubjectDomainName": "WKSTN-07",
                "TaskName": r"\Microsoft\Windows\WinUpdateCheck",
            },
        )
    )

    # --- Stage 7: Lateral movement -- explicit credentials to SRV-DB01 ---
    t += timedelta(minutes=3)
    record_id += 1
    events.append(
        _build_event(
            4648,
            record_id,
            t,
            workstation,
            "Security",
            {
                "SubjectUserName": "jsmith",
                "SubjectDomainName": "CORP",
                "TargetUserName": "administrator",
                "TargetServerName": db_server,
                "TargetInfo": db_server,
            },
        )
    )

    # Network logon (type 3) arriving on the DB server.
    t += timedelta(seconds=8)
    record_id += 1
    events.append(
        _build_event(
            4624,
            record_id,
            t,
            db_server,
            "Security",
            {
                "SubjectUserSid": "S-1-0-0",
                "TargetUserSid": "S-1-5-21-999-888-777-500",
                "TargetUserName": "administrator",
                "TargetDomainName": "CORP",
                "LogonType": "3",
                "IpAddress": "10.10.20.15",
                "IpPort": "51555",
            },
        )
    )

    # Admin share (C$) accessed on the DB server.
    t += timedelta(seconds=12)
    record_id += 1
    events.append(
        _build_event(
            5140,
            record_id,
            t,
            db_server,
            "Security",
            {
                "SubjectUserName": "administrator",
                "SubjectDomainName": "CORP",
                "ShareName": r"\\*\C$",
                "IpAddress": "10.10.20.15",
            },
        )
    )

    # --- Stage 8: Anti-forensics -- Security log cleared on the workstation ---
    t += timedelta(minutes=1)
    record_id += 1
    events.append(
        _build_event(
            1102,
            record_id,
            t,
            workstation,
            "Security",
            {
                "SubjectUserName": "svc_update",
                "SubjectDomainName": "WKSTN-07",
            },
            provider="Microsoft-Windows-Eventlog",
        )
    )

    return events


def main() -> None:
    """Generate the scenario and write it to ``sample_logs/attack_scenario.xml``."""
    events = build_scenario()
    content = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n'
        + "\n".join(events)
        + "\n</Events>\n"
    )
    _OUTPUT_PATH.write_text(content, encoding="utf-8")
    print(f"Wrote {len(events)} synthetic events to {_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
