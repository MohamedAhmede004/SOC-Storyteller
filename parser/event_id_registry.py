"""
parser/event_id_registry.py

Registry of the Windows Event IDs that SOC Storyteller understands.

This module is the single source of truth for "which event IDs matter
for security storytelling" and a short human-readable description of
each. The parser uses this registry to decide whether to keep or skip a
record (unsupported/noise event IDs are dropped early to keep memory
and processing costs down on large EVTX exports), and detection rules
use it for self-documentation.

Extending support for a new event ID is a one-line addition here --
no other module needs to change unless a *new* detection rule should
also consume it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EventIdInfo:
    """Metadata about a single supported Windows Event ID.

    Attributes:
        event_id: The numeric Windows Event ID.
        channel: The expected log channel (e.g. "Security", "System").
        name: Short human-readable name, e.g. "An account was logged on".
        category: Broad category used for grouping/reporting, e.g.
            "Authentication", "Account Management", "Process Execution".
    """

    event_id: int
    channel: str
    name: str
    category: str


# --------------------------------------------------------------------------
# Supported Event ID catalogue.
#
# Sourced from the Microsoft Security Auditing documentation. This list
# focuses on event IDs that carry meaningful signal for attack-chain
# storytelling (authentication, account management, privilege use,
# process creation, persistence mechanisms, and log tampering).
# --------------------------------------------------------------------------
SUPPORTED_EVENT_IDS: dict[int, EventIdInfo] = {
    4624: EventIdInfo(4624, "Security", "An account was successfully logged on", "Authentication"),
    4625: EventIdInfo(4625, "Security", "An account failed to log on", "Authentication"),
    4634: EventIdInfo(4634, "Security", "An account was logged off", "Authentication"),
    4647: EventIdInfo(4647, "Security", "User initiated logoff", "Authentication"),
    4648: EventIdInfo(4648, "Security", "A logon was attempted using explicit credentials", "Authentication"),
    4672: EventIdInfo(4672, "Security", "Special privileges assigned to new logon", "Privilege Use"),
    4688: EventIdInfo(4688, "Security", "A new process has been created", "Process Execution"),
    4689: EventIdInfo(4689, "Security", "A process has exited", "Process Execution"),
    4697: EventIdInfo(4697, "Security", "A service was installed in the system", "Persistence"),
    4698: EventIdInfo(4698, "Security", "A scheduled task was created", "Persistence"),
    4699: EventIdInfo(4699, "Security", "A scheduled task was deleted", "Persistence"),
    4700: EventIdInfo(4700, "Security", "A scheduled task was enabled", "Persistence"),
    4701: EventIdInfo(4701, "Security", "A scheduled task was disabled", "Persistence"),
    4702: EventIdInfo(4702, "Security", "A scheduled task was updated", "Persistence"),
    4720: EventIdInfo(4720, "Security", "A user account was created", "Account Management"),
    4722: EventIdInfo(4722, "Security", "A user account was enabled", "Account Management"),
    4723: EventIdInfo(4723, "Security", "An attempt was made to change an account's password", "Account Management"),
    4724: EventIdInfo(4724, "Security", "An attempt was made to reset an account's password", "Account Management"),
    4725: EventIdInfo(4725, "Security", "A user account was disabled", "Account Management"),
    4726: EventIdInfo(4726, "Security", "A user account was deleted", "Account Management"),
    4728: EventIdInfo(4728, "Security", "A member was added to a security-enabled global group", "Account Management"),
    4732: EventIdInfo(4732, "Security", "A member was added to a security-enabled local group", "Account Management"),
    4738: EventIdInfo(4738, "Security", "A user account was changed", "Account Management"),
    4740: EventIdInfo(4740, "Security", "A user account was locked out", "Account Management"),
    4756: EventIdInfo(4756, "Security", "A member was added to a security-enabled universal group", "Account Management"),
    4767: EventIdInfo(4767, "Security", "A user account was unlocked", "Account Management"),
    4771: EventIdInfo(4771, "Security", "Kerberos pre-authentication failed", "Authentication"),
    4776: EventIdInfo(4776, "Security", "The domain controller attempted to validate credentials", "Authentication"),
    5140: EventIdInfo(5140, "Security", "A network share object was accessed", "Object Access"),
    5145: EventIdInfo(5145, "Security", "A network share object was checked for access permissions", "Object Access"),
    1102: EventIdInfo(1102, "Security", "The audit log was cleared", "Log Tampering"),
    7045: EventIdInfo(7045, "System", "A service was installed in the system", "Persistence"),
}

# Logon Type codes used in 4624/4625/4648, per Microsoft documentation.
LOGON_TYPES: dict[str, str] = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}


def is_supported(event_id: int) -> bool:
    """Check whether an event ID is understood by the parser/detections.

    Args:
        event_id: The numeric Windows Event ID.

    Returns:
        True if the event ID is present in :data:`SUPPORTED_EVENT_IDS`.
    """
    return event_id in SUPPORTED_EVENT_IDS


def describe(event_id: int) -> str:
    """Return a short human-readable name for an event ID.

    Args:
        event_id: The numeric Windows Event ID.

    Returns:
        The event's human-readable name, or a generic fallback string if
        the event ID is not registered.
    """
    info = SUPPORTED_EVENT_IDS.get(event_id)
    return info.name if info else f"Unrecognized Event ID {event_id}"


def logon_type_name(code: str) -> str:
    """Translate a numeric LogonType field value into its readable name.

    Args:
        code: The raw LogonType string from EventData (e.g. ``"3"``).

    Returns:
        The human-readable logon type name, or ``"Unknown"`` if the code
        is not recognized.
    """
    return LOGON_TYPES.get(str(code).strip(), "Unknown")
