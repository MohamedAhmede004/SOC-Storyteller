"""
mitre/attack_mapping.py

MITRE ATT&CK(R) technique reference data and lookup service.

This module owns the mapping between SOC Storyteller's internal
detection-rule identifiers / Windows Event IDs and MITRE ATT&CK
techniques. Centralizing this here means:

  * Detection rules just declare *which* rule_id or event_id they map to;
    they never hard-code technique names/URLs themselves (no duplication).
  * The technique catalogue can be extended by editing a single
    dictionary in one file.

Technique data (IDs, names, tactics) is sourced from the public MITRE
ATT&CK knowledge base (https://attack.mitre.org), Enterprise matrix.
"""

from __future__ import annotations

from typing import Optional

from utils.exceptions import MitreMappingError
from utils.logger import get_logger
from utils.models import MitreTechnique

logger = get_logger(__name__)

_ATTACK_BASE_URL = "https://attack.mitre.org/techniques/"


def _url_for(technique_id: str) -> str:
    """Build the canonical MITRE ATT&CK URL for a technique ID.

    Args:
        technique_id: e.g. ``"T1110"`` or ``"T1110.001"``.

    Returns:
        The full URL to the technique's page on attack.mitre.org.
    """
    # Sub-techniques use a "/" in the URL instead of a ".", e.g.
    # T1110.001 -> .../techniques/T1110/001/
    if "." in technique_id:
        base, sub = technique_id.split(".", 1)
        return f"{_ATTACK_BASE_URL}{base}/{sub}/"
    return f"{_ATTACK_BASE_URL}{technique_id}/"


# --------------------------------------------------------------------------
# Curated technique catalogue.
#
# Keys are the canonical MITRE technique IDs. This is intentionally a
# focused subset covering every technique referenced by the detection
# rules shipped in this project -- extend freely as new detections are
# added.
# --------------------------------------------------------------------------
_TECHNIQUE_CATALOGUE: dict[str, MitreTechnique] = {
    tid: MitreTechnique(technique_id=tid, name=name, tactic=tactic, url=_url_for(tid))
    for tid, name, tactic in [
        ("T1110", "Brute Force", "Credential Access"),
        ("T1110.001", "Password Guessing", "Credential Access"),
        ("T1078", "Valid Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"),
        ("T1098", "Account Manipulation", "Persistence, Privilege Escalation"),
        ("T1136", "Create Account", "Persistence"),
        ("T1136.001", "Create Account: Local Account", "Persistence"),
        ("T1098.007", "Additional Local or Domain Groups", "Persistence, Privilege Escalation"),
        ("T1069", "Permission Groups Discovery", "Discovery"),
        ("T1053", "Scheduled Task/Job", "Execution, Persistence, Privilege Escalation"),
        ("T1053.005", "Scheduled Task", "Execution, Persistence, Privilege Escalation"),
        ("T1543", "Create or Modify System Process", "Persistence, Privilege Escalation"),
        ("T1543.003", "Windows Service", "Persistence, Privilege Escalation"),
        ("T1569", "System Services", "Execution"),
        ("T1569.002", "Service Execution", "Execution"),
        ("T1059", "Command and Scripting Interpreter", "Execution"),
        ("T1059.001", "PowerShell", "Execution"),
        ("T1059.003", "Windows Command Shell", "Execution"),
        ("T1055", "Process Injection", "Defense Evasion, Privilege Escalation"),
        ("T1134", "Access Token Manipulation", "Defense Evasion, Privilege Escalation"),
        ("T1070", "Indicator Removal", "Defense Evasion"),
        ("T1070.001", "Clear Windows Event Logs", "Defense Evasion"),
        ("T1021", "Remote Services", "Lateral Movement"),
        ("T1021.001", "Remote Desktop Protocol", "Lateral Movement"),
        ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
        ("T1550", "Use Alternate Authentication Material", "Defense Evasion, Lateral Movement"),
        ("T1550.002", "Pass the Hash", "Defense Evasion, Lateral Movement"),
        ("T1558", "Steal or Forge Kerberos Tickets", "Credential Access"),
        ("T1558.003", "Kerberoasting", "Credential Access"),
        ("T1078.003", "Valid Accounts: Local Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"),
        ("T1087", "Account Discovery", "Discovery"),
        ("T1087.001", "Local Account Discovery", "Discovery"),
        ("T1135", "Network Share Discovery", "Discovery"),
        ("T1039", "Data from Network Shared Drive", "Collection"),
        ("T1018", "Remote System Discovery", "Discovery"),
        ("T1531", "Account Access Removal", "Impact"),
        ("T1531.001", "Account Locked Out", "Impact"),
        ("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation, Defense Evasion"),
        ("T1489", "Service Stop", "Impact"),
    ]
}


def get_technique(technique_id: str) -> MitreTechnique:
    """Look up a single MITRE ATT&CK technique by ID.

    Args:
        technique_id: The technique identifier, e.g. ``"T1110"``.

    Returns:
        The matching :class:`MitreTechnique`.

    Raises:
        MitreMappingError: If the technique ID is not present in the
            catalogue.
    """
    technique = _TECHNIQUE_CATALOGUE.get(technique_id)
    if technique is None:
        logger.error("Unknown MITRE technique ID requested: %s", technique_id)
        raise MitreMappingError(f"Unknown MITRE ATT&CK technique ID: {technique_id}")
    return technique


def get_techniques(technique_ids: list[str]) -> list[MitreTechnique]:
    """Look up multiple MITRE ATT&CK techniques at once, skipping unknowns.

    Unlike :func:`get_technique`, unknown IDs are logged as warnings and
    skipped rather than raising, since this is typically called from
    detection rules that should never crash the whole pipeline over a
    single bad mapping.

    Args:
        technique_ids: List of technique IDs to resolve.

    Returns:
        List of resolved :class:`MitreTechnique` objects (may be shorter
        than the input if some IDs were unknown).
    """
    resolved: list[MitreTechnique] = []
    for tid in technique_ids:
        try:
            resolved.append(get_technique(tid))
        except MitreMappingError:
            logger.warning("Skipping unmapped MITRE technique id: %s", tid)
    return resolved


# --------------------------------------------------------------------------
# Rule-ID -> technique mapping.
#
# Detection rules reference this table by their own `rule_id` so the
# correlation/detection layer never needs to know MITRE details directly.
# --------------------------------------------------------------------------
_RULE_TO_TECHNIQUES: dict[str, list[str]] = {
    "brute_force_logon": ["T1110", "T1110.001"],
    "successful_logon_after_brute_force": ["T1078"],
    "account_created": ["T1136", "T1136.001"],
    "account_added_to_privileged_group": ["T1098", "T1098.007", "T1078"],
    "scheduled_task_persistence": ["T1053", "T1053.005"],
    "service_installation_persistence": ["T1543", "T1543.003", "T1569", "T1569.002"],
    "audit_log_cleared": ["T1070", "T1070.001"],
    "explicit_credential_logon": ["T1078", "T1550"],
    "lateral_movement_network_logon": ["T1021", "T1021.002"],
    "rdp_logon": ["T1021", "T1021.001"],
    "possible_pass_the_hash": ["T1550", "T1550.002"],
    "kerberos_preauth_failure": ["T1558"],
    "account_lockout": ["T1531", "T1531.001"],
    "suspicious_process_creation": ["T1059", "T1059.001", "T1059.003"],
    "special_privileges_assigned": ["T1134", "T1548"],
    "network_share_access": ["T1135", "T1039", "T1021.002"],
    "password_reset": ["T1098"],
}


def techniques_for_rule(rule_id: str) -> list[MitreTechnique]:
    """Resolve the MITRE ATT&CK techniques associated with a detection rule.

    Args:
        rule_id: The detection rule's machine-readable identifier, e.g.
            ``"brute_force_logon"``.

    Returns:
        A list of :class:`MitreTechnique` objects. Empty list if the rule
        has no registered mapping (logged as a warning, not an error --
        new detection rules may not have a mapping yet).
    """
    technique_ids: Optional[list[str]] = _RULE_TO_TECHNIQUES.get(rule_id)
    if not technique_ids:
        logger.warning("No MITRE ATT&CK mapping registered for rule_id=%s", rule_id)
        return []
    return get_techniques(technique_ids)
