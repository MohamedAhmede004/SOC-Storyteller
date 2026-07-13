"""
tests/test_mitre.py

Unit tests for :mod:`mitre.attack_mapping`.
"""

from __future__ import annotations

import pytest

from mitre.attack_mapping import get_technique, get_techniques, techniques_for_rule
from utils.exceptions import MitreMappingError


class TestGetTechnique:
    def test_returns_known_technique(self) -> None:
        tech = get_technique("T1110")
        assert tech.technique_id == "T1110"
        assert tech.name == "Brute Force"
        assert tech.url.endswith("/T1110/")

    def test_subtechnique_url_format(self) -> None:
        tech = get_technique("T1110.001")
        assert tech.url.endswith("/T1110/001/")

    def test_raises_for_unknown_technique(self) -> None:
        with pytest.raises(MitreMappingError):
            get_technique("T9999")


class TestGetTechniques:
    def test_resolves_multiple_known_ids(self) -> None:
        techniques = get_techniques(["T1110", "T1078"])
        assert len(techniques) == 2

    def test_skips_unknown_ids_without_raising(self) -> None:
        techniques = get_techniques(["T1110", "T9999"])
        assert len(techniques) == 1
        assert techniques[0].technique_id == "T1110"


class TestTechniquesForRule:
    def test_known_rule_returns_techniques(self) -> None:
        techniques = techniques_for_rule("brute_force_logon")
        assert len(techniques) > 0
        assert all(t.technique_id for t in techniques)

    def test_unknown_rule_returns_empty_list(self) -> None:
        assert techniques_for_rule("nonexistent_rule") == []

    def test_every_default_rule_id_has_mitre_mapping(self) -> None:
        """Guards against a new detection rule shipping without MITRE mapping."""
        from detections.rules import default_rule_set

        for rule in default_rule_set():
            techniques = techniques_for_rule(rule.rule_id)
            assert techniques, f"Rule '{rule.rule_id}' has no MITRE ATT&CK mapping"
