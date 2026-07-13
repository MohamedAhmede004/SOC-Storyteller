"""
tests/test_risk_engine.py

Unit tests for :mod:`risk_engine.risk_calculator`.
"""

from __future__ import annotations

import pytest

from risk_engine.risk_calculator import RiskCalculator
from tests.conftest import make_event
from utils.exceptions import RiskCalculationError
from utils.models import AttackChain, Detection, Severity


def _detection(rule_id: str, severity: Severity, offset_seconds: int = 0) -> Detection:
    events = [make_event(4624, offset_seconds=offset_seconds)]
    return Detection(rule_id=rule_id, title=rule_id, description="d", severity=severity, events=events)


class TestScoreChain:
    def test_raises_for_chain_with_no_detections(self) -> None:
        chain = AttackChain(chain_id="c1", detections=[])
        with pytest.raises(RiskCalculationError):
            RiskCalculator().score_chain(chain)

    def test_score_is_bounded_0_to_100(self) -> None:
        detections = [
            _detection(f"rule_{i}", Severity.CRITICAL, offset_seconds=i * 10) for i in range(20)
        ]
        chain = AttackChain(chain_id="c1", detections=detections)
        scored = RiskCalculator().score_chain(chain)
        assert 0.0 <= scored.risk_score <= 100.0

    def test_higher_severity_yields_higher_score(self) -> None:
        low_chain = AttackChain(chain_id="c1", detections=[_detection("r1", Severity.LOW)])
        high_chain = AttackChain(chain_id="c2", detections=[_detection("r2", Severity.CRITICAL)])
        calc = RiskCalculator()
        calc.score_chain(low_chain)
        calc.score_chain(high_chain)
        assert high_chain.risk_score > low_chain.risk_score

    def test_critical_detection_forces_critical_or_high_severity(self) -> None:
        chain = AttackChain(chain_id="c1", detections=[_detection("audit_log_cleared", Severity.CRITICAL)])
        scored = RiskCalculator().score_chain(chain)
        assert scored.risk_severity in (Severity.CRITICAL, Severity.HIGH)

    def test_multi_stage_bonus_increases_score(self) -> None:
        single_stage = AttackChain(chain_id="c1", detections=[_detection("rule_a", Severity.MEDIUM)])
        multi_stage = AttackChain(
            chain_id="c2",
            detections=[
                _detection("rule_a", Severity.MEDIUM, 0),
                _detection("rule_b", Severity.MEDIUM, 10),
                _detection("rule_c", Severity.MEDIUM, 20),
            ],
        )
        calc = RiskCalculator()
        calc.score_chain(single_stage)
        calc.score_chain(multi_stage)
        assert multi_stage.risk_score > single_stage.risk_score


class TestScoreChains:
    def test_sorted_descending_by_risk(self) -> None:
        low_chain = AttackChain(chain_id="c1", detections=[_detection("r1", Severity.LOW)])
        high_chain = AttackChain(chain_id="c2", detections=[_detection("r2", Severity.CRITICAL)])
        scored = RiskCalculator().score_chains([low_chain, high_chain])
        assert scored[0].chain_id == "c2"
        assert scored[0].risk_score >= scored[1].risk_score


class TestOverallIncidentScore:
    def test_empty_list_returns_zero(self) -> None:
        assert RiskCalculator().overall_incident_score([]) == 0.0

    def test_single_chain_close_to_its_own_score(self) -> None:
        chain = AttackChain(chain_id="c1", detections=[_detection("r1", Severity.CRITICAL)])
        calc = RiskCalculator()
        calc.score_chain(chain)
        overall = calc.overall_incident_score([chain])
        assert overall == chain.risk_score

    def test_multiple_chains_score_at_least_max_single_chain(self) -> None:
        c1 = AttackChain(chain_id="c1", detections=[_detection("r1", Severity.HIGH)])
        c2 = AttackChain(chain_id="c2", detections=[_detection("r2", Severity.MEDIUM)])
        calc = RiskCalculator()
        calc.score_chain(c1)
        calc.score_chain(c2)
        overall = calc.overall_incident_score([c1, c2])
        assert overall >= max(c1.risk_score, c2.risk_score)

    def test_bounded_at_100(self) -> None:
        chains = [
            AttackChain(chain_id=f"c{i}", detections=[_detection(f"r{i}", Severity.CRITICAL)])
            for i in range(10)
        ]
        calc = RiskCalculator()
        overall = calc.overall_incident_score(chains)
        assert overall <= 100.0
