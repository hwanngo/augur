import pytest
from augur.pipeline import default_scenarios
from augur.metrics.coverage import TACTIC_NAMES, mitre_coverage


def test_tactic_names_has_14_entries():
    assert len(TACTIC_NAMES) == 14
    assert TACTIC_NAMES["TA0001"] == "Initial Access"
    assert TACTIC_NAMES["TA0009"] == "Collection"
    assert TACTIC_NAMES["TA0042"] == "Resource Development"
    assert TACTIC_NAMES["TA0043"] == "Reconnaissance"


def test_mitre_coverage_real_library():
    scenarios = default_scenarios()
    cov = mitre_coverage(scenarios)

    # the v2 library: 40 scenarios spanning all 14 ATT&CK tactics
    assert cov["scenario_count"] == 40
    assert len(cov["tactics_covered"]) == 14
    assert cov["tactics_missing"] == []
    # coverage pct
    assert abs(cov["tactic_coverage_pct"] - 1.0) < 1e-6
    # sorted lists
    assert cov["tactics_covered"] == sorted(cov["tactics_covered"])
    assert cov["tactics_missing"] == sorted(cov["tactics_missing"])
    assert cov["techniques"] == sorted(cov["techniques"])
    # per_tactic sums to at most scenario_count (scenarios can have multiple tactics)
    assert sum(cov["per_tactic"].values()) >= cov["scenario_count"]


def test_mitre_coverage_empty():
    cov = mitre_coverage([])
    assert cov["scenario_count"] == 0
    assert cov["tactics_covered"] == []
    assert cov["techniques"] == []
    assert cov["tactic_coverage_pct"] == 0.0
    assert set(cov["tactics_missing"]) == set(TACTIC_NAMES.keys())
