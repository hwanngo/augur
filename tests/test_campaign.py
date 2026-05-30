"""TDD: Purple-Team Campaign scorecard (infra-free, deterministic, read-only)."""
import pytest
from augur.pipeline import default_scenarios, default_topology
from augur.api.campaign import build_campaign_scorecard, CAMPAIGN_MAX_SCENARIOS, HONESTY_NOTE


def _scens():
    return default_scenarios()


def _topo():
    return default_topology()


def test_canonical_anchor_detected_at_1():
    out = build_campaign_scorecard(_scens(), _topo(), scenario_ids=["SCEN-WIN-001"], min_proximity=1.0)
    assert out["definition"]["selector"] == "scenario_ids"
    assert len(out["rows"]) == 1
    r = out["rows"][0]
    assert r["scenario_id"] == "SCEN-WIN-001"
    assert r["status"] == "detected" and r["detected"] is True
    assert r["proximity"] == 1.0 and r["matched_steps"] == r["total_steps"]
    assert r["host"] and r["tactic"].startswith("TA") and r["technique"]
    assert out["aggregate"]["runnable"] == 1 and out["aggregate"]["detected"] == 1
    assert out["aggregate"]["pct_detected"] == 1.0
    assert out["honesty"] == HONESTY_NOTE


def test_determinism_recompute_identical():
    a = build_campaign_scorecard(_scens(), _topo(), tactic=None, min_proximity=1.0)
    b = build_campaign_scorecard(_scens(), _topo(), tactic=None, min_proximity=1.0)
    assert a == b


def test_unknown_scenario_id_raises():
    with pytest.raises(ValueError):
        build_campaign_scorecard(_scens(), _topo(), scenario_ids=["NOPE-999"])


def test_over_cap_raises():
    with pytest.raises(ValueError):
        build_campaign_scorecard(_scens(), _topo(), cap=1)


def test_threshold_flip_partial_to_missed():
    full = build_campaign_scorecard(_scens(), _topo(), min_proximity=1.0)
    relaxed = build_campaign_scorecard(_scens(), _topo(), min_proximity=0.0)
    assert relaxed["aggregate"]["detected"] >= full["aggregate"]["detected"]
    assert relaxed["aggregate"]["missed"] == 0


def test_rows_sorted_by_scenario_id():
    out = build_campaign_scorecard(_scens(), _topo(), min_proximity=1.0)
    ids = [r["scenario_id"] for r in out["rows"]]
    assert ids == sorted(ids)


def test_no_eligible_host_excluded_from_runnable():
    topo = _topo()
    topo.assets = []
    out = build_campaign_scorecard(_scens(), topo, scenario_ids=["SCEN-WIN-001"], min_proximity=1.0)
    r = out["rows"][0]
    assert r["status"] == "no_eligible_host" and r["host"] is None and r["detected"] is False
    assert out["aggregate"]["runnable"] == 0 and out["aggregate"]["pct_detected"] == 0.0
    assert out["aggregate"]["no_eligible_host_scenarios"] == ["SCEN-WIN-001"]

# Heavy full-corpus engine sweeps — skipped on per-push CI (-m 'not slow'); run weekly.
pytestmark = pytest.mark.slow
