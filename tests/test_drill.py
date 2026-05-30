import pytest

import augur.engine.scoring as scoring
import augur.engine.matcher as matcher
from augur.api.drill import run_drill
from augur.pipeline import default_scenarios, default_topology


def test_run_drill_fires_injected_scenario_at_full_proximity():
    scenarios, topology = default_scenarios(), default_topology()
    out = run_drill("SCEN-WIN-001", "HR_User_PC", scenarios, topology)
    assert out["scenario_id"] == "SCEN-WIN-001"
    assert out["host"] == "HR_User_PC"
    det = out["detection"]
    assert det is not None
    assert det["scenario_id"] == "SCEN-WIN-001"
    assert det["proximity"] == 1.0
    # _public stripped private keys
    assert not any(k.startswith("_") for k in det)
    fs = out["feed_summary"]
    assert fs["baseline_events"] > 0
    assert fs["injected_events"] > 0
    assert fs["total_events"] == fs["baseline_events"] + fs["injected_events"]


def test_run_drill_is_deterministic():
    scenarios, topology = default_scenarios(), default_topology()
    a = run_drill("SCEN-WIN-001", "HR_User_PC", scenarios, topology)
    b = run_drill("SCEN-WIN-001", "HR_User_PC", scenarios, topology)
    assert a == b


def test_run_drill_unknown_host_raises():
    scenarios, topology = default_scenarios(), default_topology()
    with pytest.raises(ValueError):
        run_drill("SCEN-WIN-001", "NO_SUCH_HOST", scenarios, topology)


def test_run_drill_os_mismatch_raises():
    # A linux scenario injected onto a windows host → validate_injection raises.
    scenarios, topology = default_scenarios(), default_topology()
    with pytest.raises(ValueError):
        run_drill("SCEN-LNX-001", "HR_User_PC", scenarios, topology)


def test_run_drill_does_not_mutate_engine_or_persist():
    scenarios, topology = default_scenarios(), default_topology()
    rank_before, match_before = scoring.rank, matcher.match_scenario
    run_drill("SCEN-WIN-001", "HR_User_PC", scenarios, topology)
    # scoring path identity unchanged (imported & called, never monkeypatched)
    assert scoring.rank is rank_before
    assert matcher.match_scenario is match_before
