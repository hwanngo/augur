"""is_synthesizable(scenario, topology) — pure predicate wrapping synthesize_trace(...) is not None.
True for a default synthetic scenario; False for a non-synthesizable real (SCEN-REAL-WIN-*) scenario."""
from augur.simulator.inject import is_synthesizable
from augur.pipeline import default_scenarios, default_topology
from augur.scenarios.loader import load_scenarios


def _by_id(scenarios, scenario_id):
    return next(s for s in scenarios if s.scenario_id == scenario_id)


def test_is_synthesizable_true_for_synthetic_scenario():
    scenarios, topology = default_scenarios(), default_topology()
    assert is_synthesizable(_by_id(scenarios, "SCEN-WIN-001"), topology) is True


def test_is_synthesizable_false_for_non_synth_real_scenario():
    topology = default_topology()
    real = load_scenarios("scenarios_real")
    # Verified non-synthesizable: render_injection would raise "not auto-synthesizable".
    scen = _by_id(real, "SCEN-REAL-WIN-T1548-002-001")
    assert is_synthesizable(scen, topology) is False


def test_is_synthesizable_true_for_synth_real_scenario():
    topology = default_topology()
    real = load_scenarios("scenarios_real")
    # Verified synthesizable real scenario — the predicate is driven by synth capability, not the id prefix.
    scen = _by_id(real, "SCEN-REAL-WIN-T1003-001")
    assert is_synthesizable(scen, topology) is True


def test_is_synthesizable_is_pure_and_deterministic():
    topology = default_topology()
    scen = next(s for s in default_scenarios() if s.scenario_id == "SCEN-WIN-001")
    assert is_synthesizable(scen, topology) == is_synthesizable(scen, topology)
