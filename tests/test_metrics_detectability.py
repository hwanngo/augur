import pytest
from augur.pipeline import default_scenarios, default_topology
from augur.metrics.detectability import detectability


def test_detectability_structure():
    """Smoke test: structure is correct over a tiny scenario subset."""
    scenarios = default_scenarios()[:5]
    topology = default_topology()
    result = detectability(scenarios, topology)

    assert set(result.keys()) == {
        "total", "detectable", "unsynthesizable", "partial", "detectability_rate"
    }
    assert result["total"] == 5
    assert result["detectable"] + len(result["unsynthesizable"]) + len(result["partial"]) == 5
    assert isinstance(result["unsynthesizable"], list)
    assert isinstance(result["partial"], list)


def test_detectability_synth_contract_no_partial():
    """
    The synth contract: if synthesize_trace succeeds, the scenario MUST fire at 1.0.
    partial must always be empty. Tested over the full real library.
    """
    scenarios = default_scenarios()
    topology = default_topology()
    result = detectability(scenarios, topology)

    assert result["partial"] == [], (
        f"Synth contract violated: these scenarios synthesized but did not fire at 1.0: "
        f"{result['partial']}"
    )


def test_detectability_completeness():
    """detectable + unsynthesizable accounts for every scenario (no lost scenarios)."""
    scenarios = default_scenarios()
    topology = default_topology()
    result = detectability(scenarios, topology)

    assert result["detectable"] + len(result["unsynthesizable"]) == result["total"]
    assert result["total"] == len(scenarios)


def test_detectability_rate_bounds():
    scenarios = default_scenarios()
    topology = default_topology()
    result = detectability(scenarios, topology)

    assert 0.0 <= result["detectability_rate"] <= 1.0
