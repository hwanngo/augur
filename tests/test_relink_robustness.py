import pytest

import augur.engine.matcher as matcher_mod
from augur.metrics.robustness import (
    MUTATION_KINDS, detection_robustness, evaluate_mutation,
)
from augur.pipeline import default_scenarios, default_topology


def _scenario(scenario_id: str):
    for s in default_scenarios():
        if s.scenario_id == scenario_id:
            return s
    raise AssertionError(f"scenario {scenario_id} not found")


# ── Green baseline: relink rejects on every multi-step library scenario ───────
def test_relink_green_baseline_whole_library():
    """relink_host(last) on every scenario degrades to round((n-1)/n, 4) and is
    detected_correctly. No row may be no_distinct_host on the real 5-zone topology."""
    scenarios = default_scenarios()
    topo = default_topology()
    failures = []
    for sc in scenarios:
        n = sc.step_count
        assert n >= 2, "library invariant: all scenarios are multi-step"
        row = evaluate_mutation(sc, topo, "relink_host", n)
        # the real topology always has a distinct second eligible host
        assert row["status"] != "no_distinct_host", sc.scenario_id
        if not (row["observed"] == round((n - 1) / n, 4) and row["pass"]
                and row["status"] == "detected_correctly"):
            failures.append((sc.scenario_id, row))
    assert not failures, failures


def test_relink_included_in_full_robustness_report_green():
    report = detection_robustness(default_scenarios(), default_topology())
    relink = [r for r in report["rows"] if r["kind"] == "relink_host"]
    assert relink, "relink_host rows must be present"
    assert all(r["status"] == "detected_correctly" for r in relink)
    assert report["aggregate"]["failed"] == 0


# ── Anti-circular sentinel: the assertion binds to the LINK gate, not the synth ─
def test_sentinel_loosened_link_gate_would_wrongly_fire(monkeypatch):
    """If ``_link_ok`` were monkeypatched to always-True, the relinked trace would
    (WRONGLY) fire at 1.0 instead of truncating to (n-1)/n. This proves the relink
    mutation actually exercises the LINK gate (not the synth's own placement). The
    shipped engine is NOT altered (monkeypatch is scoped to this test).

    Mirrors test_tripwire_loosened_temporal_gate_would_wrongly_fire in
    tests/test_robustness_validation.py."""
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    n = sc.step_count
    assert n >= 2

    # Sanity: with the real link gate, relink truncates.
    real_row = evaluate_mutation(sc, topo, "relink_host", n)
    assert real_row["observed"] == round((n - 1) / n, 4)
    assert real_row["pass"] is True

    # Disable the link gate; the relinked trace now wrongly chains across hosts and
    # fires at 1.0. _link_ok's real signature is (prev, cand, scope) -> bool.
    monkeypatch.setattr(matcher_mod, "_link_ok", lambda prev, cand, scope: True)
    loosened_row = evaluate_mutation(sc, topo, "relink_host", n)
    assert loosened_row["observed"] == 1.0
    assert loosened_row["pass"] is False  # the validator catches the regression
    assert loosened_row["status"] == "unexpected_fire"


def test_relink_kinds_constant():
    assert "relink_host" in MUTATION_KINDS
