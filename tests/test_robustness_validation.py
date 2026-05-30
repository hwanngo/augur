import ast
from pathlib import Path

import pytest

from augur.generative.synth import synthesize_trace
from augur.metrics.mutations import drop_step, stretch_temporal, relocate_zone
from augur.pipeline import default_scenarios, default_topology


def _scenario(scenario_id: str):
    for s in default_scenarios():
        if s.scenario_id == scenario_id:
            return s
    raise AssertionError(f"scenario {scenario_id} not found")


# ── drop_step ────────────────────────────────────────────────────────────────
def test_drop_step_removes_exactly_step_k_events():
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    trace = synthesize_trace(sc, topo)
    assert trace is not None
    k = sc.step_count
    guid = f"syn-p{k}"
    before = [e for e in trace if e.get("process_guid") == guid]
    assert before, "synth should tag step-k events with process_guid syn-p{k}"

    mutated = drop_step(trace, sc, k)

    # exactly the step-k events are gone
    assert all(e.get("process_guid") != guid for e in mutated)
    # everything else preserved, in order
    expected_rest = [e for e in trace if e.get("process_guid") != guid]
    assert mutated == expected_rest
    # original is untouched (pure)
    assert any(e.get("process_guid") == guid for e in trace)


def test_drop_step_rejects_out_of_range():
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    trace = synthesize_trace(sc, topo)
    with pytest.raises(ValueError):
        drop_step(trace, sc, 0)
    with pytest.raises(ValueError):
        drop_step(trace, sc, sc.step_count + 1)


# ── stretch_temporal ─────────────────────────────────────────────────────────
def test_stretch_temporal_pushes_step_k_past_gate():
    from datetime import datetime

    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    trace = synthesize_trace(sc, topo)
    k = sc.step_count
    assert k >= 2
    step = sc.attack_sequence_flow.steps[k - 1]
    max_delta = step.temporal_link.max_time_delta_seconds

    mutated = stretch_temporal(trace, sc, k)

    def ts_of(events, gk):
        evs = [e for e in events if e.get("process_guid") == f"syn-p{gk}"]
        assert evs
        return datetime.fromisoformat(evs[0]["timestamp"])

    prev_ts = ts_of(mutated, k - 1)
    k_ts = ts_of(mutated, k)
    delta = (k_ts - prev_ts).total_seconds()
    assert delta == max_delta + 1  # overshoot the gate by exactly 1s

    # step k-1 is unchanged vs the original
    assert ts_of(trace, k - 1) == ts_of(mutated, k - 1)


def test_stretch_temporal_rejects_step_1():
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    trace = synthesize_trace(sc, topo)
    with pytest.raises(ValueError):
        stretch_temporal(trace, sc, 1)


# ── relocate_zone ────────────────────────────────────────────────────────────
def test_relocate_zone_retargets_all_hosts_off_zone():
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    trace = synthesize_trace(sc, topo)
    applicable = set(sc.spatial_constraints.applicable_zones)

    mutated, host = relocate_zone(trace, sc, topo)
    assert host is not None
    # every event now points at the single off-zone host
    assert {e["host"] for e in mutated} == {host}
    # that host's zone is NOT applicable
    zone, _crit = topo.enrich(host)
    assert zone.value not in applicable
    # original untouched
    assert {e["host"] for e in trace} != {host} or len(trace) == 0


from augur.metrics.robustness import (
    expected_proximity, evaluate_mutation, detection_robustness,
    MUTATION_KINDS, HONESTY_NOTE,
)


# ── expected_proximity (spec-derived, no engine) ─────────────────────────────
def test_expected_proximity_drop_step():
    sc = _scenario("SCEN-WIN-001")
    n = sc.step_count
    assert expected_proximity(sc, "drop_step", n) == round((n - 1) / n, 4)
    assert expected_proximity(sc, "drop_step", 1) is None  # anchor removed


def test_expected_proximity_stretch_truncates_before_k():
    sc = _scenario("SCEN-WIN-001")
    n = sc.step_count
    # LOCKED convention: stretch step k => matched prefix k-1 => (k-1)/n
    assert expected_proximity(sc, "stretch_temporal", n) == round((n - 1) / n, 4)


def test_expected_proximity_relocate_is_none():
    sc = _scenario("SCEN-WIN-001")
    assert expected_proximity(sc, "relocate_zone", None) is None


# ── evaluate_mutation (drives the real read-only pipeline) ───────────────────
def test_evaluate_mutation_drop_last_step_truncates():
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    n = sc.step_count
    row = evaluate_mutation(sc, topo, "drop_step", n)
    assert row["scenario_id"] == "SCEN-WIN-001"
    assert row["kind"] == "drop_step"
    assert row["expected"] == round((n - 1) / n, 4)
    assert row["observed"] == round((n - 1) / n, 4)
    assert row["pass"] is True
    assert row["status"] == "detected_correctly"


def test_evaluate_mutation_stretch_last_step_truncates():
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    n = sc.step_count
    row = evaluate_mutation(sc, topo, "stretch_temporal", n)
    assert row["expected"] == round((n - 1) / n, 4)
    assert row["observed"] == round((n - 1) / n, 4)
    assert row["pass"] is True
    assert row["status"] == "detected_correctly"


def test_evaluate_mutation_relocate_vanishes():
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    row = evaluate_mutation(sc, topo, "relocate_zone", None)
    assert row["expected"] is None
    assert row["observed"] is None
    assert row["pass"] is True
    assert row["status"] == "rejected_correctly"


import augur.engine.matcher as matcher_mod


# ── Integration: three canonical anchors degrade correctly ───────────────────
@pytest.mark.parametrize("scenario_id", ["SCEN-WIN-001", "SCEN-LNX-001", "SCEN-MAC-001"])
def test_canonical_scenarios_degrade_correctly(scenario_id):
    topo = default_topology()
    sc = _scenario(scenario_id)
    n = sc.step_count

    drop_row = evaluate_mutation(sc, topo, "drop_step", n)
    assert drop_row["observed"] == round((n - 1) / n, 4)
    assert drop_row["pass"] is True

    if n >= 2:
        stretch_row = evaluate_mutation(sc, topo, "stretch_temporal", n)
        assert stretch_row["observed"] == round((n - 1) / n, 4)
        assert stretch_row["pass"] is True

    reloc_row = evaluate_mutation(sc, topo, "relocate_zone", None)
    assert reloc_row["observed"] is None  # detection vanished
    assert reloc_row["pass"] is True


# ── Regression tripwire: prove the temporal gate has teeth ───────────────────
def test_tripwire_loosened_temporal_gate_would_wrongly_fire(monkeypatch):
    """If ``_temporal_ok`` were monkeypatched to always-True, the stretched trace
    would (WRONGLY) fire at 1.0 instead of truncating. This proves the stretch
    mutation actually exercises the temporal gate — the check has teeth. The shipped
    engine is NOT altered (monkeypatch is scoped to this test)."""
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    n = sc.step_count
    assert n >= 2

    # Sanity: with the real gate, stretch truncates.
    real_row = evaluate_mutation(sc, topo, "stretch_temporal", n)
    assert real_row["observed"] == round((n - 1) / n, 4)

    # Loosen the gate to always-True; the stretched trace now wrongly fires 1.0.
    monkeypatch.setattr(matcher_mod, "_temporal_ok", lambda prev_ts, ts, step: True)
    loosened_row = evaluate_mutation(sc, topo, "stretch_temporal", n)
    assert loosened_row["observed"] == 1.0
    assert loosened_row["pass"] is False  # the validator catches the regression


# ── Green baseline: the whole library passes today ───────────────────────────
def test_detection_robustness_green_baseline():
    report = detection_robustness(default_scenarios(), default_topology())
    agg = report["aggregate"]
    assert agg["failed"] == 0, [r for r in report["rows"] if not r["pass"]
                                and r["status"] not in {"unsynthesizable", "no_offzone_host", "not_applicable"}]
    assert agg["pass_pct"] == 1.0
    assert report["honesty_note"] == HONESTY_NOTE
    assert set(MUTATION_KINDS) == {"drop_step", "stretch_temporal", "relocate_zone", "relink_host"}


def test_detection_robustness_no_offzone_host_not_triggered_on_library():
    # The real 5-zone topology always has an off-zone host, so relocate is never skipped.
    report = detection_robustness(default_scenarios(), default_topology())
    reloc = [r for r in report["rows"] if r["kind"] == "relocate_zone"]
    assert reloc and all(r["status"] == "rejected_correctly" for r in reloc)


# ── Determinism: two runs are byte-identical ─────────────────────────────────
def test_detection_robustness_is_deterministic():
    a = detection_robustness(default_scenarios(), default_topology())
    b = detection_robustness(default_scenarios(), default_topology())
    assert a == b


# ── Purity: mutations.py must not import the engine, now(), or random ────────
def test_mutations_purity_no_engine_now_random():
    src = Path("src/augur/metrics/mutations.py").read_text()
    tree = ast.parse(src)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert not any(m.startswith("augur.engine") for m in imported), "mutations must not import the engine"
    assert not any(m.startswith("augur.graph") for m in imported), "mutations must not import the graph"
    assert "random" not in imported
    assert ".now(" not in src and "utcnow" not in src


from datetime import datetime, timezone

from augur.metrics.report import build_report, render_markdown


def test_report_includes_robustness_section():
    scenarios = default_scenarios()[:3]
    topo = default_topology()
    report = build_report(scenarios, topo, [], datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert "robustness" in report
    rob = report["robustness"]
    assert set(rob["aggregate"].keys()) == {"total", "passed", "failed", "skipped", "pass_pct"}
    assert rob["honesty_note"] == HONESTY_NOTE

    md = render_markdown(report)
    assert "Detection Robustness" in md
    assert "construction-integrity" in md  # honesty banner present


import pytest as _pytest

from augur.metrics.__main__ import main


def test_cli_fail_on_robustness_exits_zero_on_green(tmp_path):
    """On the green library, --fail-on-robustness exits cleanly (no SystemExit)."""
    out = tmp_path / "r.md"
    # short benign corpus keeps the run fast; robustness runs over the full library
    main(["--out", str(out), "--duration", "60", "--rate", "5", "--fail-on-robustness"])
    assert "Detection Robustness" in out.read_text()


def test_cli_fail_on_robustness_exits_nonzero_when_failing(tmp_path, monkeypatch):
    """If a robustness row fails, --fail-on-robustness must exit non-zero (CI gate)."""
    import augur.metrics.report as report_mod

    real = report_mod.detection_robustness

    def _inject_failure(scenarios, topology, **kw):
        rep = real(scenarios, topology, **kw)
        # Flip the first scored row to a failure so the gate must trip.
        for r in rep["rows"]:
            if r["status"] in ("detected_correctly", "rejected_correctly"):
                r["pass"] = False
                r["status"] = "unexpected_fire"
                break
        rep["aggregate"]["failed"] = 1
        return rep

    monkeypatch.setattr(report_mod, "detection_robustness", _inject_failure)

    with _pytest.raises(SystemExit) as exc:
        main(["--out", str(tmp_path / "r.md"), "--duration", "60", "--rate", "5",
              "--fail-on-robustness"])
    assert exc.value.code != 0


# ── relink_host wiring ───────────────────────────────────────────────────────
def test_expected_proximity_relink_truncates_before_k():
    sc = _scenario("SCEN-WIN-001")
    n = sc.step_count
    # LOCKED: relink step k => same_host broken at k-1->k => matched prefix k-1
    assert expected_proximity(sc, "relink_host", n) == round((n - 1) / n, 4)
    assert expected_proximity(sc, "relink_host", 2) == round(1 / n, 4)


def test_evaluate_mutation_relink_last_step_truncates():
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    n = sc.step_count
    row = evaluate_mutation(sc, topo, "relink_host", n)
    assert row["kind"] == "relink_host"
    assert row["expected"] == round((n - 1) / n, 4)
    assert row["observed"] == round((n - 1) / n, 4)
    assert row["pass"] is True
    assert row["status"] == "detected_correctly"


def test_relink_host_in_mutation_kinds():
    assert MUTATION_KINDS == ("drop_step", "stretch_temporal", "relocate_zone", "relink_host")


def test_build_report_accepts_all_steps_kwarg():
    from datetime import datetime, timezone
    scenarios = default_scenarios()[:2]
    topo = default_topology()
    # default path
    rep_default = build_report(scenarios, topo, [], datetime(2026, 1, 1, tzinfo=timezone.utc))
    # all-steps path emits strictly more robustness rows
    rep_all = build_report(scenarios, topo, [], datetime(2026, 1, 1, tzinfo=timezone.utc),
                           all_steps=True)
    assert rep_all["robustness"]["aggregate"]["total"] > rep_default["robustness"]["aggregate"]["total"]


def test_cli_all_steps_fail_on_robustness_exits_zero_on_green(tmp_path):
    """--all-steps --fail-on-robustness exits cleanly on the green library."""
    out = tmp_path / "r.md"
    main(["--out", str(out), "--duration", "60", "--rate", "5",
          "--all-steps", "--fail-on-robustness"])
    assert "Detection Robustness" in out.read_text()
