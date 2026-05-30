from augur.metrics.robustness import detection_robustness
from augur.pipeline import default_scenarios, default_topology


def _expected_row_count(scenarios):
    """Per-step cardinality under --all-steps:
       drop_step          -> last step only     (1 row)
       stretch_temporal   -> k in 2..n           (n-1 rows)
       relink_host        -> k in 2..n           (n-1 rows)
       relocate_zone      -> single              (1 row)

    drop_step stays last-step-only: at an intermediate position its matched-prefix
    is not spec-derivable as (k-1)/n (the surviving steps can still chain). The
    GATE mutations (stretch/relink) are the ones swept across every hop.
    """
    total = 0
    for sc in scenarios:
        n = sc.step_count
        total += 1 + (n - 1) + (n - 1) + 1
    return total


def test_all_steps_emits_expected_cardinality():
    scenarios = default_scenarios()
    topo = default_topology()
    report = detection_robustness(scenarios, topo, all_steps=True)
    assert report["aggregate"]["total"] == _expected_row_count(scenarios)


def test_all_steps_per_kind_step_ranges():
    # Pick one multi-step scenario and assert each kind hits the right step_ids.
    scenarios = [s for s in default_scenarios() if s.scenario_id == "SCEN-WIN-001"]
    topo = default_topology()
    n = scenarios[0].step_count
    report = detection_robustness(scenarios, topo, all_steps=True)
    rows = report["rows"]

    drop_steps = sorted(r["step_id"] for r in rows if r["kind"] == "drop_step")
    stretch_steps = sorted(r["step_id"] for r in rows if r["kind"] == "stretch_temporal")
    relink_steps = sorted(r["step_id"] for r in rows if r["kind"] == "relink_host")
    reloc = [r for r in rows if r["kind"] == "relocate_zone"]

    assert drop_steps == [n]  # last step only (not a gate mutation)
    assert stretch_steps == list(range(2, n + 1))
    assert relink_steps == list(range(2, n + 1))
    assert len(reloc) == 1  # step-independent, single row


def test_all_steps_green_on_library():
    report = detection_robustness(default_scenarios(), default_topology(), all_steps=True)
    assert report["aggregate"]["failed"] == 0
    assert report["aggregate"]["pass_pct"] == 1.0


def test_all_steps_false_is_byte_identical_to_default():
    """Regression guard: all_steps=False must reproduce today's last-step-only output."""
    a = detection_robustness(default_scenarios(), default_topology())
    b = detection_robustness(default_scenarios(), default_topology(), all_steps=False)
    assert a == b
    # and the default path is still last-step-only: one drop, one stretch, one
    # relink, one relocate per scenario => 4 rows/scenario.
    assert a["aggregate"]["total"] == 4 * len(default_scenarios())
