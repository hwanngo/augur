"""Criteria cross-step overlap diagnostic — informational, NON-GATING.

Proves the drop_step intermediate/anchor precision signal is surfaced honestly
(not silently scoped away) AND that it never enters the robustness pass/fail gate.
Deterministic: fixed scenarios + topology + synth.
"""
from __future__ import annotations

from augur.metrics.report import build_report
from augur.metrics.robustness import (
    criteria_overlap_diagnostic,
    detection_robustness,
)
from augur.pipeline import default_scenarios, default_topology


def test_overlap_diagnostic_library_is_clean():
    """The library is free of cross-step criteria-superset over-match.

    Previously SCEN-LNX-005 (anchor) and SCEN-MAC-001 (intermediate) were the two
    flagged rows; both criteria were tightened so the diagnostic now flags nothing.
    """
    scens = default_scenarios()
    topo = default_topology()
    d = criteria_overlap_diagnostic(scens, topo)

    assert d["flagged"] == 0

    # The two formerly-overlapping rows must no longer appear.
    flagged_ids = {(r["scenario_id"], r["step_id"]) for r in d["rows"]}
    assert ("SCEN-LNX-005", 1) not in flagged_ids
    assert ("SCEN-MAC-001", 2) not in flagged_ids


def test_overlap_diagnostic_is_deterministic():
    scens, topo = default_scenarios(), default_topology()
    assert criteria_overlap_diagnostic(scens, topo) == criteria_overlap_diagnostic(scens, topo)


def test_overlap_excluded_from_robustness_gate():
    """The diagnostic must NEVER affect the robustness pass/fail aggregate."""
    scens, topo = default_scenarios(), default_topology()
    rob = detection_robustness(scens, topo, all_steps=True)
    # Gate is clean despite the overlap findings existing.
    assert rob["aggregate"]["failed"] == 0
    # And the overlap diagnostic is a separate structure, not a robustness row.
    assert "criteria_overlap" not in rob


def test_report_includes_overlap_only_under_all_steps():
    from datetime import datetime, timezone

    scens, topo = default_scenarios(), default_topology()
    ts = datetime(2026, 6, 2, tzinfo=timezone.utc)

    plain = build_report(scens, topo, [], ts, all_steps=False)
    assert "criteria_overlap" not in plain

    deep = build_report(scens, topo, [], ts, all_steps=True)
    assert "criteria_overlap" in deep
    assert deep["criteria_overlap"]["flagged"] == 0
    assert "NOT a gate failure" in deep["criteria_overlap"]["note"]
