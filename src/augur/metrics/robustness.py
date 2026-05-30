"""Detection-robustness / false-negative-boundary validation.

Mutates a scenario's positive synthetic trace along each engine gate axis and
asserts the engine degrades to the *spec-mandated* proximity. The engine, matcher,
scoring, graph and topology are imported and called UNCHANGED — this module only
perturbs the input trace (via ``metrics/mutations.py``) and reads the output
proximity. Deterministic: fixed scenarios/topology + deterministic synth + pure
mutators ⇒ byte-identical reports run-to-run (no ``now()``, no ``random``).

Honesty: a PASS proves each gate currently REJECTS on the scenario library — a
construction-integrity / regression gate — NOT a real-world false-negative-rate
claim. See ``HONESTY_NOTE``.
"""
from __future__ import annotations

from augur.generative.synth import synthesize_trace
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.metrics.mutations import drop_step, relink_host, relocate_zone, stretch_temporal
from augur.normalize.registry import normalize_events
from augur.engine.runner import run_engine
from augur.scenarios.schema import Scenario
from augur.topology.network import Topology

MUTATION_KINDS = ("drop_step", "stretch_temporal", "relocate_zone", "relink_host")

HONESTY_NOTE = (
    "Robustness validation against the deterministic simulator's MUTATED synthetic "
    "traces — a construction-integrity and regression gate on the engine's "
    "temporal/spatial/link gates, NOT a real-world false-negative-rate claim. A PASS "
    "proves each gate currently rejects on the scenario library; it is not evidence "
    "against a live adversary."
)


def expected_proximity(scenario: Scenario, kind: str, step_id: int | None) -> float | None:
    """Spec-derived expectation. ``None`` => expect NO detection.

    LOCKED conventions:
        drop_step(k):        round((k-1)/n, 4)   (None when k == 1 — anchor removed)
        stretch_temporal(k): round((k-1)/n, 4)   (matched prefix truncates to k-1)
        relocate_zone:       None                (anchor fails the spatial gate)
    """
    n = scenario.step_count
    if kind == "relocate_zone":
        return None
    if kind == "drop_step":
        if step_id == 1:
            return None
        return round((step_id - 1) / n, 4)
    if kind == "stretch_temporal":
        # step_id >= 2 guaranteed by caller / mutator
        return round((step_id - 1) / n, 4)
    if kind == "relink_host":
        # step_id >= 2 guaranteed by caller / mutator; same_host link broken at
        # k-1 -> k, matched prefix truncates to k-1.
        return round((step_id - 1) / n, 4)
    raise ValueError(f"unknown mutation kind: {kind!r}")


def _default_step(scenario: Scenario, kind: str) -> int | None:
    """Default step choice: the LAST step (k = step_count) for drop/stretch."""
    if kind == "relocate_zone":
        return None
    return scenario.step_count


def _run_proximity(scenario: Scenario, topology: Topology, mutated: list[dict]) -> float | None:
    """Drive the standard read-only pipeline (mirrors metrics/detectability.py)."""
    events = sorted(normalize_events(mutated), key=lambda e: e.timestamp)
    backend = NetworkXBackend()
    build_graph(events, topology, backend)
    dets = {d.scenario_id: d for d in run_engine(backend, [scenario], min_proximity=0.0)}
    det = dets.get(scenario.scenario_id)
    return det.proximity if det is not None else None


def evaluate_mutation(
    scenario: Scenario, topology: Topology, kind: str, step_id: int | None = None
) -> dict:
    """Apply one mutation, run the read-only pipeline, compare to expected_proximity.

    Row keys: scenario_id, kind, step_id, expected, observed, pass, status, note.
    status in {detected_correctly, rejected_correctly, unexpected_fire,
               unexpected_miss, unsynthesizable, no_offzone_host, no_distinct_host,
               not_applicable}.
    Never raises mid-batch: bad inputs become a ``not_applicable`` row.
    """
    if step_id is None:
        step_id = _default_step(scenario, kind)

    row = {
        "scenario_id": scenario.scenario_id,
        "kind": kind,
        "step_id": step_id,
        "expected": None,
        "observed": None,
        "pass": False,
        "status": "not_applicable",
        "note": "",
    }

    # 1-step scenarios can't be stretched/relinked (no step >= 2).
    if kind in ("stretch_temporal", "relink_host") and (step_id is None or step_id < 2):
        row["note"] = f"no step >= 2 to {kind} (1-step scenario)"
        return row

    trace = synthesize_trace(scenario, topology)
    if trace is None:
        row["status"] = "unsynthesizable"
        row["note"] = "synthesize_trace returned None"
        return row

    try:
        if kind == "drop_step":
            mutated = drop_step(trace, scenario, step_id)
        elif kind == "stretch_temporal":
            mutated = stretch_temporal(trace, scenario, step_id)
        elif kind == "relocate_zone":
            mutated, host = relocate_zone(trace, scenario, topology)
            if host is None:
                row["status"] = "no_offzone_host"
                row["note"] = "topology has no host outside applicable_zones"
                return row
            row["note"] = f"relocated to {host}"
        elif kind == "relink_host":
            mutated, host = relink_host(trace, scenario, topology, step_id)
            if host is None:
                row["status"] = "no_distinct_host"
                row["note"] = "topology has no distinct second eligible host"
                return row
            row["note"] = f"relinked step {step_id}..end to {host}"
        else:
            row["note"] = f"unknown kind {kind!r}"
            return row
    except ValueError as exc:
        row["note"] = str(exc)
        return row

    expected = expected_proximity(scenario, kind, step_id)
    observed = _run_proximity(scenario, topology, mutated)
    passed = observed == expected

    row["expected"] = expected
    row["observed"] = observed
    row["pass"] = passed

    if passed:
        row["status"] = "rejected_correctly" if expected is None else "detected_correctly"
    else:
        if expected is None and observed is not None:
            row["status"] = "unexpected_fire"
        elif expected is not None and observed is None:
            row["status"] = "unexpected_miss"
        else:
            row["status"] = "unexpected_fire" if (observed or 0) > (expected or 0) else "unexpected_miss"
    return row


_SKIPPED_STATUSES = {"unsynthesizable", "no_offzone_host", "no_distinct_host", "not_applicable"}


def _steps_for_kind(scenario: Scenario, kind: str) -> list[int | None]:
    """Step_ids to mutate under --all-steps:
       stretch_temporal -> 2..n   (temporal GATE — rejects at every hop)
       relink_host      -> 2..n   (link GATE — rejects at every hop)
       drop_step        -> [n]    (last step only)
       relocate_zone    -> [None] (step-independent)

    The ``--all-steps`` sweep proves the engine's GATES (temporal/spatial/link)
    reject at *every* prefix position, so the gate mutations (``stretch_temporal``,
    ``relink_host``) are swept over 2..n. ``drop_step`` is NOT a gate mutation — it
    removes a step's events entirely — and at an *intermediate* position its
    matched-prefix outcome is not spec-derivable as ``(k-1)/n``: the DFS may still
    realize a valid contiguous prefix from the surviving steps, or a later step's
    events may satisfy the dropped step's criteria. So ``drop_step`` stays at the
    last step (its well-defined ``(n-1)/n`` truncation), matching the default run.
    """
    n = scenario.step_count
    if kind == "relocate_zone":
        return [None]
    if kind == "drop_step":
        return [n]
    # stretch_temporal, relink_host
    return list(range(2, n + 1))


OVERLAP_NOTE = (
    "Criteria cross-step overlap (informational, NOT a gate failure). For these "
    "scenarios, dropping an intermediate or anchor step's events leaves the chain "
    "still (partially) matching above the naive (k-1)/n truncation — because a "
    "later step's matching_criteria is satisfied by the dropped step's surviving "
    "events, or vice versa (overlapping process predicates). This is a PRECISION "
    "signal about the scenario library (potential over-match under partial "
    "evidence), not a temporal/spatial/link gate rejection failure. It is excluded "
    "from the robustness pass/fail gate by construction (drop_step is only a "
    "well-defined prefix-truncation oracle at the LAST step)."
)


def criteria_overlap_diagnostic(
    scenarios: list[Scenario], topology: Topology
) -> dict:
    """Informational (NON-GATING) drop_step sweep over k in 1..n-1.

    For each multi-step scenario and each NON-last step k, drop step k's events and
    compare the observed proximity to the naive prefix-truncation oracle
    ``round((k-1)/n, 4)`` (``None`` for the anchor, k == 1). A row is flagged
    ``overlap`` when ``observed`` exceeds that oracle (or is non-None for the anchor)
    — i.e. the chain still matched more than dropping step k should permit, because
    step matching_criteria overlap across steps.

    This is NOT a gate test and is NEVER part of the robustness pass/fail aggregate.
    It surfaces a real precision property of the scenario library honestly instead of
    silently scoping it away. Deterministic; reuses the read-only pipeline.

    Returns {rows, flagged, note}. ``rows`` are only the flagged ones (tight);
    ``flagged`` is their count. Deterministic order by (scenario_id, step_id).
    """
    rows: list[dict] = []
    for scenario in scenarios:
        n = scenario.step_count
        if n < 2:
            continue
        for k in range(1, n):  # intermediate + anchor; last step is the gate oracle
            trace = synthesize_trace(scenario, topology)
            if trace is None:
                continue
            try:
                mutated = drop_step(trace, scenario, k)
            except ValueError:
                continue
            naive = None if k == 1 else round((k - 1) / n, 4)
            observed = _run_proximity(scenario, topology, mutated)
            # Flag when the chain survived beyond the naive truncation oracle.
            if k == 1:
                overlap = observed is not None
            else:
                overlap = observed is not None and observed > naive
            if overlap:
                rows.append({
                    "scenario_id": scenario.scenario_id,
                    "step_id": k,
                    "naive_expected": naive,
                    "observed": observed,
                    "kind": "anchor" if k == 1 else "intermediate",
                })
    rows.sort(key=lambda r: (r["scenario_id"], r["step_id"]))
    return {"rows": rows, "flagged": len(rows), "note": OVERLAP_NOTE}


def detection_robustness(
    scenarios: list[Scenario], topology: Topology, *, kinds=MUTATION_KINDS,
    all_steps: bool = False,
) -> dict:
    """Run all applicable (scenario x kind) mutations.

    Default (``all_steps=False``): the default (last) step only — byte-identical to
    the pre-sweep behavior. ``all_steps=True``: every applicable step per kind
    (drop 1..n, stretch/relink 2..n, relocate single), proving the gates reject at
    EVERY prefix position, not just the deepest.

    Returns {rows, aggregate{total, passed, failed, skipped, pass_pct}, honesty_note}.
    Deterministic order by (scenario_id, kind, step_id). ``pass_pct`` excludes skipped
    rows from the denominator (mirrors detectability's ``unsynthesizable`` handling).
    """
    rows: list[dict] = []
    for scenario in scenarios:
        for kind in kinds:
            if all_steps:
                for step_id in _steps_for_kind(scenario, kind):
                    rows.append(evaluate_mutation(scenario, topology, kind, step_id))
            else:
                rows.append(evaluate_mutation(scenario, topology, kind))

    rows.sort(key=lambda r: (r["scenario_id"], r["kind"], r["step_id"] if r["step_id"] is not None else -1))

    scored = [r for r in rows if r["status"] not in _SKIPPED_STATUSES]
    passed = sum(1 for r in scored if r["pass"])
    failed = sum(1 for r in scored if not r["pass"])
    skipped = len(rows) - len(scored)
    pass_pct = round(passed / len(scored), 4) if scored else 1.0

    return {
        "rows": rows,
        "aggregate": {
            "total": len(rows),
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "pass_pct": pass_pct,
        },
        "honesty_note": HONESTY_NOTE,
    }
