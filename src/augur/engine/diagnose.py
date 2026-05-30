"""Read-only near-miss diagnosis for partial detections (F3).

Explains why the FIRST un-matched step (k+1) of an existing partial detection stalled.
Reuses the matcher's standalone gate helpers; never calls ``match_scenario`` / re-runs the DFS /
mutates scoring. [AUDIT #1] scoped to ``matched_len >= 1``; anchor-misses (scenarios that never
matched step 1, which therefore emit no Detection) are out of scope. [AUDIT #2] the live anchor
Candidate is re-derived from the backend, not from the serialized Detection.

The matcher's ``_find_candidates`` already drops spatially-invalid candidates (it applies
``_spatial_ok`` before returning). A candidate that exists only in the wrong zone would therefore
never reach the temporal/link gates and would wrongly read as "no_candidate". To keep spatial
near-misses explainable, this module re-derives candidates *without* the spatial pre-filter via a
local read-only ``_all_candidates_unfiltered`` — the matcher itself is untouched.
"""
from augur.graph.interface import GraphBackend
from augur.engine.scoring import Detection
from augur.engine.matcher import (
    Candidate, _find_candidates, _spatial_ok, _temporal_ok, _link_ok,
)
from augur.engine.criteria import (
    is_behavior_step, node_matches, node_matches_nonbehavior, behavior_edge_matches,
)
from augur.scenarios.schema import Scenario, Step


def _all_candidates_unfiltered(scenario: Scenario, step: Step, backend: GraphBackend) -> list[Candidate]:
    """``matcher._find_candidates`` MINUS the ``_spatial_ok`` filter.

    The matcher helper is spatial-filtered by design (and must not be changed); diagnosis needs the
    pre-spatial set so a wrong-zone-only candidate surfaces as a ``spatial`` near-miss rather than
    ``no_candidate``. Everything else (criteria matching, sort order) mirrors the matcher exactly.
    """
    criteria = step.matching_criteria
    out: list[Candidate] = []
    if is_behavior_step(criteria):
        for proc in backend.find_nodes("Process", lambda n: node_matches_nonbehavior(n, criteria)):
            host = backend.host_of(proc.id)
            for i, edge in enumerate(backend.edges_from(proc.id, "EXHIBITED")):
                if behavior_edge_matches(edge.attrs, criteria):
                    out.append(Candidate(element_id=f"{proc.id}|EXH|{i}", timestamp=edge.timestamp, host=host))
    else:
        node_type = criteria["Node_Type"]
        for node in backend.find_nodes(node_type, lambda n: node_matches(n, criteria)):
            out.append(Candidate(element_id=node.id, timestamp=node.timestamp, host=backend.host_of(node.id)))
    out = [c for c in out if c.timestamp is not None]
    return sorted(out, key=lambda c: (c.timestamp, c.element_id))


def diagnose_stall(backend: GraphBackend, scenario: Scenario, detection: Detection) -> dict | None:
    """Explain why step ``k+1`` of a partial ``detection`` stalled, or ``None``.

    Returns ``None`` for 100% detections (nothing stalled) and, defensively, when the anchor cannot
    be re-derived from the live graph. Otherwise returns one of:

    - ``{"kind": "no_candidate", "step_id", "step_name"}``
    - ``{"kind": "temporal", "step_id", "host", "delta_seconds", "window_seconds"}``
    - ``{"kind": "spatial", "step_id", "host", "zone", "applicable_zones"}``
    - ``{"kind": "link", "step_id", "host", "link_scope"}``
    """
    steps = scenario.attack_sequence_flow.steps
    matched_len = len(detection.matched_steps)
    if matched_len < 1 or matched_len >= len(steps):
        return None                      # 100% or (defensively) anchor-miss → no stall

    # [AUDIT #2] re-derive the live anchor Candidate for the last matched step (step k) by element_id.
    anchor_step = steps[matched_len - 1]
    last = detection.matched_steps[-1]
    anchor = next(
        (c for c in _find_candidates(scenario, anchor_step, backend)
         if c.element_id == last["element_id"]),
        None,
    )
    if anchor is None:                   # defensive: graph changed under us
        return None

    next_step = steps[matched_len]       # step k+1 (1-based step_id == matched_len + 1)
    sc = scenario.spatial_constraints
    scope = next_step.temporal_link.link_scope

    # Re-derive candidates WITHOUT the spatial pre-filter so spatial misses are explainable.
    raw = _all_candidates_unfiltered(scenario, next_step, backend)
    if not raw:
        return {"kind": "no_candidate", "step_id": next_step.step_id, "step_name": next_step.name}

    # Evaluate gates in engine order: spatial → temporal → link. Collect near-misses; pick closest.
    near: list[tuple[str, Candidate, float | None]] = []
    for c in raw:
        if not _spatial_ok(c.host, sc):
            near.append(("spatial", c, None))
            continue
        if not _temporal_ok(anchor.timestamp, c.timestamp, next_step):
            delta = (c.timestamp - anchor.timestamp).total_seconds()
            near.append(("temporal", c, delta))
            continue
        if not _link_ok(anchor, c, scope):
            near.append(("link", c, None))
            continue
        # A candidate that passes every gate means the engine would have extended — no stall here.
        return None

    # Tie-break: spatial first, then temporal (smallest positive overshoot), then link.
    order = {"spatial": 0, "temporal": 1, "link": 2}
    window = next_step.temporal_link.max_time_delta_seconds

    def key(item):
        kind, c, delta = item
        overshoot = (delta - window) if (kind == "temporal" and delta is not None) else 0.0
        return (order[kind], overshoot if overshoot > 0 else float("inf"), c.element_id)

    kind, cand, delta = sorted(near, key=key)[0]
    host = cand.host.hostname if cand.host else None
    if kind == "temporal":
        return {"kind": "temporal", "step_id": next_step.step_id, "host": host,
                "delta_seconds": delta, "window_seconds": window}
    if kind == "spatial":
        zone = cand.host.zone.value if cand.host else None
        return {"kind": "spatial", "step_id": next_step.step_id, "host": host,
                "zone": zone, "applicable_zones": list(sc.applicable_zones)}
    return {"kind": "link", "step_id": next_step.step_id, "host": host, "link_scope": scope.value}
