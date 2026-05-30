from dataclasses import dataclass
from datetime import datetime, timedelta
from augur.enums import LinkScope, Zone, Criticality
from augur.graph.interface import GraphBackend
from augur.graph.models import HostNode
from augur.scenarios.schema import Scenario, Step, SpatialConstraints
from augur.engine.criteria import (
    is_behavior_step, node_matches, behavior_edge_matches, node_matches_nonbehavior,
)


@dataclass
class Candidate:
    element_id: str
    timestamp: datetime
    host: HostNode | None


def _spatial_ok(host: HostNode | None, sc: SpatialConstraints) -> bool:
    if host is None or host.zone == Zone.Unknown:
        return False
    if host.zone.value not in sc.applicable_zones:
        return False
    if sc.critical_assets_only and host.criticality != Criticality.CRITICAL:
        return False
    return True


def _find_candidates(scenario: Scenario, step: Step, backend: GraphBackend) -> list[Candidate]:
    criteria = step.matching_criteria
    sc = scenario.spatial_constraints
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
    out = [c for c in out if c.timestamp is not None and _spatial_ok(c.host, sc)]
    return sorted(out, key=lambda c: (c.timestamp, c.element_id))


def _temporal_ok(prev_ts: datetime, ts: datetime, step: Step) -> bool:
    link = step.temporal_link
    if ts < prev_ts:
        return False
    lo = prev_ts + timedelta(seconds=link.min_time_delta_seconds)
    hi = prev_ts + timedelta(seconds=link.max_time_delta_seconds)
    return lo <= ts <= hi


def _link_ok(prev: Candidate, cand: Candidate, scope: LinkScope) -> bool:
    if scope == LinkScope.any:
        return True
    same = prev.host.hostname.lower() == cand.host.hostname.lower()
    return same if scope == LinkScope.same_host else (not same)


def match_scenario(scenario: Scenario, backend: GraphBackend) -> tuple[int, list[Candidate]]:
    steps = scenario.attack_sequence_flow.steps
    cands = {s.step_id: _find_candidates(scenario, s, backend) for s in steps}
    if not cands[steps[0].step_id]:
        return 0, []

    best = (0, [])

    def extend(idx: int, prev: Candidate, chain: list[Candidate]) -> None:
        nonlocal best
        if len(chain) > best[0]:
            best = (len(chain), list(chain))
        if idx >= len(steps):
            return
        step = steps[idx]
        for cand in cands[step.step_id]:
            if not _temporal_ok(prev.timestamp, cand.timestamp, step):
                continue
            if not _link_ok(prev, cand, step.temporal_link.link_scope):
                continue
            chain.append(cand)
            extend(idx + 1, cand, chain)
            chain.pop()

    for anchor in cands[steps[0].step_id]:
        extend(1, anchor, [anchor])
    return best
