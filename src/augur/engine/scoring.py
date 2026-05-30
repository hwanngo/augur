from dataclasses import dataclass
from augur.enums import SEVERITY_RANK
from augur.engine.matcher import Candidate
from augur.scenarios.schema import Scenario


@dataclass
class Detection:
    scenario_id: str
    name: str
    severity: str
    proximity: float
    matched_steps: list[dict]
    missing_steps: list[dict]
    affected_hosts: list[str]
    affected_zones: list[str]
    hunting_queries: list[dict]
    _latest_ts: str = ""
    _latest_ts_epoch: float = 0.0
    _severity_rank: int = 0


def build_detection(scenario: Scenario, matched_len: int, chain: list[Candidate]) -> Detection:
    steps = scenario.attack_sequence_flow.steps
    matched_steps = []
    for i, cand in enumerate(chain):
        step = steps[i]
        matched_steps.append({
            "step_id": step.step_id, "name": step.name, "element_id": cand.element_id,
            "host": cand.host.hostname if cand.host else None,
            "timestamp": cand.timestamp.isoformat() if cand.timestamp else None,
        })
    missing_steps = [{
        "step_id": s.step_id,
        "name": s.name,
        "matching_criteria": s.matching_criteria,
        "temporal": s.temporal_link.model_dump() if s.temporal_link is not None else None,
    } for s in steps[matched_len:]]
    hosts = sorted({c.host.hostname for c in chain if c.host})
    zones = sorted({c.host.zone.value for c in chain if c.host})
    queries = [{"engine": q.engine, "query": q.query, "query_path": q.query_path}
               for q in scenario.actionable_hunting_outputs.validation_queries]
    ts_objs = [c.timestamp for c in chain if c.timestamp]
    latest = max((t.isoformat() for t in ts_objs), default="")
    latest_epoch = max((t.timestamp() for t in ts_objs), default=0.0)
    return Detection(
        scenario_id=scenario.scenario_id, name=scenario.name, severity=scenario.severity.value,
        proximity=round(matched_len / scenario.step_count, 4),
        matched_steps=matched_steps, missing_steps=missing_steps,
        affected_hosts=hosts, affected_zones=zones, hunting_queries=queries,
        _latest_ts=latest, _latest_ts_epoch=latest_epoch,
        _severity_rank=SEVERITY_RANK[scenario.severity],
    )


def rank(detections: list[Detection], min_proximity: float = 0.30) -> list[Detection]:
    # highest proximity first, then severity, then most-recent matched event first (spec §6.3)
    kept = [d for d in detections if d.proximity >= min_proximity and d.proximity > 0]
    return sorted(kept, key=lambda d: (-d.proximity, -d._severity_rank, -d._latest_ts_epoch))
