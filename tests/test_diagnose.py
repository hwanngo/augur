"""F3 — read-only near-miss diagnosis (engine/diagnose.py).

Explains why the FIRST un-matched step (k+1) of an existing partial detection stalled.
Never calls match_scenario / re-runs the DFS / mutates scoring. [AUDIT #1] matched_len>=1;
[AUDIT #2] the live anchor Candidate is re-derived from the backend.
"""
from datetime import datetime, timezone, timedelta

from augur.engine.diagnose import diagnose_stall, _all_candidates_unfiltered
from augur.engine.runner import run_engine
from augur.engine.matcher import Candidate
from augur.engine.scoring import build_detection
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.models import HostNode, ProcessNode
from augur.normalize.ecs import normalize_events
from augur.ingest.jsonl import read_jsonl
from augur.pipeline import default_scenarios, default_topology
from augur.enums import Zone, Criticality, LinkScope, Severity
from augur.scenarios.schema import (
    Scenario, ScenarioMetadata, MitreMapping, SpatialConstraints,
    AttackSequenceFlow, Step, TemporalLink, ActionableHuntingOutputs, HuntingQuery,
)


def _backend_for(paths):
    raws = []
    for p in paths:
        raws.extend(read_jsonl(p))
    events = sorted(normalize_events(raws), key=lambda e: e.timestamp)
    b = NetworkXBackend()
    build_graph(events, default_topology(), b)
    return b


def _partial(paths, scen_id):
    scns = default_scenarios()
    b = _backend_for(paths)
    dets = run_engine(b, scns, min_proximity=0.0)
    d = next(d for d in dets if d.scenario_id == scen_id)
    scn = next(s for s in scns if s.scenario_id == scen_id)
    return b, scn, d


# ---------------------------------------------------------------------------
# C1 — skeleton: None for 100% detections
# ---------------------------------------------------------------------------

def test_full_detection_returns_none():
    scns = default_scenarios()
    b = _backend_for(["sample_data/acceptance/full_detection.jsonl"])
    dets = run_engine(b, scns, min_proximity=0.0)
    win = next(d for d in dets if d.scenario_id == "SCEN-WIN-001")
    assert win.proximity == 1.0
    scn = next(s for s in scns if s.scenario_id == "SCEN-WIN-001")
    assert diagnose_stall(b, scn, win) is None     # no stall on a 100% detection


# ---------------------------------------------------------------------------
# C2 — anchor re-derivation + each gate outcome + tie-break
# ---------------------------------------------------------------------------

def test_anchor_rederived_from_backend():
    b, scn, d = _partial(["sample_data/acceptance/no_detection_temporal_gap.jsonl"], "SCEN-WIN-001")
    out = diagnose_stall(b, scn, d)
    assert out is not None and out["step_id"] == len(d.matched_steps) + 1


def test_temporal_overshoot_reports_delta_and_window():
    b, scn, d = _partial(["sample_data/acceptance/no_detection_temporal_gap.jsonl"], "SCEN-WIN-001")
    out = diagnose_stall(b, scn, d)
    assert out["kind"] == "temporal"
    assert out["delta_seconds"] > out["window_seconds"]   # overshot the window
    assert "host" in out


def test_no_candidate_when_step_absent():
    b, scn, d = _partial(["sample_data/acceptance/partial_detection.jsonl"], "SCEN-WIN-001")
    out = diagnose_stall(b, scn, d)
    assert out["kind"] == "no_candidate"
    assert out["step_id"] == len(d.matched_steps) + 1
    assert out["step_name"]


# ---------------------------------------------------------------------------
# Crafted-graph tests for spatial / link / tie-break (deterministic branches)
# ---------------------------------------------------------------------------

_T = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)


def _two_step_scenario(zones=("Internal_Server",), scope=LinkScope.same_host, window=60):
    return Scenario(
        scenario_metadata=ScenarioMetadata(
            scenario_id="SCEN-TST-001", name="Test", description="d",
            severity=Severity.HIGH, mitre_mappings=[MitreMapping(tactic="TA0001", technique="T1000")],
            os_family="windows",
        ),
        spatial_constraints=SpatialConstraints(applicable_zones=list(zones)),
        attack_sequence_flow=AttackSequenceFlow(steps=[
            Step(step_id=1, name="s1", matching_criteria={"Node_Type": "Process", "ProcessName": {"in": ["a.exe"]}}),
            Step(step_id=2, name="s2",
                 temporal_link=TemporalLink(previous_step=1, link_scope=scope,
                                            min_time_delta_seconds=0, max_time_delta_seconds=window),
                 matching_criteria={"Node_Type": "Process", "ProcessName": {"in": ["b.exe"]}}),
        ]),
        actionable_hunting_outputs=ActionableHuntingOutputs(
            validation_queries=[HuntingQuery(engine="KQL", query="x")]),
    )


def _host(hid, name, zone):
    return HostNode(id=hid, hostname=name, ip="1.1.1.1", os="windows",
                    zone=zone, criticality=Criticality.MEDIUM)


def _proc(pid, name, host, ts):
    return ProcessNode(id=pid, name=name, path=f"C:\\{name}", command_line=name,
                       parent_guid=None, parent_process_name=None, host=host, timestamp=ts)


def _backend_with(hosts, procs):
    b = NetworkXBackend()
    for h in hosts:
        b.add_host(h)
    for p in procs:
        b.add_process(p)
        # link the process to its host so host_of resolves the zone
        host = next((h for h in hosts if h.hostname == p.host), None)
        if host is not None:
            b.add_edge(p.id, host.id, "RUNS_ON", p.timestamp)
    return b


def _anchor_detection(scn, b, anchor_proc):
    """Build a matched_len==1 Detection whose anchor (step 1) is anchor_proc."""
    host = b.host_of(anchor_proc.id)
    cand = Candidate(element_id=anchor_proc.id, timestamp=anchor_proc.timestamp, host=host)
    return build_detection(scn, 1, [cand])


def test_spatial_near_miss_reported():
    # step-2 candidate exists but only on a host in a non-applicable zone.
    scn = _two_step_scenario(zones=("Internal_Server",))
    good_host = _host("H_OK", "SRV1", Zone.Internal_Server)
    bad_host = _host("H_BAD", "DMZ1", Zone.DMZ)
    a = _proc("p_a", "a.exe", "SRV1", _T)                          # step-1 anchor (applicable zone)
    b2 = _proc("p_b", "b.exe", "DMZ1", _T + timedelta(seconds=5))  # step-2 cand in wrong zone
    b = _backend_with([good_host, bad_host], [a, b2])
    d = _anchor_detection(scn, b, a)
    out = diagnose_stall(b, scn, d)
    assert out["kind"] == "spatial"
    assert out["zone"] == "DMZ"
    assert "Internal_Server" in out["applicable_zones"]
    assert out["host"] == "DMZ1"


def test_link_near_miss_reported():
    # step-2 candidate is spatially+temporally fine but on a DIFFERENT host (same_host required).
    scn = _two_step_scenario(zones=("Internal_Server",), scope=LinkScope.same_host)
    h1 = _host("H1", "SRV1", Zone.Internal_Server)
    h2 = _host("H2", "SRV2", Zone.Internal_Server)
    a = _proc("p_a", "a.exe", "SRV1", _T)
    b2 = _proc("p_b", "b.exe", "SRV2", _T + timedelta(seconds=5))
    b = _backend_with([h1, h2], [a, b2])
    d = _anchor_detection(scn, b, a)
    out = diagnose_stall(b, scn, d)
    assert out["kind"] == "link"
    assert out["link_scope"] == "same_host"
    assert out["host"] == "SRV2"


def test_tiebreak_spatial_before_temporal():
    # one spatial near-miss and one temporal near-miss → spatial wins (engine evaluates it first).
    scn = _two_step_scenario(zones=("Internal_Server",), window=60)
    h_ok = _host("H1", "SRV1", Zone.Internal_Server)
    h_bad = _host("H2", "DMZ1", Zone.DMZ)
    a = _proc("p_a", "a.exe", "SRV1", _T)
    spatial_cand = _proc("p_sp", "b.exe", "DMZ1", _T + timedelta(seconds=5))     # spatial fail
    temporal_cand = _proc("p_tm", "b.exe", "SRV1", _T + timedelta(seconds=600))  # temporal fail
    b = _backend_with([h_ok, h_bad], [a, spatial_cand, temporal_cand])
    d = _anchor_detection(scn, b, a)
    out = diagnose_stall(b, scn, d)
    assert out["kind"] == "spatial"


def test_tiebreak_smallest_temporal_overshoot_wins():
    # two temporal near-misses on the same host → the smaller positive overshoot is reported.
    scn = _two_step_scenario(zones=("Internal_Server",), window=60)
    h_ok = _host("H1", "SRV1", Zone.Internal_Server)
    a = _proc("p_a", "a.exe", "SRV1", _T)
    near = _proc("p_near", "b.exe", "SRV1", _T + timedelta(seconds=90))   # overshoot 30s
    far = _proc("p_far", "b.exe", "SRV1", _T + timedelta(seconds=300))    # overshoot 240s
    b = _backend_with([h_ok], [a, near, far])
    d = _anchor_detection(scn, b, a)
    out = diagnose_stall(b, scn, d)
    assert out["kind"] == "temporal"
    assert out["delta_seconds"] == 90
    assert out["window_seconds"] == 60


def test_all_candidates_unfiltered_keeps_wrong_zone():
    # the local enumeration must NOT spatially pre-filter (unlike matcher._find_candidates).
    scn = _two_step_scenario(zones=("Internal_Server",))
    bad_host = _host("H_BAD", "DMZ1", Zone.DMZ)
    b2 = _proc("p_b", "b.exe", "DMZ1", _T + timedelta(seconds=5))
    b = _backend_with([bad_host], [b2])
    cands = _all_candidates_unfiltered(scn, scn.attack_sequence_flow.steps[1], b)
    assert [c.element_id for c in cands] == ["p_b"]
