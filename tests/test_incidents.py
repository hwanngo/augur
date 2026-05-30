"""TDD: incidents.cluster_incidents — pure, deterministic, corpus-time-only campaign clustering.

Consumes public detection dicts (the `_public` shape from windowed_detections), the scenario
library (for the technique join), and a live Topology (authoritative zone/criticality). NO engine,
NO networkx, NO graph backend, NO now(), NO randomness, NO persistence.
"""
import ast
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from augur.api.incidents import (
    cluster_incidents, _scenario_technique_map, _detection_window, _edges, _components,
    TEMPORAL_HORIZON_SECONDS, MAX_DETECTIONS, MAX_MEMBERS_LISTED, SEV_RANK, HONESTY_NOTE,
)
from augur.topology.network import Topology
from augur.enums import Zone, Criticality
from augur.scenarios.schema import Scenario


# ── tiny in-memory topology ──────────────────────────────────────────────────
def _topo():
    return Topology(zones=[Zone.User_Endpoint], assets=[
        {"hostname": "HOST-A", "zone": Zone.User_Endpoint, "criticality": Criticality.CRITICAL,
         "os": "windows", "ip": "10.0.0.1"},
        {"hostname": "HOST-B", "zone": Zone.User_Endpoint, "criticality": Criticality.LOW,
         "os": "windows", "ip": "10.0.0.2"},
    ])


def _scenario(scenario_id, *, name="S", severity="HIGH", os_family="windows",
              tactic="TA0002", technique="T1059", steps=2):
    step_dicts = []
    for i in range(1, steps + 1):
        s = {"step_id": i, "name": f"step{i}",
             "matching_criteria": {"Node_Type": "Process", "process_name": {"equals": "p.exe"}}}
        if i > 1:
            s["temporal_link"] = {"previous_step": i - 1, "max_time_delta_seconds": 3600}
        step_dicts.append(s)
    return Scenario(
        scenario_metadata={"scenario_id": scenario_id, "name": name, "description": "d",
                           "severity": severity,
                           "mitre_mappings": [{"tactic": tactic, "technique": technique}],
                           "os_family": os_family},
        spatial_constraints={"applicable_zones": ["User_Endpoint"]},
        attack_sequence_flow={"steps": step_dicts},
        actionable_hunting_outputs={"validation_queries": [{"engine": "kql", "query": "x"}]},
    )


def _det(scenario_id, *, severity="HIGH", proximity=1.0, hosts=("HOST-A",),
         ts="2026-01-01T10:00:00+00:00", name="S"):
    """A public detection dict; matched_steps carry the timestamp (no _latest_ts in public dicts)."""
    return {
        "scenario_id": scenario_id, "name": name, "severity": severity,
        "proximity": proximity,
        "matched_steps": [{"step_id": 1, "name": "step1", "element_id": "e1",
                           "host": hosts[0], "timestamp": ts}],
        "missing_steps": [],
        "affected_hosts": list(hosts), "affected_zones": ["User_Endpoint"], "hunting_queries": [],
    }


# ── Task 1 tests ──────────────────────────────────────────────────────────────
def test_constants():
    assert TEMPORAL_HORIZON_SECONDS == 3600
    assert MAX_DETECTIONS == 500
    assert MAX_MEMBERS_LISTED == 50
    assert SEV_RANK == {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    assert "CORRELATION" in HONESTY_NOTE
    assert "campaign" in HONESTY_NOTE.lower()
    # Revision 1: temporal adjacency is label-only context, never a standalone grouping signal.
    assert "context" in HONESTY_NOTE.lower()
    assert "on its own" in HONESTY_NOTE.lower()


def test_scenario_technique_map():
    scens = [_scenario("SCEN-WIN-001", technique="T1059"),
             _scenario("SCEN-LNX-001", technique="T1003")]
    m = _scenario_technique_map(scens)
    assert m["SCEN-WIN-001"] == frozenset({"T1059"})
    assert m["SCEN-LNX-001"] == frozenset({"T1003"})
    # frozenset so it is hashable / immutable
    assert isinstance(m["SCEN-WIN-001"], frozenset)


def test_detection_window_from_matched_steps():
    d = {
        "scenario_id": "X", "name": "S", "severity": "HIGH", "proximity": 1.0,
        "matched_steps": [
            {"step_id": 1, "name": "a", "element_id": "e1", "host": "HOST-A",
             "timestamp": "2026-01-01T10:00:00+00:00"},
            {"step_id": 2, "name": "b", "element_id": "e2", "host": "HOST-A",
             "timestamp": "2026-01-01T10:30:00+00:00"},
        ],
        "affected_hosts": ["HOST-A"],
    }
    first, last = _detection_window(d)
    assert first == datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc).timestamp()
    assert last == datetime(2026, 1, 1, 10, 30, tzinfo=timezone.utc).timestamp()


def test_detection_window_naive_assumed_utc():
    d = {"matched_steps": [{"timestamp": "2026-01-01T10:00:00"}]}  # naive
    first, last = _detection_window(d)
    assert first == datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc).timestamp()
    assert last == first


def test_detection_window_empty_is_sentinel():
    # No matched_steps, or all timestamps None -> empty sentinel (inf, -inf) so it forms no edges.
    assert _detection_window({"matched_steps": []}) == (float("inf"), float("-inf"))
    assert _detection_window({"matched_steps": [{"timestamp": None}]}) == (float("inf"), float("-inf"))


def test_edges_shared_host_only():
    tech = {"A": frozenset({"T1"}), "B": frozenset({"T2"})}  # disjoint techniques
    dets = [
        _det("A", hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00"),
        _det("B", hosts=("HOST-A",), ts="2026-06-01T10:00:00+00:00"),  # far apart in time
    ]
    e = _edges(dets, tech)
    assert e == {frozenset({0, 1}): {"shared_host"}}


def test_edges_shared_technique_only():
    tech = {"A": frozenset({"T1"}), "B": frozenset({"T1"})}  # same technique
    dets = [
        _det("A", hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00"),
        _det("B", hosts=("HOST-B",), ts="2026-06-01T10:00:00+00:00"),  # diff host, far apart
    ]
    e = _edges(dets, tech)
    assert e == {frozenset({0, 1}): {"shared_technique"}}


def test_edges_temporal_only_no_edge():
    # Revision 1: temporal alone never makes an edge. Diff host + disjoint technique + 30min apart
    # -> no host/technique relation -> NO edge (temporal is label-only, never standalone).
    tech = {"A": frozenset({"T1"}), "B": frozenset({"T2"})}  # disjoint techniques
    dets = [
        _det("A", hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00"),
        _det("B", hosts=("HOST-B",), ts="2026-01-01T10:30:00+00:00"),  # diff host, 30min apart
    ]
    e = _edges(dets, tech)
    assert e == {}


def test_edges_multiple_relations_combined():
    tech = {"A": frozenset({"T1"}), "B": frozenset({"T1"})}  # same technique
    dets = [
        _det("A", hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00"),
        _det("B", hosts=("HOST-A",), ts="2026-01-01T10:10:00+00:00"),  # same host, same tech, close
    ]
    e = _edges(dets, tech)
    assert e == {frozenset({0, 1}): {"shared_host", "shared_technique", "temporal_adjacency"}}


def test_edges_no_relation_no_edge():
    tech = {"A": frozenset({"T1"}), "B": frozenset({"T2"})}
    dets = [
        _det("A", hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00"),
        _det("B", hosts=("HOST-B",), ts="2026-06-01T10:00:00+00:00"),
    ]
    assert _edges(dets, tech) == {}


def test_temporal_horizon_boundary():
    # Revision 1: temporal is a LABEL on an already-host-linked pair. Both share HOST-A (so there is
    # always an edge via host); the horizon governs only whether the temporal_adjacency label appears.
    tech = {"A": frozenset({"T1"}), "B": frozenset({"T2"})}  # technique disjoint -> host is the edge
    at = "2026-01-01T10:00:00+00:00"
    # exactly TEMPORAL_HORIZON_SECONDS apart -> temporal label present, alongside shared_host
    on_edge = _det("B", hosts=("HOST-A",), ts="2026-01-01T11:00:00+00:00")  # +3600s
    dets = [_det("A", hosts=("HOST-A",), ts=at), on_edge]
    e = _edges(dets, tech)
    assert e[frozenset({0, 1})] == {"shared_host", "temporal_adjacency"}
    # one second beyond -> still an edge via host, but NO temporal_adjacency label
    beyond = _det("B", hosts=("HOST-A",), ts="2026-01-01T11:00:01+00:00")  # +3601s
    dets2 = [_det("A", hosts=("HOST-A",), ts=at), beyond]
    e2 = _edges(dets2, tech)
    assert e2[frozenset({0, 1})] == {"shared_host"}


def test_temporal_empty_window_no_edge():
    tech = {"A": frozenset({"T1"}), "B": frozenset({"T2"})}
    a = _det("A", hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00")
    b = {"scenario_id": "B", "name": "S", "severity": "HIGH", "proximity": 1.0,
         "matched_steps": [], "affected_hosts": ["HOST-B"], "affected_zones": [], "hunting_queries": []}
    assert _edges([a, b], tech) == {}  # b has empty window -> no temporal edge; no host/tech overlap


def test_components_singletons_when_no_edges():
    assert _components(3, {}) == [[0], [1], [2]]


def test_components_merge_pair():
    comps = _components(3, {frozenset({0, 1}): {"shared_host"}})
    assert comps == [[0, 1], [2]]


def test_components_transitive_chain():
    # A-B via host, B-C via technique -> all three merge transitively
    edges = {frozenset({0, 1}): {"shared_host"}, frozenset({1, 2}): {"shared_technique"}}
    assert _components(3, edges) == [[0, 1, 2]]


def test_components_indices_and_order_deterministic():
    edges = {frozenset({2, 4}): {"shared_host"}, frozenset({0, 1}): {"shared_host"}}
    comps = _components(5, edges)
    # each component sorted ascending; components ordered by their min index ascending
    assert comps == [[0, 1], [2, 4], [3]]


def test_cluster_two_share_host_third_isolated():
    scens = [_scenario("A", technique="T1"), _scenario("B", technique="T2"),
             _scenario("C", technique="T3")]
    tech_disjoint_far = "2026-09-01T10:00:00+00:00"
    dets = [
        _det("A", hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00", severity="HIGH", proximity=1.0),
        _det("B", hosts=("HOST-A",), ts="2026-01-01T10:05:00+00:00", severity="MEDIUM", proximity=0.5),
        _det("C", hosts=("HOST-B",), ts=tech_disjoint_far, severity="LOW", proximity=0.5),
    ]
    out = cluster_incidents(dets, scens, _topo())
    incs = out["incidents"]
    assert len(incs) == 2
    big = incs[0]                      # highest score/size first
    assert big["size"] == 2
    assert {m["scenario_id"] for m in big["members"]} == {"A", "B"}
    assert big["incident_id"] == "INC-0001"
    small = incs[1]
    assert small["size"] == 1 and small["members"][0]["scenario_id"] == "C"
    assert small["incident_id"] == "INC-0002"


def test_relations_exposed_per_incident():
    scens = [_scenario("A", technique="T1"), _scenario("B", technique="T1")]
    dets = [
        _det("A", hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00"),
        _det("B", hosts=("HOST-A",), ts="2026-01-01T10:10:00+00:00"),
    ]
    out = cluster_incidents(dets, scens, _topo())
    assert out["incidents"][0]["relations"] == ["shared_host", "shared_technique", "temporal_adjacency"]


def test_severity_and_score_rollup():
    scens = [_scenario("A", technique="T1"), _scenario("B", technique="T1")]
    dets = [
        _det("A", hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00", severity="HIGH", proximity=1.0),
        _det("B", hosts=("HOST-A",), ts="2026-01-01T10:05:00+00:00", severity="CRITICAL", proximity=0.5),
    ]
    inc = cluster_incidents(dets, scens, _topo())["incidents"][0]
    assert inc["top_severity"] == "CRITICAL"
    assert inc["max_proximity"] == 1.0
    # score = round(sum(proximity * SEV_RANK), 4) = 1.0*3 + 0.5*4 = 5.0
    assert inc["score"] == 5.0


def test_hosts_topology_enriched_and_techniques_unioned():
    scens = [_scenario("A", technique="T1"), _scenario("B", technique="T2")]
    dets = [
        _det("A", hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00"),
        _det("B", hosts=("HOST-A", "HOST-B"), ts="2026-01-01T10:05:00+00:00"),
    ]
    inc = cluster_incidents(dets, scens, _topo())["incidents"][0]
    hosts = {h["hostname"]: h for h in inc["hosts"]}
    assert hosts["HOST-A"]["criticality"] == "CRITICAL"
    assert hosts["HOST-B"]["criticality"] == "LOW"
    assert inc["techniques"] == ["T1", "T2"]
    assert inc["first_ts"] == "2026-01-01T10:00:00+00:00"
    assert inc["last_ts"] == "2026-01-01T10:05:00+00:00"
    assert inc["honesty_note"] == HONESTY_NOTE


def test_rollup_shape():
    scens = [_scenario("A", technique="T1"), _scenario("B", technique="T1"),
             _scenario("C", technique="T9")]
    dets = [
        _det("A", hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00"),
        _det("B", hosts=("HOST-A",), ts="2026-01-01T10:05:00+00:00"),
        _det("C", hosts=("HOST-B",), ts="2026-09-01T10:00:00+00:00"),
    ]
    out = cluster_incidents(dets, scens, _topo())
    r = out["rollup"]
    assert r["incidents"] == 2
    assert r["clustered_detections"] == 2   # the A+B incident has 2 members
    assert r["singletons"] == 1
    assert r["largest_incident_size"] == 2
    assert r["detections_total"] == 3
    assert r["truncated"] is False
    assert r["honesty_note"] == HONESTY_NOTE


def test_empty_input_valid_empty_payload():
    out = cluster_incidents([], [_scenario("A")], _topo())
    assert out["incidents"] == []
    assert out["rollup"] == {
        "incidents": 0, "clustered_detections": 0, "singletons": 0,
        "largest_incident_size": 0, "detections_total": 0, "truncated": False,
        "honesty_note": HONESTY_NOTE,
    }


def test_malformed_detection_raises_valueerror():
    bad = [{"name": "no scenario_id"}]  # missing scenario_id
    with pytest.raises(ValueError):
        cluster_incidents(bad, [_scenario("A")], _topo())


def test_determinism_byte_identical_and_order_invariant():
    scens = [_scenario("A", technique="T1"), _scenario("B", technique="T1"),
             _scenario("C", technique="T9")]
    dets = [
        _det("A", hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00"),
        _det("B", hosts=("HOST-A",), ts="2026-01-01T10:05:00+00:00"),
        _det("C", hosts=("HOST-B",), ts="2026-09-01T10:00:00+00:00"),
    ]
    a = cluster_incidents(dets, scens, _topo())
    b = cluster_incidents(list(reversed(dets)), scens, _topo())
    # shuffled input -> identical incident_ids/ranking (total sort)
    assert json.dumps(a, sort_keys=False) == json.dumps(b, sort_keys=False)


def test_member_cap_sets_truncated_flag():
    # one incident with > MAX_MEMBERS_LISTED members (all share HOST-A + technique T1)
    scens = [_scenario(f"S{i:03d}", technique="T1") for i in range(MAX_MEMBERS_LISTED + 5)]
    dets = [_det(f"S{i:03d}", hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00")
            for i in range(MAX_MEMBERS_LISTED + 5)]
    inc = cluster_incidents(dets, scens, _topo())["incidents"][0]
    assert inc["size"] == MAX_MEMBERS_LISTED + 5          # true count
    assert len(inc["members"]) == MAX_MEMBERS_LISTED      # capped list
    assert inc["members_truncated"] is True


def test_detection_cap_sets_rollup_truncated():
    scens = [_scenario(f"S{i:04d}", technique=f"T{i}") for i in range(MAX_DETECTIONS + 3)]
    dets = [_det(f"S{i:04d}", hosts=(f"HOST-{i}",), ts="2026-01-01T10:00:00+00:00")
            for i in range(MAX_DETECTIONS + 3)]
    out = cluster_incidents(dets, scens, _topo())
    assert out["rollup"]["truncated"] is True
    assert out["rollup"]["detections_total"] == MAX_DETECTIONS  # capped count


def test_purity_no_engine_graph_networkx_now_random():
    src = Path("src/augur/api/incidents.py").read_text()
    tree = ast.parse(src)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert not any(m.startswith("augur.engine") for m in imported), \
        "incidents must not import engine internals (scoring/matcher/runner)"
    assert not any(m.startswith("augur.graph") for m in imported), \
        "incidents must not import a graph backend"
    assert not any(m.startswith("augur.normalize") for m in imported), \
        "incidents must not import a normalizer"
    assert "networkx" not in imported and not any(m.startswith("networkx") for m in imported), \
        "incidents must not import networkx"
    assert "random" not in imported
    assert ".now(" not in src and "utcnow" not in src
