"""TDD: build_pivot_graph — pure, deterministic, bounded k-hop neighborhood from a detection."""
from datetime import datetime, timezone, timedelta

import pytest

from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.models import HostNode, ProcessNode, FileNode
from augur.enums import Zone, Criticality
from augur.topology.network import Topology, Asset
from augur.api.pivot_graph import build_pivot_graph, MAX_NODES, MAX_EDGES, HONESTY_NOTE

T = datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc)


def _topology(hostname="WS-FIN-07"):
    # One known asset; anything else off-topology -> Unknown/UNKNOWN via enrich().
    return Topology(zones=[Zone.User_Endpoint],
                    assets=[Asset(hostname=hostname, ip="10.0.0.7", os="windows",
                                  zone=Zone.User_Endpoint, criticality=Criticality.HIGH)])


def _backend(hostname="WS-FIN-07"):
    """p0 -SPAWNED-> p1 -SPAWNED-> p2 ; p1 -LOADED-> f1(injected) ; p1 -EXHIBITED-> p1 ; all RUNS_ON host."""
    b = NetworkXBackend()
    hid = hostname.lower()
    b.add_host(HostNode(id=hid, hostname=hostname, ip="10.0.0.7", os="windows",
                        zone=Zone.User_Endpoint, criticality=Criticality.HIGH))
    for pid, name in [("p0", "parent.exe"), ("p1", "evil.exe"), ("p2", "child.exe")]:
        b.add_process(ProcessNode(id=pid, name=name, path=f"C:\\{name}", command_line=name,
                                  parent_guid=None, parent_process_name=None, host=hostname,
                                  timestamp=T, integrity_level="High"))
        b.add_edge(pid, hid, "RUNS_ON", T)
    b.add_file(FileNode(id="f1", name="x.dll", path="C:\\x.dll", extension=".dll", is_signed=False,
                        is_injected=True, api_hooking_detected=False, host=hostname, timestamp=T))
    b.add_edge("p0", "p1", "SPAWNED", T)
    b.add_edge("p1", "p2", "SPAWNED", T)
    b.add_edge("p1", "f1", "LOADED", T, is_injected=True)
    b.add_edge("p1", "p1", "EXHIBITED", T, behavior="lsass_access", target="lsass.exe")
    return b


def _detection(element_ids, hostname="WS-FIN-07"):
    return {
        "scenario_id": "SCEN-WIN-001", "name": "Pass-the-Hash", "severity": "CRITICAL",
        "affected_hosts": [hostname],
        "matched_steps": [{"step_id": i + 1, "name": f"step{i+1}", "element_id": eid,
                           "host": hostname, "timestamp": T.isoformat()}
                          for i, eid in enumerate(element_ids)],
    }


def test_seed_subgraph_marks_seed_and_hop0():
    res = build_pivot_graph(_detection(["p1"]), _backend(), _topology(), hops=1)
    by_id = {n["id"]: n for n in res["nodes"]}
    assert by_id["p1"]["seed"] is True and by_id["p1"]["hop"] == 0
    assert res["seed"]["seed_node_ids"] == ["p1"]
    # host always added for a seed; hop on host is 1 (a neighbor), not 0
    assert "ws-fin-07" in by_id
    assert by_id["ws-fin-07"]["node_type"] == "Host"


def test_exh_element_id_resolves_to_owning_process():
    # behavior step element_id is synthetic "p1|EXH|3" -> resolves to process p1
    res = build_pivot_graph(_detection(["p1|EXH|3"]), _backend(), _topology(), hops=1)
    assert res["seed"]["seed_node_ids"] == ["p1"]
    by_id = {n["id"]: n for n in res["nodes"]}
    assert by_id["p1"]["seed"] is True and by_id["p1"]["hop"] == 0
    assert "p1|EXH|3" not in by_id   # synthetic id never becomes a node


def test_one_hop_pulls_parent_files_host():
    res = build_pivot_graph(_detection(["p1"]), _backend(), _topology(), hops=1)
    ids = {n["id"] for n in res["nodes"]}
    assert {"p1", "p0", "p2", "f1", "ws-fin-07"} <= ids   # parent(in SPAWNED), child(out SPAWNED), file, host
    etypes = {e["edge_type"] for e in res["edges"]}
    assert {"SPAWNED", "LOADED", "RUNS_ON"} <= etypes
    # LOADED edge carries is_injected from attrs
    loaded = next(e for e in res["edges"] if e["edge_type"] == "LOADED")
    assert loaded["is_injected"] is True


def test_two_hops_reaches_grandparent_and_siblings():
    # seed p2; 1-hop = p1 (parent) + host; 2-hop reaches p0 (grandparent) and f1 (uncle file via p1)
    res = build_pivot_graph(_detection(["p2"]), _backend(), _topology(), hops=2)
    ids = {n["id"] for n in res["nodes"]}
    assert {"p2", "p1", "p0", "f1"} <= ids
    by_id = {n["id"]: n for n in res["nodes"]}
    assert by_id["p2"]["hop"] == 0
    assert by_id["p1"]["hop"] == 1
    assert by_id["p0"]["hop"] == 2


def test_node_carries_criticality_and_zone_from_topology():
    res = build_pivot_graph(_detection(["p1"]), _backend(), _topology(), hops=1)
    by_id = {n["id"]: n for n in res["nodes"]}
    assert by_id["p1"]["criticality"] == "HIGH" and by_id["p1"]["zone"] == "User_Endpoint"


def test_off_topology_host_is_unknown():
    # backend host "ROGUE-PC" is NOT in topology -> enrich() returns Unknown/UNKNOWN
    res = build_pivot_graph(_detection(["p1"], hostname="ROGUE-PC"),
                            _backend(hostname="ROGUE-PC"), _topology("WS-FIN-07"), hops=1)
    by_id = {n["id"]: n for n in res["nodes"]}
    assert by_id["p1"]["criticality"] == "UNKNOWN" and by_id["p1"]["zone"] == "Unknown"


def test_deterministic_identical_dicts():
    a = build_pivot_graph(_detection(["p1"]), _backend(), _topology(), hops=2)
    b = build_pivot_graph(_detection(["p1"]), _backend(), _topology(), hops=2)
    assert a == b


def test_hops_clamped_1_to_3():
    lo = build_pivot_graph(_detection(["p1"]), _backend(), _topology(), hops=0)
    assert lo["summary"]["hops"] == 1
    hi = build_pivot_graph(_detection(["p1"]), _backend(), _topology(), hops=5)
    assert hi["summary"]["hops"] == 3


def test_bad_detection_raises_valueerror():
    # no resolvable seed node id at all (all synthetic, no owning process in graph)
    with pytest.raises(ValueError):
        build_pivot_graph(_detection(["ghost|EXH|1"]), _backend(), _topology(), hops=1)


def test_node_and_edge_caps_truncate_with_honest_totals():
    # Build a parent PROCESS that SPAWNED > MAX_NODES child processes; seed from the parent.
    # This exercises the cap via edges_from(parent) fan-out (Process is non-terminal in BFS).
    b = NetworkXBackend()
    hid = "hub"
    b.add_host(HostNode(id=hid, hostname="HUB", ip="1", os="o",
                        zone=Zone.User_Endpoint, criticality=Criticality.LOW))
    parent_id = "parent_proc"
    b.add_process(ProcessNode(id=parent_id, name="parent", path="parent", command_line="parent",
                              parent_guid=None, parent_process_name=None, host="HUB",
                              timestamp=T, integrity_level="Low"))
    b.add_edge(parent_id, hid, "RUNS_ON", T)
    n = MAX_NODES + 50
    for i in range(n):
        pid = f"p{i:04d}"
        b.add_process(ProcessNode(id=pid, name=pid, path=pid, command_line=pid,
                                  parent_guid=None, parent_process_name=None, host="HUB",
                                  timestamp=T + timedelta(seconds=i), integrity_level="Low"))
        b.add_edge(pid, hid, "RUNS_ON", T + timedelta(seconds=i))
        b.add_edge(parent_id, pid, "SPAWNED", T + timedelta(seconds=i))
    topo = Topology(zones=[Zone.User_Endpoint],
                    assets=[Asset(hostname="HUB", ip="1", os="o",
                                  zone=Zone.User_Endpoint, criticality=Criticality.LOW)])
    det = {"scenario_id": "S", "name": "n", "severity": "LOW", "affected_hosts": ["HUB"],
           "matched_steps": [{"step_id": 1, "name": "s", "element_id": parent_id,
                              "host": "HUB", "timestamp": T.isoformat()}]}
    res = build_pivot_graph(det, b, topo, hops=1)
    assert res["summary"]["nodes_truncated"] is True
    assert res["summary"]["node_count"] == MAX_NODES
    assert res["summary"]["nodes_total"] >= n + 1            # honest total discovered (children + parent + host)
    # every emitted edge has both endpoints in the kept node set
    kept = {nn["id"] for nn in res["nodes"]}
    assert all(e["src"] in kept and e["dst"] in kept for e in res["edges"])
    assert res["summary"]["edge_count"] <= MAX_EDGES


def test_honesty_note_verbatim_and_no_reachability_claim():
    res = build_pivot_graph(_detection(["p1"]), _backend(), _topology(), hops=1)
    assert res["summary"]["honesty_note"] == HONESTY_NOTE
    assert "NOT network reachability" in res["summary"]["honesty_note"]


def test_file_seed_host_present_at_hops_1():
    """Fix 2 (spec §6.1): seeding from a File node at hops=1 must include the seed's host.

    A FileNode has no outgoing RUNS_ON edge, so BFS alone would not reach its host within
    1 hop.  The explicit host-injection introduced in Fix 1 closes this gap.
    """
    b = _backend()
    # f1 is a FileNode; its host is WS-FIN-07 (id "ws-fin-07")
    det = _detection(["f1"])
    res = build_pivot_graph(det, b, _topology(), hops=1)
    by_id = {n["id"]: n for n in res["nodes"]}
    assert "f1" in by_id, "seed file should be present"
    assert by_id["f1"]["seed"] is True and by_id["f1"]["hop"] == 0
    # The host must be present — this would FAIL without Fix 1
    assert "ws-fin-07" in by_id, "seed file's host must be present even at hops=1"
    assert by_id["ws-fin-07"]["node_type"] == "Host"


def test_pivot_touches_implicit_node():
    """Regression lock: implicit nodes (add_edge to a never-add_node'd parent id) must not crash.

    NetworkX creates a stub graph node when add_edge references an id that was never
    add_node'd — those stubs have no 'obj' attribute so get_node() returns None.
    build_pivot_graph must skip them silently (try_add_node returns False) rather than
    raising AttributeError / NoneType errors.
    """
    b = NetworkXBackend()
    hostname = "WS-FIN-07"
    hid = hostname.lower()
    b.add_host(HostNode(id=hid, hostname=hostname, ip="10.0.0.7", os="windows",
                        zone=Zone.User_Endpoint, criticality=Criticality.HIGH))
    # p1 is properly added
    b.add_process(ProcessNode(id="p1", name="evil.exe", path="C:\\evil.exe",
                              command_line="evil.exe", parent_guid=None,
                              parent_process_name=None, host=hostname,
                              timestamp=T, integrity_level="High"))
    b.add_edge("p1", hid, "RUNS_ON", T)
    # "ghost_parent" is NEVER add_node'd — it becomes an implicit NetworkX stub node
    # (no 'obj' key).  This mirrors builder.py adding a SPAWNED edge for a parent_process_guid
    # that never appeared in the log as a process_create event (e.g. HR_User_PC:1, DMZ-WEB02:1).
    b.add_edge("ghost_parent", "p1", "SPAWNED", T)

    topo = _topology(hostname)
    det = _detection(["p1"], hostname=hostname)
    # Must not raise; BFS will discover "ghost_parent" as a neighbor but try_add_node skips it.
    result = build_pivot_graph(det, b, topo, hops=3)
    assert result["summary"]["node_count"] >= 1
    node_ids = {n["id"] for n in result["nodes"]}
    assert "p1" in node_ids
    # ghost_parent has no obj -> skipped; must NOT appear in result nodes
    assert "ghost_parent" not in node_ids


def test_node_cap_drops_same_nodes_deterministically():
    """Fix 3 (cap determinism): two calls on the same >MAX_NODES parent-process fan-out return identical node-id lists.

    Uses a parent PROCESS that SPAWNED > MAX_NODES children (edges_from fan-out, not a host hub)
    so the cap is exercised via the Process expansion path (hosts are terminal in BFS now).
    """
    b = NetworkXBackend()
    hid = "hub"
    b.add_host(HostNode(id=hid, hostname="HUB", ip="1", os="o",
                        zone=Zone.User_Endpoint, criticality=Criticality.LOW))
    parent_id = "parent_proc"
    b.add_process(ProcessNode(id=parent_id, name="parent", path="parent", command_line="parent",
                              parent_guid=None, parent_process_name=None, host="HUB",
                              timestamp=T, integrity_level="Low"))
    b.add_edge(parent_id, hid, "RUNS_ON", T)
    n = MAX_NODES + 50
    for i in range(n):
        pid = f"p{i:04d}"
        b.add_process(ProcessNode(id=pid, name=pid, path=pid, command_line=pid,
                                  parent_guid=None, parent_process_name=None, host="HUB",
                                  timestamp=T + timedelta(seconds=i), integrity_level="Low"))
        b.add_edge(pid, hid, "RUNS_ON", T + timedelta(seconds=i))
        b.add_edge(parent_id, pid, "SPAWNED", T + timedelta(seconds=i))
    topo = Topology(zones=[Zone.User_Endpoint],
                    assets=[Asset(hostname="HUB", ip="1", os="o",
                                  zone=Zone.User_Endpoint, criticality=Criticality.LOW)])
    det = {"scenario_id": "S", "name": "n", "severity": "LOW", "affected_hosts": ["HUB"],
           "matched_steps": [{"step_id": 1, "name": "s", "element_id": parent_id,
                              "host": "HUB", "timestamp": T.isoformat()}]}
    res1 = build_pivot_graph(det, b, topo, hops=1)
    res2 = build_pivot_graph(det, b, topo, hops=1)
    ids1 = [nn["id"] for nn in res1["nodes"]]
    ids2 = [nn["id"] for nn in res2["nodes"]]
    assert ids1 == ids2, "cap must drop the same nodes on every run (determinism)"
    assert len(ids1) == MAX_NODES


def test_host_does_not_fan_out_to_coresident_processes():
    """Host nodes are terminal context — co-resident processes (RUNS_ON only) must NOT appear.

    Build a host with:
      - seed_proc: the seed process (RUNS_ON host)
      - co0..co4: five unrelated co-resident processes (RUNS_ON host only; no SPAWNED/LOADED link
        to seed_proc)

    At hops=2, BFS from seed_proc reaches the host at hop=1 via the explicit §6.1 injection and
    via seed_proc's own RUNS_ON edge.  Because HostNode is terminal, the BFS does NOT follow
    edges_to(host) and therefore does NOT discover co0..co4 via the host hub.
    The host itself IS present; the co-residents are NOT.
    """
    b = NetworkXBackend()
    hostname = "BUSY-HOST"
    hid = hostname.lower()
    b.add_host(HostNode(id=hid, hostname=hostname, ip="10.1.1.1", os="linux",
                        zone=Zone.User_Endpoint, criticality=Criticality.LOW))
    # Seed process
    b.add_process(ProcessNode(id="seed_proc", name="seed.sh", path="/bin/seed.sh",
                              command_line="seed.sh", parent_guid=None, parent_process_name=None,
                              host=hostname, timestamp=T, integrity_level="Low"))
    b.add_edge("seed_proc", hid, "RUNS_ON", T)
    # Co-resident processes — linked to the host ONLY, not to seed_proc
    for i in range(5):
        cid = f"co{i}"
        b.add_process(ProcessNode(id=cid, name=f"co{i}.sh", path=f"/bin/co{i}.sh",
                                  command_line=f"co{i}.sh", parent_guid=None,
                                  parent_process_name=None, host=hostname,
                                  timestamp=T + timedelta(seconds=i + 1), integrity_level="Low"))
        b.add_edge(cid, hid, "RUNS_ON", T + timedelta(seconds=i + 1))

    topo = Topology(zones=[Zone.User_Endpoint],
                    assets=[Asset(hostname=hostname, ip="10.1.1.1", os="linux",
                                  zone=Zone.User_Endpoint, criticality=Criticality.LOW)])
    det = {"scenario_id": "S-CO", "name": "co-resident test", "severity": "LOW",
           "affected_hosts": [hostname],
           "matched_steps": [{"step_id": 1, "name": "s", "element_id": "seed_proc",
                               "host": hostname, "timestamp": T.isoformat()}]}
    res = build_pivot_graph(det, b, topo, hops=2)
    node_ids = {n["id"] for n in res["nodes"]}

    # Host is present (reached via seed_proc's RUNS_ON + explicit §6.1 injection)
    assert hid in node_ids, "seed's host must be present"
    # Co-resident processes are NOT present (host is terminal — no edges_to fan-out)
    for i in range(5):
        assert f"co{i}" not in node_ids, f"co-resident co{i} must NOT be reachable via host"
