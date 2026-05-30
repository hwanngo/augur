from datetime import datetime, timezone
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.models import HostNode, ProcessNode, FileNode
from augur.enums import Zone, Criticality

T = datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc)


def _backend():
    b = NetworkXBackend()
    b.add_host(HostNode(id="h", hostname="HR_User_PC", ip="1", os="o",
                        zone=Zone.User_Endpoint, criticality=Criticality.MEDIUM))
    b.add_process(ProcessNode(id="p1", name="evil.exe", path="C:\\t.exe", command_line="x",
                              parent_guid=None, parent_process_name=None, host="HR_User_PC", timestamp=T))
    b.add_file(FileNode(id="f1", name="x.dll", path="C:\\x.dll", extension=".dll", is_signed=False,
                        is_injected=True, api_hooking_detected=False, host="HR_User_PC", timestamp=T))
    b.add_edge("p1", "h", "RUNS_ON", T)
    b.add_edge("p1", "f1", "LOADED", T, is_injected=True)
    b.add_edge("p1", "p1", "EXHIBITED", T, behavior="lsass_access", target="lsass.exe", granted_access="0x1410")
    return b


def test_find_nodes_by_type_and_predicate():
    b = _backend()
    procs = b.find_nodes("Process", lambda n: n.name == "evil.exe")
    assert [p.id for p in procs] == ["p1"]
    files = b.find_nodes("File", lambda n: n.is_injected)
    assert [f.id for f in files] == ["f1"]


def test_edges_from_filtered():
    b = _backend()
    loaded = b.edges_from("p1", "LOADED")
    assert loaded[0].dst_id == "f1" and loaded[0].attrs["is_injected"] is True
    exhibited = b.edges_from("p1", "EXHIBITED")
    assert exhibited[0].attrs["behavior"] == "lsass_access"


def test_host_of_resolves_process_and_file():
    b = _backend()
    assert b.host_of("p1").hostname == "HR_User_PC"
    assert b.host_of("f1").hostname == "HR_User_PC"


def test_reset_clears():
    b = _backend()
    b.reset()
    assert b.find_nodes("Process", lambda n: True) == []


def test_edges_to_incoming_spawned_and_runs_on():
    b = _backend()
    # add a parent that SPAWNED p1
    b.add_process(ProcessNode(id="p0", name="parent.exe", path="C:\\p.exe", command_line="y",
                              parent_guid=None, parent_process_name=None, host="HR_User_PC", timestamp=T))
    b.add_edge("p0", "p1", "SPAWNED", T)
    # incoming SPAWNED to p1 -> parent reachable
    incoming = b.edges_to("p1", "SPAWNED")
    assert [e.src_id for e in incoming] == ["p0"]
    assert incoming[0].dst_id == "p1" and incoming[0].edge_type == "SPAWNED"
    # host reachable via incoming RUNS_ON (p1 -> h)
    runs_on = b.edges_to("h", "RUNS_ON")
    assert [e.src_id for e in runs_on] == ["p1"]
    # unfiltered: all incoming edges of p1 (SPAWNED from p0, EXHIBITED self-loop)
    all_in = b.edges_to("p1")
    assert {e.edge_type for e in all_in} == {"SPAWNED", "EXHIBITED"}
    # filter excludes non-matching types: p1 has no incoming LOADED edge
    assert b.edges_to("p1", "LOADED") == []


def test_edges_to_sorted_by_timestamp_then_src():
    from datetime import timedelta
    b = _backend()
    b.add_process(ProcessNode(id="pA", name="a", path="a", command_line="a",
                              parent_guid=None, parent_process_name=None, host="HR_User_PC", timestamp=T))
    b.add_process(ProcessNode(id="pB", name="b", path="b", command_line="b",
                              parent_guid=None, parent_process_name=None, host="HR_User_PC", timestamp=T))
    b.add_edge("pB", "h", "RUNS_ON", T)                       # same ts as pA's RUNS_ON below
    b.add_edge("pA", "h", "RUNS_ON", T)
    b.add_edge("pA", "h", "RUNS_ON", T + timedelta(seconds=5))  # later ts -> sorts last
    got = [(e.src_id, e.timestamp) for e in b.edges_to("h", "RUNS_ON")]
    # same-ts group sorts by src_id (p1 < pA < pB); the +5s edge from pA is last
    assert got == sorted(got, key=lambda x: (x[1].timestamp(), x[0]))
    assert got[-1] == ("pA", T + timedelta(seconds=5))


def test_edges_to_missing_node_returns_empty():
    b = _backend()
    assert b.edges_to("does-not-exist") == []
