"""Invariant 6 guard: the engine is STRUCTURALLY BLIND to the new `dns_query` kind AND `domain` field.

Two-layer proof:
  1. FIELD blindness — `domain` is in NEITHER criteria field map, so node_matches can never read it.
  2. KIND blindness — build_graph's closed if/elif/elif over process_create/image_load/behavior drops
     `dns_query` entirely: a corpus WITH dns_query events yields the SAME nodes/edges as the same corpus
     with the DNS events stripped. The matcher only enumerates Process/File nodes + EXHIBITED edges, so
     its input is byte-identical.
Plus: detectability stays 40/40 (the engine sees identical input).
"""
from datetime import datetime, timezone

from augur.engine.criteria import PROCESS_KEY_MAP, FILE_KEY_MAP
from augur.normalize.model import NormalizedEvent
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.pipeline import default_topology


def test_domain_absent_from_criteria_field_maps():
    assert "domain" not in PROCESS_KEY_MAP.values()
    assert "domain" not in FILE_KEY_MAP.values()
    assert "domain" not in PROCESS_KEY_MAP and "domain" not in FILE_KEY_MAP
    assert "Domain" not in PROCESS_KEY_MAP and "Domain" not in FILE_KEY_MAP
    assert "QueryName" not in PROCESS_KEY_MAP and "QueryName" not in FILE_KEY_MAP


def _ts(s):
    return datetime(2026, 1, 1, 9, 0, s, tzinfo=timezone.utc)


def _proc(guid="HR_User_PC:1", name="chrome.exe"):
    return NormalizedEvent(timestamp=_ts(0), kind="process_create", host="HR_User_PC", event_id=1,
                           process_guid=guid, process_name=name, process_path="C:\\x\\" + name,
                           command_line=name, parent_process_guid="HR_User_PC:0")


def _dns(domain="evil.example.com"):
    return NormalizedEvent(timestamp=_ts(1), kind="dns_query", host="HR_User_PC", event_id=22,
                           process_guid="HR_User_PC:1", domain=domain)


def _snapshot(backend):
    """A comparable (nodes, edges) snapshot of the backend's graph state."""
    g = backend._g  # NetworkXBackend wraps a networkx MultiDiGraph in `._g`
    nodes = sorted(g.nodes())
    edges = sorted((u, v, d.get("edge_type")) for u, v, d in g.edges(data=True))
    return nodes, edges


def test_build_graph_ignores_dns_events():
    topo = default_topology()
    with_dns = [_proc(), _dns(), _proc(guid="HR_User_PC:2", name="outlook.exe")]
    without_dns = [_proc(), _proc(guid="HR_User_PC:2", name="outlook.exe")]

    b1 = NetworkXBackend()
    build_graph(with_dns, topo, b1)
    b2 = NetworkXBackend()
    build_graph(without_dns, topo, b2)

    assert _snapshot(b1) == _snapshot(b2)


def test_detectability_stays_40_of_40():
    from augur.metrics.detectability import detectability
    from augur.pipeline import default_scenarios, default_topology
    rep = detectability(default_scenarios(), default_topology())
    assert rep["total"] == 40
    assert rep["detectable"] == 40
    assert rep["detectability_rate"] == 1.0
