"""Behavior-branch if-absent ProcessNode upsert.

A behavior event whose actor has NO preceding process_create (EID 1) — the real-data condition where
the actor process predates the capture window — must now still yield a Process node, so its EXHIBITED
edge attaches to a real node and the matcher can find it.
"""
from datetime import datetime, timezone

from augur.normalize.model import NormalizedEvent
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.models import ProcessNode
from augur.pipeline import default_topology


def _ts(s):
    return datetime(2026, 6, 3, 10, 0, s, tzinfo=timezone.utc)


def _behavior_no_create(guid="{ps-orphan}"):
    return NormalizedEvent(
        timestamp=_ts(5), kind="behavior", host="CORP-WKS-0421", event_id=10,
        process_guid=guid, behavior="ProcessAccess", target="lsass.exe", granted_access="0x1010",
    )


def test_orphan_behavior_actor_gets_a_process_node():
    topo = default_topology()
    backend = NetworkXBackend()
    build_graph([_behavior_no_create()], topo, backend)

    node = backend.get_node("{ps-orphan}")
    assert isinstance(node, ProcessNode)
    assert node.host == "CORP-WKS-0421"
    assert node.name is None          # behavior event carries no source name
    assert node.timestamp == _ts(5)
    # the EXHIBITED self-edge exists and carries the access attrs
    edges = backend.edges_from("{ps-orphan}", "EXHIBITED")
    assert len(edges) == 1
    assert edges[0].attrs["target"] == "lsass.exe"
    assert edges[0].attrs["granted_access"] == "0x1010"
    # host_of resolves via name-fallback (no RUNS_ON edge) so topology owns the zone
    host = backend.host_of("{ps-orphan}")
    assert host is not None and host.hostname == "CORP-WKS-0421"


def _behavior_with_prior_create(guid="{ps-real}"):
    """A synthetic-style pair: process_create (EID 1) THEN a behavior event for the SAME guid."""
    create = NormalizedEvent(
        timestamp=_ts(0), kind="process_create", host="CORP-WKS-0421", event_id=1,
        process_guid=guid, process_name="powershell.exe",
        process_path="C:\\x\\powershell.exe", command_line="powershell.exe",
        parent_process_guid="CORP-WKS-0421:0")
    behave = NormalizedEvent(
        timestamp=_ts(5), kind="behavior", host="CORP-WKS-0421", event_id=10,
        process_guid=guid, behavior="ProcessAccess", target="lsass.exe", granted_access="0x1010")
    return [create, behave]


def test_behavior_upsert_noop_on_synthetic():
    """When a behavior actor ALREADY has a process_create, the if-absent upsert is inert:
    exactly ONE Process node for that guid (the original create's), name preserved, no overwrite."""
    topo = default_topology()
    backend = NetworkXBackend()
    build_graph(_behavior_with_prior_create(), topo, backend)

    procs = backend.find_nodes("Process", lambda n: n.id == "{ps-real}")
    assert len(procs) == 1                       # no duplicate node materialized
    assert procs[0].name == "powershell.exe"     # original create's node, NOT overwritten to None
    # the EXHIBITED edge still attaches to that single node
    assert len(backend.edges_from("{ps-real}", "EXHIBITED")) == 1


def test_detectability_stays_40_of_40_with_upsert_live():
    """The hard gate, re-asserted with the upsert always live."""
    from augur.metrics.detectability import detectability
    from augur.pipeline import default_scenarios, default_topology
    rep = detectability(default_scenarios(), default_topology())
    assert rep["total"] == 40
    assert rep["detectable"] == 40
    assert rep["detectability_rate"] == 1.0
