"""Invariant 6 guard (Increment 4): the engine is STRUCTURALLY BLIND to the NEW Linux + macOS
dns_query / network_connect records — same recipe as test_engine_ignores_dns/_netconn, extended to
the new OS sources.

build_graph dispatches only process_create/image_load/behavior; dns_query/network_connect have no
branch and are dropped regardless of OS. A graph built from a corpus WITH the new Linux/macOS netintel
records equals the graph built from the same corpus WITHOUT them. domain/dest_ip/dest_port are in no
criteria field map, so the matcher can never read them either.
"""
from datetime import datetime, timezone

from augur.engine.criteria import PROCESS_KEY_MAP, FILE_KEY_MAP
from augur.normalize.linux_auditd import normalize as lnx
from augur.normalize.macos_esf import normalize as mac
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.pipeline import default_topology


def test_dest_and_domain_absent_from_criteria_field_maps():
    for fld in ("dest_ip", "dest_port", "domain", "daddr", "dport", "query_name"):
        assert fld not in PROCESS_KEY_MAP and fld not in PROCESS_KEY_MAP.values()
        assert fld not in FILE_KEY_MAP and fld not in FILE_KEY_MAP.values()


def _ts(s):
    return "2026-01-01T09:00:0%d+00:00" % s


def _lnx_proc(pid=2000):
    return {"source_type": "linux_auditd", "type": "EXECVE", "timestamp": _ts(0),
            "host": "CORP-JENKINS01", "pid": pid, "ppid": 1, "exe": "/usr/bin/curl", "comm": "curl"}


def _lnx_connect():
    return {"source_type": "linux_auditd", "type": "SYSCALL", "syscall": "connect", "timestamp": _ts(1),
            "host": "CORP-JENKINS01", "pid": 2001, "daddr": "203.0.113.10", "dport": 443}


def _lnx_dns():
    return {"source_type": "linux_auditd", "type": "EDR", "behavior": "dns_query", "timestamp": _ts(2),
            "host": "CORP-JENKINS01", "pid": 2002, "query_name": "evil-c2.example.com"}


def _mac_proc(pid=3000):
    return {"source_type": "macos_esf", "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC", "timestamp": _ts(0),
            "host": "DESIGN-MBP-07", "process": {"executable": {"path": "/usr/bin/curl"},
            "audit_token": "DESIGN-MBP-07:%d" % pid}, "event": {"exec": {"args": ["curl"]}}}


def _mac_connect():
    return {"source_type": "macos_esf", "event_type": "ES_AGENT_NOTIFY_NETWORK_CONNECT", "timestamp": _ts(1),
            "host": "DESIGN-MBP-07", "process": {"audit_token": "DESIGN-MBP-07:3001"},
            "dest_ip": "203.0.113.10", "dest_port": 443}


def _mac_dns():
    return {"source_type": "macos_esf", "event_type": "ES_AGENT_NOTIFY_DNS_QUERY", "timestamp": _ts(2),
            "host": "DESIGN-MBP-07", "process": {"audit_token": "DESIGN-MBP-07:3002"},
            "query_name": "evil-c2.example.com"}


def _norm(raws):
    out = []
    for r in raws:
        n = lnx(r) if r["source_type"] == "linux_auditd" else mac(r)
        if n is not None:
            out.append(n)
    return sorted(out, key=lambda e: e.timestamp)


def _snapshot(backend):
    g = backend._g
    nodes = sorted(g.nodes())
    edges = sorted((u, v, d.get("edge_type")) for u, v, d in g.edges(data=True))
    return nodes, edges


def test_graph_identical_with_and_without_new_netintel_records():
    topo = default_topology()
    with_ni = _norm([_lnx_proc(), _lnx_connect(), _lnx_dns(),
                     _mac_proc(), _mac_connect(), _mac_dns()])
    without_ni = _norm([_lnx_proc(), _mac_proc()])

    b1 = NetworkXBackend()
    build_graph(with_ni, topo, b1)
    b2 = NetworkXBackend()
    build_graph(without_ni, topo, b2)

    assert _snapshot(b1) == _snapshot(b2)


def test_detectability_stays_40_of_40():
    from augur.metrics.detectability import detectability
    from augur.pipeline import default_scenarios, default_topology
    rep = detectability(default_scenarios(), default_topology())
    assert rep["total"] == 40
    assert rep["detectable"] == 40
    assert rep["detectability_rate"] == 1.0
