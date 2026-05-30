"""TDD: ipv6-type IOC matching against network-connection (dest_ip) telemetry (Increment 5).

Canonical comparison: both sides normalized via ipaddress.ip_address(x).compressed so
2001:0db8:0000:0000:0000:0000:0000:0010 matches 2001:db8::10. Also proves the engine stays blind to
the new v6 network_connect events (graph-equality guard, mirror of test_engine_ignores_netconn.py).
"""
import json
from datetime import datetime, timezone

from augur.api.ioc import match_iocs, _EVENT_TYPES, _UNMATCHABLE
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.normalize.model import NormalizedEvent
from augur.pipeline import default_topology

_H = "HR_User_PC"


def _netconn(ts, host=_H, dest_ip="2001:db8::dead:10", dest_port=443):
    return {"source_type": "windows_sysmon", "event_id": 3, "timestamp": ts, "host": host,
            "process_guid": f"{host}:1001", "dest_ip": dest_ip, "dest_port": dest_port}


def _write_feed(tmp_path, lines):
    p = tmp_path / "feed.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in lines))
    return [str(p)]


def _topo():
    return default_topology()


def test_ipv6_in_accepted_not_in_unmatchable():
    assert "ipv6" in _EVENT_TYPES
    assert "ipv6" not in _UNMATCHABLE


def test_ipv6_exact_match(tmp_path):
    feed = _write_feed(tmp_path, [_netconn("2026-01-01T09:00:00+00:00", dest_ip="2001:db8::dead:10")])
    out = match_iocs([{"type": "ipv6", "value": "2001:db8::dead:10"}], feed, [], _topo(), [])
    r = out["iocs"][0]
    assert r["matched"] is True and r["hit_count"] == 1
    assert r["hits"][0]["matched_field"] == "dest_ip"
    assert r["hits"][0]["snippet"] == "2001:db8::dead:10"


def test_ipv6_canonical_form_match(tmp_path):
    # Event carries the expanded form; IOC carries the compressed form -> canonical compare matches.
    feed = _write_feed(tmp_path, [_netconn("2026-01-01T09:00:00+00:00",
                                            dest_ip="2001:0db8:0000:0000:0000:0000:0000:0010")])
    out = match_iocs([{"type": "ipv6", "value": "2001:db8::10"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is True and out["iocs"][0]["hit_count"] == 1


def test_ipv6_non_member_misses(tmp_path):
    feed = _write_feed(tmp_path, [_netconn("2026-01-01T09:00:00+00:00", dest_ip="2001:db8::1")])
    out = match_iocs([{"type": "ipv6", "value": "2001:db8::2"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is False


def test_cidr_v6_matches_member(tmp_path):
    # A v6 CIDR works through the SAME cidr branch (ip_network handles v4 and v6 uniformly).
    feed = _write_feed(tmp_path, [_netconn("2026-01-01T09:00:00+00:00", dest_ip="2001:db8::dead:10")])
    out = match_iocs([{"type": "cidr", "value": "2001:db8::/32"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is True and out["iocs"][0]["hit_count"] == 1


def _ts(s):
    return datetime(2026, 1, 1, 9, 0, s, tzinfo=timezone.utc)


def _proc(guid="HR_User_PC:1", name="chrome.exe"):
    return NormalizedEvent(timestamp=_ts(0), kind="process_create", host="HR_User_PC", event_id=1,
                           process_guid=guid, process_name=name, process_path="C:\\x\\" + name,
                           command_line=name, parent_process_guid="HR_User_PC:0")


def _nc6():
    return NormalizedEvent(timestamp=_ts(1), kind="network_connect", host="HR_User_PC", event_id=3,
                           process_guid="HR_User_PC:1", dest_ip="2001:db8::dead:10", dest_port=443)


def _snapshot(backend):
    g = backend._g
    nodes = sorted(g.nodes())
    edges = sorted((u, v, d.get("edge_type")) for u, v, d in g.edges(data=True))
    return nodes, edges


def test_engine_blind_to_v6_netconn_events():
    """Graph-equality guard: a corpus WITH v6 network_connect events yields the SAME graph as the same
    corpus without them — the engine is structurally blind to the new v6 dests."""
    topo = default_topology()
    with_v6 = [_proc(), _nc6(), _proc(guid="HR_User_PC:2", name="outlook.exe")]
    without_v6 = [_proc(), _proc(guid="HR_User_PC:2", name="outlook.exe")]

    b1 = NetworkXBackend()
    build_graph(with_v6, topo, b1)
    b2 = NetworkXBackend()
    build_graph(without_v6, topo, b2)
    assert _snapshot(b1) == _snapshot(b2)
