"""TDD: ip-type IOC matching for windows_sysmon network-connection (EID 3) telemetry only (Increment 3).

Exact dest-IP string match. 203.0.113.10 is the canonical synthetic C2 IP. ipv6/CIDR stay rejected.
"""
import json

import pytest

from augur.api.ioc import match_iocs, HONESTY_NOTE, _EVENT_TYPES, _UNMATCHABLE
from augur.pipeline import default_topology

_H = "HR_User_PC"


def _netconn(ts, host=_H, dest_ip="203.0.113.10", dest_port=443):
    return {"source_type": "windows_sysmon", "event_id": 3, "timestamp": ts, "host": host,
            "process_guid": f"{host}:1001", "dest_ip": dest_ip, "dest_port": dest_port}


def _linux_proc(ts, host="CORP-JENKINS01"):
    return {"source_type": "linux_auditd", "timestamp": ts, "host": host, "type": "EXECVE",
            "pid": 10, "ppid": 1, "uid": "deploy", "exe": "/usr/bin/curl", "comm": "curl", "a0": "curl"}


def _macos_proc(ts, host="MAC-DESIGN01"):
    return {"source_type": "macos_esf", "timestamp": ts, "host": host,
            "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC", "user": "designer",
            "process": {"executable": {"path": "/usr/bin/curl"}, "audit_token": f"{host}:1"},
            "event": {"exec": {"args": ["curl"]}}}


def _write_feed(tmp_path, lines):
    p = tmp_path / "feed.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in lines))
    return [str(p)]


def _topo():
    return default_topology()


def test_ip_in_accepted_not_in_unmatchable():
    assert "ip" in _EVENT_TYPES
    assert "ip" not in _UNMATCHABLE


def test_ip_matches_known_dest_ip(tmp_path):
    feed = _write_feed(tmp_path, [_netconn("2026-01-01T09:00:00+00:00", dest_ip="203.0.113.10")])
    out = match_iocs([{"type": "ip", "value": "203.0.113.10"}], feed, [], _topo(), [])
    r = out["iocs"][0]
    assert r["matched"] is True and r["hit_count"] == 1 and r["target"] == "event"
    assert r["hits"][0]["host"] == _H and r["hits"][0]["matched_field"] == "dest_ip"
    assert r["hits"][0]["snippet"] == "203.0.113.10"


def test_ip_exact_match_near_miss_misses(tmp_path):
    feed = _write_feed(tmp_path, [_netconn("2026-01-01T09:00:00+00:00", dest_ip="203.0.113.10")])
    out = match_iocs([{"type": "ip", "value": "203.0.113.11"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is False and out["iocs"][0]["hit_count"] == 0


def test_ip_clean_miss(tmp_path):
    feed = _write_feed(tmp_path, [_netconn("2026-01-01T09:00:00+00:00", dest_ip="192.0.2.10")])
    out = match_iocs([{"type": "ip", "value": "203.0.113.99"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is False and out["iocs"][0]["hit_count"] == 0


def test_ip_never_matches_linux_or_macos_event(tmp_path):
    # Linux/macOS events carry no dest_ip -> an ip IOC can never hit them.
    feed = _write_feed(tmp_path, [_linux_proc("2026-01-01T09:00:00+00:00"),
                                  _macos_proc("2026-01-01T09:00:01+00:00")])
    out = match_iocs([{"type": "ip", "value": "203.0.113.10"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is False


def test_ipv6_now_matchable(tmp_path):
    # ipv6 is now an accepted type — canonical compare against synthetic v6 dests.
    feed = _write_feed(tmp_path, [_netconn("2026-01-01T09:00:00+00:00", dest_ip="2001:db8::dead:10")])
    out = match_iocs([{"type": "ipv6", "value": "2001:db8::dead:10"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is True and out["iocs"][0]["hit_count"] == 1


def test_cidr_matches(tmp_path):
    # CIDR is now an accepted type — 203.0.113.0/24 contains the canonical synthetic C2 dest.
    feed = _write_feed(tmp_path, [_netconn("2026-01-01T09:00:00+00:00", dest_ip="203.0.113.10")])
    out = match_iocs([{"type": "cidr", "value": "203.0.113.0/24"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is True and out["iocs"][0]["hit_count"] == 1


def test_ip_honesty_note(tmp_path):
    feed = _write_feed(tmp_path, [_netconn("2026-01-01T09:00:00+00:00")])
    out = match_iocs([{"type": "ip", "value": "203.0.113.10"}], feed, [], _topo(), [])
    note = out["summary"]["honesty_note"]
    assert note == HONESTY_NOTE
    assert "RFC 5737" in note
    assert "synthetic" in note.lower()
    assert "Windows" in note
    assert "NOT evaluated" not in note  # ip IS now evaluated; the old "ip NOT evaluated" clause is gone
