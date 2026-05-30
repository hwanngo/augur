"""TDD: cidr-type IOC matching against network-connection (dest_ip) telemetry (Increment 5).

CIDR network is parsed ONCE per IOC (ipaddress.ip_network, strict=False) and tested for membership.
Pure stdlib, no event/model/simulator change — 203.0.113.0/24 already contains the synthetic dests.
"""
import json

import pytest

from augur.api.ioc import match_iocs, _EVENT_TYPES, _UNMATCHABLE
from augur.pipeline import default_topology

_H = "HR_User_PC"


def _netconn(ts, host=_H, dest_ip="203.0.113.10", dest_port=443):
    return {"source_type": "windows_sysmon", "event_id": 3, "timestamp": ts, "host": host,
            "process_guid": f"{host}:1001", "dest_ip": dest_ip, "dest_port": dest_port}


def _write_feed(tmp_path, lines):
    p = tmp_path / "feed.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in lines))
    return [str(p)]


def _topo():
    return default_topology()


def test_cidr_in_accepted_not_in_unmatchable():
    assert "cidr" in _EVENT_TYPES
    assert "cidr" not in _UNMATCHABLE


def test_cidr_v4_matches_member(tmp_path):
    feed = _write_feed(tmp_path, [_netconn("2026-01-01T09:00:00+00:00", dest_ip="203.0.113.10")])
    out = match_iocs([{"type": "cidr", "value": "203.0.113.0/24"}], feed, [], _topo(), [])
    r = out["iocs"][0]
    assert r["matched"] is True and r["hit_count"] == 1 and r["target"] == "event"
    assert r["hits"][0]["host"] == _H and r["hits"][0]["matched_field"] == "dest_ip"
    assert r["hits"][0]["snippet"] == "203.0.113.10"


def test_cidr_v4_non_member_misses(tmp_path):
    feed = _write_feed(tmp_path, [_netconn("2026-01-01T09:00:00+00:00", dest_ip="198.51.100.10")])
    out = match_iocs([{"type": "cidr", "value": "203.0.113.0/24"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is False and out["iocs"][0]["hit_count"] == 0


def test_cidr_malformed_raises(tmp_path):
    feed = _write_feed(tmp_path, [])
    with pytest.raises(ValueError):
        match_iocs([{"type": "cidr", "value": "203.0.113.0/99"}], feed, [], _topo(), [])
    with pytest.raises(ValueError):
        match_iocs([{"type": "cidr", "value": "not-a-cidr"}], feed, [], _topo(), [])


def test_cidr_bare_address_ressembles_host_32(tmp_path):
    # A /32 is a valid 1-host network and DOES match its own address (honest contract).
    feed = _write_feed(tmp_path, [_netconn("2026-01-01T09:00:00+00:00", dest_ip="203.0.113.10")])
    out = match_iocs([{"type": "cidr", "value": "203.0.113.10/32"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is True
