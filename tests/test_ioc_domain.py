"""TDD: domain-type IOC matching for windows_sysmon DNS (EID 22) telemetry only (Increment 2)."""
import json

from augur.api.ioc import match_iocs, HONESTY_NOTE, _EVENT_TYPES, _UNMATCHABLE
from augur.pipeline import default_topology

_H = "HR_User_PC"


def _dns(ts, host=_H, query="evil-c2.example.com"):
    return {"source_type": "windows_sysmon", "event_id": 22, "timestamp": ts, "host": host,
            "process_guid": f"{host}:1001", "query_name": query}


def _linux_proc(ts, host="CORP-JENKINS01"):
    return {"source_type": "linux_auditd", "timestamp": ts, "host": host, "type": "EXECVE",
            "pid": 10, "ppid": 1, "uid": "deploy", "exe": "/usr/bin/curl", "comm": "curl", "a0": "curl"}


def _write_feed(tmp_path, lines):
    p = tmp_path / "feed.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in lines))
    return [str(p)]


def _topo():
    return default_topology()


def test_domain_in_accepted_not_in_unmatchable():
    assert "domain" in _EVENT_TYPES
    assert "domain" not in _UNMATCHABLE


def test_domain_matches_known_queried_domain(tmp_path):
    feed = _write_feed(tmp_path, [_dns("2026-01-01T09:00:00+00:00", query="evil-c2.example.com")])
    out = match_iocs([{"type": "domain", "value": "evil-c2.example.com"}], feed, [], _topo(), [])
    r = out["iocs"][0]
    assert r["matched"] is True and r["hit_count"] == 1 and r["target"] == "event"
    assert r["hits"][0]["host"] == _H and r["hits"][0]["matched_field"] == "domain"
    assert r["hits"][0]["snippet"] == "evil-c2.example.com"


def test_domain_case_insensitive(tmp_path):
    feed = _write_feed(tmp_path, [_dns("2026-01-01T09:00:00+00:00", query="evil-c2.example.com")])
    out = match_iocs([{"type": "domain", "value": "EVIL-C2.EXAMPLE.COM"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is True


def test_domain_clean_miss(tmp_path):
    feed = _write_feed(tmp_path, [_dns("2026-01-01T09:00:00+00:00", query="update.microsoft.com")])
    out = match_iocs([{"type": "domain", "value": "never-queried.example.org"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is False and out["iocs"][0]["hit_count"] == 0


def test_domain_exact_not_substring(tmp_path):
    # v1 is EXACT host match only — a registrable-suffix watchlist does NOT match a subdomain query.
    feed = _write_feed(tmp_path, [_dns("2026-01-01T09:00:00+00:00", query="evil-c2.example.com")])
    out = match_iocs([{"type": "domain", "value": "example.com"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is False


def test_domain_never_matches_linux_event(tmp_path):
    # Linux events carry no domain -> a domain IOC can never hit them.
    feed = _write_feed(tmp_path, [_linux_proc("2026-01-01T09:00:00+00:00")])
    out = match_iocs([{"type": "domain", "value": "evil-c2.example.com"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is False


def test_ip_accepted_domain_accepted(tmp_path):
    # ip is now accepted (Increment 3); domain remains accepted (clean miss, not a raise).
    for good, val in (("ip", "203.0.113.99"), ("domain", "x.example.com")):
        out = match_iocs([{"type": good, "value": val}], _write_feed(tmp_path, []), [], _topo(), [])
        assert out["iocs"][0]["matched"] is False and out["iocs"][0]["type"] == good


def test_domain_honesty_note(tmp_path):
    feed = _write_feed(tmp_path, [_dns("2026-01-01T09:00:00+00:00")])
    out = match_iocs([{"type": "domain", "value": "x.example.com"}], feed, [], _topo(), [])
    note = out["summary"]["honesty_note"]
    assert note == HONESTY_NOTE
    assert "synthetic" in note.lower()
    assert "NOT evaluated" not in note  # ip is now evaluated (Increment 3)
    assert "RFC 5737" in note           # the new connection-telemetry caveat
    assert "Windows" in note
