"""Increment 4 payoff: /api/ioc_match returns domain + ip hits on Linux AND macOS telemetry, not just
Windows. The hosts rollup spans all three OS families (via topology.enrich), with no change to ioc.py's
matching logic — only the data now carries the fields on all OSes.
"""
import json

from augur.api.ioc import match_iocs
from augur.pipeline import default_topology


def _write(tmp_path, raws):
    p = tmp_path / "feed.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in raws) + "\n")
    return [str(p)]


def _topo():
    return default_topology()


# Windows DNS (EID 22) + IP (EID 3)
def _win_dns(host="HR_User_PC"):
    return {"source_type": "windows_sysmon", "event_id": 22, "timestamp": "2026-01-01T09:00:00+00:00",
            "host": host, "process_guid": f"{host}:1", "query_name": "evil-c2.example.com"}


def _win_ip(host="HR_User_PC"):
    return {"source_type": "windows_sysmon", "event_id": 3, "timestamp": "2026-01-01T09:00:01+00:00",
            "host": host, "process_guid": f"{host}:1", "dest_ip": "203.0.113.10", "dest_port": 443}


# Linux DNS (EDR overlay) + IP (connect SYSCALL)
def _lnx_dns(host="CORP-JENKINS01"):
    return {"source_type": "linux_auditd", "type": "EDR", "behavior": "dns_query",
            "timestamp": "2026-01-01T09:00:02+00:00", "host": host, "pid": 2002,
            "query_name": "evil-c2.example.com"}


def _lnx_ip(host="CORP-JENKINS01"):
    return {"source_type": "linux_auditd", "type": "SYSCALL", "syscall": "connect",
            "timestamp": "2026-01-01T09:00:03+00:00", "host": host, "pid": 2001,
            "daddr": "203.0.113.10", "dport": 443}


# macOS DNS + IP (agent overlays)
def _mac_dns(host="DESIGN-MBP-07"):
    return {"source_type": "macos_esf", "event_type": "ES_AGENT_NOTIFY_DNS_QUERY",
            "timestamp": "2026-01-01T09:00:04+00:00", "host": host,
            "process": {"audit_token": f"{host}:3002"}, "query_name": "evil-c2.example.com"}


def _mac_ip(host="DESIGN-MBP-07"):
    return {"source_type": "macos_esf", "event_type": "ES_AGENT_NOTIFY_NETWORK_CONNECT",
            "timestamp": "2026-01-01T09:00:05+00:00", "host": host,
            "process": {"audit_token": f"{host}:3001"}, "dest_ip": "203.0.113.10", "dest_port": 443}


def test_domain_hits_on_all_three_os(tmp_path):
    feed = _write(tmp_path, [_win_dns(), _lnx_dns(), _mac_dns()])
    out = match_iocs([{"type": "domain", "value": "evil-c2.example.com"}], feed, [], _topo(), [])
    dom = next(r for r in out["iocs"] if r["type"] == "domain")
    assert dom["matched"] and dom["hit_count"] == 3
    hosts_hit = {h["host"] for h in dom["hits"]}
    assert hosts_hit == {"HR_User_PC", "CORP-JENKINS01", "DESIGN-MBP-07"}


def test_ip_hits_on_all_three_os(tmp_path):
    feed = _write(tmp_path, [_win_ip(), _lnx_ip(), _mac_ip()])
    out = match_iocs([{"type": "ip", "value": "203.0.113.10"}], feed, [], _topo(), [])
    ip = next(r for r in out["iocs"] if r["type"] == "ip")
    assert ip["matched"] and ip["hit_count"] == 3
    hosts_hit = {h["host"] for h in ip["hits"]}
    assert hosts_hit == {"HR_User_PC", "CORP-JENKINS01", "DESIGN-MBP-07"}


def test_hosts_rollup_spans_three_os(tmp_path):
    feed = _write(tmp_path, [_win_dns(), _lnx_dns(), _mac_dns(), _win_ip(), _lnx_ip(), _mac_ip()])
    out = match_iocs(
        [{"type": "domain", "value": "evil-c2.example.com"}, {"type": "ip", "value": "203.0.113.10"}],
        feed, [], _topo(), [])
    rollup = {h["hostname"] for h in out["hosts"]}
    assert {"HR_User_PC", "CORP-JENKINS01", "DESIGN-MBP-07"} <= rollup
    # every rolled-up host carries an enriched zone + criticality (topology authoritative)
    for h in out["hosts"]:
        assert h["zone"] and h["criticality"]
        assert set(h["types"]) <= {"domain", "ip"}
