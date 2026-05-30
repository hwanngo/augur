"""Increment 4: Linux auditd gains network_connect (connect SYSCALL) and dns_query (EDR overlay).

The connect SYSCALL must NOT collide with the existing image_load SYSCALL branch (which keys on
`raw["name"]`). connect keys on `syscall == "connect"` + `daddr`/`dport`. The DNS overlay rides the
existing EDR record type with `behavior == "dns_query"` carrying `query_name`.
"""
from augur.normalize.linux_auditd import normalize


def _connect(ts="2026-01-01T09:00:01+00:00", host="CORP-JENKINS01",
             daddr="203.0.113.10", dport=443, pid=2001):
    return {"source_type": "linux_auditd", "type": "SYSCALL", "syscall": "connect",
            "timestamp": ts, "host": host, "pid": pid, "daddr": daddr, "dport": dport}


def _image_load(ts="2026-01-01T09:00:02+00:00", host="CORP-JENKINS01", pid=2002,
                name="/usr/lib/x86_64-linux-gnu/libssl.so.3"):
    return {"source_type": "linux_auditd", "type": "SYSCALL", "syscall": "openat",
            "timestamp": ts, "host": host, "pid": pid, "name": name}


def test_connect_syscall_maps_to_network_connect():
    ev = normalize(_connect())
    assert ev is not None
    assert ev.kind == "network_connect"
    assert ev.dest_ip == "203.0.113.10"
    assert ev.dest_port == 443
    assert ev.host == "CORP-JENKINS01"
    assert ev.process_guid == "CORP-JENKINS01:2001"
    assert ev.os_family == "linux"
    assert ev.source_type == "linux_auditd"


def test_image_load_syscall_still_maps_to_image_load():
    ev = normalize(_image_load())
    assert ev is not None
    assert ev.kind == "image_load"
    assert ev.image_loaded == "/usr/lib/x86_64-linux-gnu/libssl.so.3"
    assert ev.dest_ip is None and ev.dest_port is None


def test_connect_and_image_load_disambiguate_in_one_pass():
    evs = [normalize(_connect()), normalize(_image_load())]
    kinds = [e.kind for e in evs]
    assert kinds == ["network_connect", "image_load"]


def _dns_overlay(ts="2026-01-01T09:00:03+00:00", host="CORP-JENKINS01",
                 query="evil-c2.example.com", pid=2003):
    return {"source_type": "linux_auditd", "type": "EDR", "behavior": "dns_query",
            "timestamp": ts, "host": host, "pid": pid, "query_name": query}


def _behavior_overlay(ts="2026-01-01T09:00:04+00:00", host="CORP-JENKINS01", pid=2004):
    return {"source_type": "linux_auditd", "type": "EDR", "behavior": "credential_access",
            "timestamp": ts, "host": host, "pid": pid, "target": "/etc/shadow"}


def test_dns_edr_overlay_maps_to_dns_query():
    ev = normalize(_dns_overlay())
    assert ev is not None
    assert ev.kind == "dns_query"
    assert ev.domain == "evil-c2.example.com"
    assert ev.host == "CORP-JENKINS01"
    assert ev.process_guid == "CORP-JENKINS01:2003"
    assert ev.os_family == "linux"


def test_non_dns_edr_overlay_still_maps_to_behavior():
    ev = normalize(_behavior_overlay())
    assert ev is not None
    assert ev.kind == "behavior"
    assert ev.behavior == "credential_access"
    assert ev.target == "/etc/shadow"
    assert ev.domain is None


from datetime import datetime, timezone

from augur.simulator.emitters import emit
from augur.simulator.intents import EventIntent


def test_linux_emitter_network_connect_round_trips():
    intent = EventIntent(kind="network_connect", host="CORP-JENKINS01",
                         timestamp=datetime(2026, 1, 1, 9, 0, 1, tzinfo=timezone.utc),
                         pid=2001, dest_ip="203.0.113.10", dest_port=443)
    raw = emit("linux", intent)
    assert raw["type"] == "SYSCALL" and raw["syscall"] == "connect"
    assert raw["daddr"] == "203.0.113.10" and raw["dport"] == 443
    assert raw["source_type"] == "linux_auditd"
    ev = normalize(raw)
    assert ev.kind == "network_connect" and ev.dest_ip == "203.0.113.10" and ev.dest_port == 443


def test_linux_emitter_dns_query_round_trips():
    intent = EventIntent(kind="dns_query", host="CORP-JENKINS01",
                         timestamp=datetime(2026, 1, 1, 9, 0, 3, tzinfo=timezone.utc),
                         pid=2003, domain="evil-c2.example.com")
    raw = emit("linux", intent)
    assert raw["type"] == "EDR" and raw["behavior"] == "dns_query"
    assert raw["query_name"] == "evil-c2.example.com"
    ev = normalize(raw)
    assert ev.kind == "dns_query" and ev.domain == "evil-c2.example.com"
