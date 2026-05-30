"""Increment 4: macOS gains network_connect + dns_query via explicit agent overlays.

Stable ESF has NO socket-connect or DNS NOTIFY event — modern agents synthesize both via a Network
Extension. We model these as clearly-named agent event types (NOT real ES_EVENT_TYPE_* NOTIFY).
"""
from augur.normalize.macos_esf import normalize


def _connect(ts="2026-01-01T09:00:01+00:00", host="DESIGN-MBP-07",
             dest_ip="203.0.113.10", dest_port=443, pid=3001):
    return {"source_type": "macos_esf", "event_type": "ES_AGENT_NOTIFY_NETWORK_CONNECT",
            "timestamp": ts, "host": host,
            "process": {"audit_token": f"{host}:{pid}"},
            "dest_ip": dest_ip, "dest_port": dest_port}


def _dns(ts="2026-01-01T09:00:02+00:00", host="DESIGN-MBP-07",
         query="evil-c2.example.com", pid=3002):
    return {"source_type": "macos_esf", "event_type": "ES_AGENT_NOTIFY_DNS_QUERY",
            "timestamp": ts, "host": host,
            "process": {"audit_token": f"{host}:{pid}"},
            "query_name": query}


def test_macos_agent_connect_maps_to_network_connect():
    ev = normalize(_connect())
    assert ev is not None
    assert ev.kind == "network_connect"
    assert ev.dest_ip == "203.0.113.10"
    assert ev.dest_port == 443
    assert ev.host == "DESIGN-MBP-07"
    assert ev.process_guid == "DESIGN-MBP-07:3001"
    assert ev.os_family == "macos"


def test_macos_agent_dns_maps_to_dns_query():
    ev = normalize(_dns())
    assert ev is not None
    assert ev.kind == "dns_query"
    assert ev.domain == "evil-c2.example.com"
    assert ev.host == "DESIGN-MBP-07"
    assert ev.process_guid == "DESIGN-MBP-07:3002"
    assert ev.os_family == "macos"


def test_macos_exec_and_mmap_still_normalize():
    exec_raw = {"source_type": "macos_esf", "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
                "timestamp": "2026-01-01T09:00:00+00:00", "host": "DESIGN-MBP-07",
                "process": {"executable": {"path": "/usr/bin/curl"}, "audit_token": "DESIGN-MBP-07:1"},
                "event": {"exec": {"args": ["curl"]}}}
    ev = normalize(exec_raw)
    assert ev.kind == "process_create" and ev.process_name == "curl"


from datetime import datetime, timezone

from augur.simulator.emitters import emit
from augur.simulator.intents import EventIntent


def test_macos_emitter_network_connect_round_trips():
    intent = EventIntent(kind="network_connect", host="DESIGN-MBP-07",
                         timestamp=datetime(2026, 1, 1, 9, 0, 1, tzinfo=timezone.utc),
                         pid=3001, dest_ip="203.0.113.10", dest_port=443)
    raw = emit("macos", intent)
    assert raw["event_type"] == "ES_AGENT_NOTIFY_NETWORK_CONNECT"
    assert raw["dest_ip"] == "203.0.113.10" and raw["dest_port"] == 443
    ev = normalize(raw)
    assert ev.kind == "network_connect" and ev.dest_ip == "203.0.113.10" and ev.dest_port == 443


def test_macos_emitter_dns_query_round_trips():
    intent = EventIntent(kind="dns_query", host="DESIGN-MBP-07",
                         timestamp=datetime(2026, 1, 1, 9, 0, 2, tzinfo=timezone.utc),
                         pid=3002, domain="evil-c2.example.com")
    raw = emit("macos", intent)
    assert raw["event_type"] == "ES_AGENT_NOTIFY_DNS_QUERY"
    assert raw["query_name"] == "evil-c2.example.com"
    ev = normalize(raw)
    assert ev.kind == "dns_query" and ev.domain == "evil-c2.example.com"
