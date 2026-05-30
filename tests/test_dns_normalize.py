"""TDD: Sysmon EID 22 (DnsQuery) -> dns_query kind carrying an inert `domain` field (Increment 2).

A new event KIND must NOT crash windows_sysmon.normalize (it RAISES on unknown EIDs), and a mixed
corpus including EID 22 must load. `domain` is inert: the matcher never reads it.
"""
from datetime import datetime, timezone

from augur.normalize.model import NormalizedEvent


def test_normalized_event_has_inert_domain_field():
    ev = NormalizedEvent(
        timestamp=datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc),
        kind="dns_query", host="HR_User_PC", event_id=22, domain="update.microsoft.com",
    )
    assert ev.domain == "update.microsoft.com"


def test_normalized_event_domain_defaults_none():
    ev = NormalizedEvent(
        timestamp=datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc),
        kind="process_create", host="HR_User_PC", event_id=1,
    )
    assert ev.domain is None


import pytest

from augur.normalize.windows_sysmon import normalize as win_normalize
from augur.normalize.registry import normalize_events


def _dns_raw(ts="2026-01-01T09:00:00+00:00", host="HR_User_PC", query="update.microsoft.com"):
    return {"source_type": "windows_sysmon", "event_id": 22, "timestamp": ts, "host": host,
            "process_guid": "HR_User_PC:1001", "query_name": query}


def test_eid22_normalizes_to_dns_query_without_raising():
    ev = win_normalize(_dns_raw())
    assert ev.kind == "dns_query"
    assert ev.domain == "update.microsoft.com"
    assert ev.host == "HR_User_PC"
    assert ev.process_guid == "HR_User_PC:1001"
    assert ev.event_id == 22


def test_unknown_eid_still_raises():
    with pytest.raises(ValueError):
        win_normalize({"event_id": 999, "timestamp": "2026-01-01T09:00:00+00:00", "host": "h"})


def test_mixed_corpus_including_eid22_loads():
    raws = [
        {"source_type": "windows_sysmon", "event_id": 1, "timestamp": "2026-01-01T09:00:00+00:00",
         "host": "HR_User_PC", "process_guid": "HR_User_PC:1", "process_name": "chrome.exe",
         "process_path": "C:\\x\\chrome.exe", "command_line": "chrome.exe"},
        _dns_raw(ts="2026-01-01T09:00:05+00:00"),
    ]
    evs = normalize_events(raws)
    assert len(evs) == 2
    assert {e.kind for e in evs} == {"process_create", "dns_query"}


from datetime import timedelta

from augur.simulator.intents import EventIntent
from augur.simulator.emitters import emit


def test_windows_emitter_emits_eid22_dns_query_roundtrips():
    intent = EventIntent(kind="dns_query", host="HR_User_PC",
                         timestamp=datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc),
                         pid=1001, domain="ctldl.windowsupdate.com")
    raw = emit("windows", intent)
    assert raw["event_id"] == 22
    assert raw["query_name"] == "ctldl.windowsupdate.com"
    assert raw["source_type"] == "windows_sysmon"
    assert raw["host"] == "HR_User_PC"
    # round-trips through the normalizer to a dns_query carrying the domain
    ev = win_normalize(raw)
    assert ev.kind == "dns_query" and ev.domain == "ctldl.windowsupdate.com"
    assert ev.process_guid == "HR_User_PC:1001"


from augur.simulator.baseline import generate_baseline, DEMO_BAD_DOMAINS, BENIGN_DOMAINS
from augur.simulator.config import SimConfig
from augur.simulator.profiles import MachineProfile
from augur.normalize.registry import normalize_events as _norm_all


def _win_lnx_profiles():
    return [MachineProfile("HR_User_PC", "windows", ["alice"]),
            MachineProfile("CORP-JENKINS01", "linux", ["jenkins"])]


def test_baseline_emits_multi_os_dns_events():
    cfg = SimConfig(seed=7, duration_seconds=600, rate_per_minute=12)
    base = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    raws = generate_baseline(_win_lnx_profiles(), cfg, base)
    # Windows DNS: native Sysmon EID 22
    win_dns = [r for r in raws if r.get("event_id") == 22]
    assert win_dns and all(r["host"] == "HR_User_PC" for r in win_dns)
    assert all(r.get("query_name") for r in win_dns)
    # Linux DNS: EDR overlay record (auditd does not resolve DNS)
    lnx_dns = [r for r in raws if r.get("type") == "EDR" and r.get("behavior") == "dns_query"]
    assert lnx_dns and all(r["host"] == "CORP-JENKINS01" for r in lnx_dns)
    assert all(r.get("query_name") for r in lnx_dns)


def test_baseline_dns_is_deterministic_under_fixed_seed():
    cfg = SimConfig(seed=7, duration_seconds=600, rate_per_minute=12)
    base = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    a = [r for r in generate_baseline(_win_lnx_profiles(), cfg, base) if r.get("event_id") == 22]
    b = [r for r in generate_baseline(_win_lnx_profiles(), cfg, base) if r.get("event_id") == 22]
    assert a == b


def test_baseline_dns_includes_a_demo_bad_domain():
    cfg = SimConfig(seed=7, duration_seconds=600, rate_per_minute=12)
    base = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    raws = generate_baseline(_win_lnx_profiles(), cfg, base)
    queried = {r["query_name"] for r in raws if r.get("event_id") == 22}
    assert queried & set(DEMO_BAD_DOMAINS), "a demo-bad domain must be queried so a watchlist can hit"
    assert queried & set(BENIGN_DOMAINS), "benign domains must also be present"


def test_baseline_dns_events_normalize_cleanly():
    cfg = SimConfig(seed=7, duration_seconds=600, rate_per_minute=12)
    base = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    raws = generate_baseline(_win_lnx_profiles(), cfg, base)
    evs = _norm_all(raws)  # must not raise on the EID-22 events
    assert any(e.kind == "dns_query" and e.domain for e in evs)
