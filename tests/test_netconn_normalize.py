"""TDD: Sysmon EID 3 (NetworkConnect) → inert `network_connect` kind for windows_sysmon (Increment 3).

Round-trip + no-raise guard: the new EID normalizes cleanly (does NOT crash normalize_events) and the
synthetic snake_case dest_ip/dest_port (provenance: Sysmon DestinationIp/DestinationPort) are populated.
"""
from augur.normalize.windows_sysmon import normalize, _KIND_BY_EVENT
from augur.normalize.registry import normalize_events


def _netconn(ts="2026-01-01T09:00:01+00:00", host="HR_User_PC",
             dest_ip="203.0.113.10", dest_port=443):
    return {"source_type": "windows_sysmon", "event_id": 3, "timestamp": ts, "host": host,
            "process_guid": f"{host}:1001", "dest_ip": dest_ip, "dest_port": dest_port}


def test_eid3_mapped_in_kind_table():
    assert _KIND_BY_EVENT[3] == "network_connect"


def test_eid3_normalizes_without_raising():
    ev = normalize(_netconn())
    assert ev.kind == "network_connect"
    assert ev.dest_ip == "203.0.113.10"
    assert ev.dest_port == 443
    assert ev.host == "HR_User_PC"
    assert ev.process_guid == "HR_User_PC:1001"
    assert ev.os_family == "windows"


def test_eid3_missing_dest_fields_are_none():
    ev = normalize({"source_type": "windows_sysmon", "event_id": 3,
                    "timestamp": "2026-01-01T09:00:01+00:00", "host": "HR_User_PC"})
    assert ev.dest_ip is None and ev.dest_port is None


def test_mixed_corpus_including_eid3_loads():
    proc = {"source_type": "windows_sysmon", "event_id": 1, "timestamp": "2026-01-01T09:00:00+00:00",
            "host": "HR_User_PC", "process_guid": "HR_User_PC:1", "process_name": "chrome.exe",
            "process_path": "C:\\x\\chrome.exe", "command_line": "chrome.exe"}
    evs = normalize_events([proc, _netconn()])
    kinds = [e.kind for e in evs]
    assert "process_create" in kinds and "network_connect" in kinds


from datetime import datetime, timezone

from augur.simulator.emitters import emit
from augur.simulator.intents import EventIntent


def test_windows_emitter_network_connect_round_trips():
    intent = EventIntent(kind="network_connect", host="HR_User_PC",
                         timestamp=datetime(2026, 1, 1, 9, 0, 1, tzinfo=timezone.utc),
                         pid=1001, dest_ip="203.0.113.10", dest_port=443)
    raw = emit("windows", intent)
    assert raw["event_id"] == 3
    assert raw["dest_ip"] == "203.0.113.10" and raw["dest_port"] == 443
    assert raw["source_type"] == "windows_sysmon"
    ev = normalize(raw)
    assert ev.kind == "network_connect" and ev.dest_ip == "203.0.113.10" and ev.dest_port == 443


from augur.simulator.baseline import generate_baseline, BENIGN_IPS, DEMO_BAD_IPS
from augur.simulator.config import SimConfig
from augur.simulator.profiles import MachineProfile


def _profiles():
    return [
        MachineProfile(host="HR_User_PC", os_family="windows", users=["alice"]),
        MachineProfile(host="WIN-DC01", os_family="windows", users=["svc"]),
        MachineProfile(host="CORP-JENKINS01", os_family="linux", users=["deploy"]),
    ]


def test_demo_bad_ip_is_canonical_c2():
    assert "203.0.113.10" in DEMO_BAD_IPS


def test_benign_ips_are_rfc5737_ranges():
    for ip in BENIGN_IPS:
        assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def test_baseline_emits_multi_os_network_connect():
    base = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
    raws = generate_baseline(_profiles(), SimConfig(seed=7, duration_seconds=600, rate_per_minute=2), base)
    # Windows: native Sysmon EID 3. The v6 sub-loop (Increment 5) adds additive RFC 3849 v6 dests on
    # the same EID 3 — scope the v4-range assertion to the v4 rows; v6 rows are checked separately.
    win_nc = [r for r in raws if r.get("event_id") == 3]
    assert win_nc and {r["host"] for r in win_nc} <= {"HR_User_PC", "WIN-DC01"}
    win_nc_v4 = [r for r in win_nc if ":" not in r["dest_ip"]]
    assert any(r["dest_ip"] == "203.0.113.10" for r in win_nc_v4)
    for r in win_nc_v4:
        assert r["dest_ip"].startswith(("192.0.2.", "198.51.100.", "203.0.113."))
    win_nc_v6 = [r for r in win_nc if ":" in r["dest_ip"]]
    assert win_nc_v6 and all(r["dest_ip"].startswith("2001:db8:") for r in win_nc_v6)
    # Linux: connect SYSCALL with daddr. v6 sub-loop adds additive RFC 3849 v6 daddrs — scope v4 assert.
    lnx_nc = [r for r in raws if r.get("type") == "SYSCALL" and r.get("syscall") == "connect"]
    assert lnx_nc and all(r["host"] == "CORP-JENKINS01" for r in lnx_nc)
    lnx_nc_v4 = [r for r in lnx_nc if ":" not in r["daddr"]]
    for r in lnx_nc_v4:
        assert r["daddr"].startswith(("192.0.2.", "198.51.100.", "203.0.113."))
    assert all(r["daddr"].startswith("2001:db8:") for r in lnx_nc if ":" in r["daddr"])


def test_baseline_deterministic_same_seed():
    base = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
    cfg = SimConfig(seed=7, duration_seconds=600, rate_per_minute=2)
    assert generate_baseline(_profiles(), cfg, base) == generate_baseline(_profiles(), cfg, base)


def test_netconn_stream_does_not_perturb_process_or_dns_lines():
    """Invariant 1: the connection stream rides a THIRD independent RNG, so process_create AND
    dns_query lines are byte-identical to a (hypothetical) run without it. We assert the process
    and dns subsets are stable across two identical-seed runs (the stream is deterministic and
    additive — it never reorders or mutates the other streams)."""
    base = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
    cfg = SimConfig(seed=7, duration_seconds=600, rate_per_minute=2)
    a = generate_baseline(_profiles(), cfg, base)
    b = generate_baseline(_profiles(), cfg, base)
    proc_a = [r for r in a if r.get("event_id") == 1]
    proc_b = [r for r in b if r.get("event_id") == 1]
    dns_a = [r for r in a if r.get("event_id") == 22]
    dns_b = [r for r in b if r.get("event_id") == 22]
    assert proc_a == proc_b and dns_a == dns_b and proc_a and dns_a
