"""TDD: IOC / Threat-Intel overlay matcher (infra-free, deterministic, read-only)."""
import pytest
from augur.api.ioc import match_iocs, MAX_HITS_PER_IOC, HONESTY_NOTE


def _write_feed(tmp_path, lines):
    import json
    p = tmp_path / "feed.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in lines))
    return [str(p)]


def _topo():
    from augur.pipeline import default_topology
    return default_topology()


def _proc(ts, host, proc, cmd=""):
    return {"timestamp": ts, "host": host, "event_id": 1, "process_guid": "{g}",
            "process_name": proc, "process_path": f"C:\\\\{proc}", "command_line": cmd or f"{proc} -x"}


class _Mitre:
    def __init__(self, t): self.technique = t
class _Meta:
    def __init__(self, t): self.mitre_mappings = [_Mitre(t)]
class _Scen:
    def __init__(self, sid, t): self.scenario_id = sid; self.scenario_metadata = _Meta(t)


def _scens():
    return [_Scen("SCEN-A", "T1003.001"), _Scen("SCEN-B", "T1059.001")]


def _dets(*sids_prox):
    return [{"scenario_id": s, "name": s + "-name", "severity": "HIGH", "proximity": p,
             "affected_hosts": ["HR_User_PC"]} for s, p in sids_prox]


_H = "HR_User_PC"


def test_process_name_exact_case_insensitive(tmp_path):
    feed = _write_feed(tmp_path, [_proc("2026-01-01T09:00:00+00:00", _H, "PowerShell.exe")])
    out = match_iocs([{"type": "process_name", "value": "powershell.exe"}], feed, [], _topo(), [])
    r = out["iocs"][0]
    assert r["matched"] is True and r["hit_count"] == 1 and r["target"] == "event"
    assert r["hits"][0]["host"] == _H and r["hits"][0]["matched_field"] == "process_name"


def test_command_substring(tmp_path):
    feed = _write_feed(tmp_path, [_proc("2026-01-01T09:00:00+00:00", _H, "p.exe", "x Invoke-Kerberoast y")])
    out = match_iocs([{"type": "command", "value": "invoke-kerberoast"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is True and out["iocs"][0]["hits"][0]["matched_field"] == "command_line"


def test_no_match(tmp_path):
    feed = _write_feed(tmp_path, [_proc("2026-01-01T09:00:00+00:00", _H, "p.exe")])
    out = match_iocs([{"type": "process_name", "value": "nope.exe"}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is False and out["iocs"][0]["hit_count"] == 0
    assert out["summary"]["iocs_matched"] == 0 and out["summary"]["hosts_touched"] == 0


def test_technique_covered_and_fired(tmp_path):
    out = match_iocs([{"type": "technique", "value": "T1003.001"}], _write_feed(tmp_path, []),
                     _scens(), _topo(), _dets(("SCEN-A", 1.0)))
    r = out["iocs"][0]
    assert r["target"] == "scenario" and r["covered"] is True and r["matched"] is True
    assert r["hits"][0]["scenario_id"] == "SCEN-A" and r["hits"][0]["proximity"] == 1.0


def test_technique_covered_not_fired(tmp_path):
    out = match_iocs([{"type": "technique", "value": "T1059.001"}], _write_feed(tmp_path, []),
                     _scens(), _topo(), _dets(("SCEN-A", 1.0)))
    r = out["iocs"][0]
    assert r["covered"] is True and r["matched"] is False and r["hits"] == []


def test_technique_uncovered(tmp_path):
    out = match_iocs([{"type": "technique", "value": "T9999"}], _write_feed(tmp_path, []),
                     _scens(), _topo(), [])
    assert out["iocs"][0]["covered"] is False and out["iocs"][0]["matched"] is False


def test_hosts_rollup_enriched(tmp_path):
    feed = _write_feed(tmp_path, [_proc("2026-01-01T09:00:00+00:00", _H, "powershell.exe", "x mimikatz y")])
    out = match_iocs([{"type": "process_name", "value": "powershell.exe"},
                      {"type": "command", "value": "mimikatz"}], feed, [], _topo(), [])
    assert out["summary"]["hosts_touched"] == 1
    h = out["hosts"][0]
    assert h["hostname"] == _H and h["ioc_count"] == 2 and h["zone"] and h["criticality"]
    assert set(h["types"]) == {"process_name", "command"}


def test_ip_domain_and_hash_accepted(tmp_path):
    # ip, domain, hash are all now accepted (matchable) types — a clean miss returns a result, not a raise.
    for good in ("hash", "domain", "ip"):
        val = "a" * 64 if good == "hash" else ("x.example.com" if good == "domain" else "203.0.113.99")
        out = match_iocs([{"type": good, "value": val}], _write_feed(tmp_path, []), [], _topo(), [])
        assert out["iocs"][0]["matched"] is False and out["iocs"][0]["type"] == good


def test_empty_and_unknown_type_rejected(tmp_path):
    with pytest.raises(ValueError):
        match_iocs([], _write_feed(tmp_path, []), [], _topo(), [])
    with pytest.raises(ValueError):
        match_iocs([{"type": "weird", "value": "x"}], _write_feed(tmp_path, []), [], _topo(), [])


def test_truncation(tmp_path):
    lines = [_proc(f"2026-01-01T09:00:{i%60:02d}+00:00", _H, "powershell.exe") for i in range(MAX_HITS_PER_IOC + 25)]
    out = match_iocs([{"type": "process_name", "value": "powershell.exe"}], _write_feed(tmp_path, lines), [], _topo(), [])
    r = out["iocs"][0]
    assert r["hit_count"] == MAX_HITS_PER_IOC + 25 and len(r["hits"]) == MAX_HITS_PER_IOC and r["truncated"] is True


def test_deterministic_recompute_identical(tmp_path):
    feed = _write_feed(tmp_path, [_proc("2026-01-01T09:00:00+00:00", _H, "powershell.exe", "x mimikatz")])
    iocs = [{"type": "process_name", "value": "powershell.exe"}, {"type": "command", "value": "mimikatz"}]
    assert match_iocs(iocs, feed, [], _topo(), []) == match_iocs(iocs, feed, [], _topo(), [])
    assert HONESTY_NOTE in match_iocs(iocs, feed, [], _topo(), [])["summary"]["honesty_note"]
