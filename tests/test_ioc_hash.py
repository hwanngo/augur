"""TDD: hash-type IOC matching for windows_sysmon telemetry only (Increment 1)."""
import hashlib
import json

from augur.api.ioc import match_iocs, HONESTY_NOTE, _EVENT_TYPES, _UNMATCHABLE
from augur.pipeline import default_topology

_H = "HR_User_PC"
_WIN_PATH = "C:\\Windows\\System32\\rundll32.exe"
_WIN_NAME = "rundll32.exe"


def _derive(path, name):
    seed = f"{path}|{name}".encode()
    return {"sha256": hashlib.sha256(seed).hexdigest(),
            "md5": hashlib.md5(seed).hexdigest()}


def _win_proc(ts, host=_H, path=_WIN_PATH, name=_WIN_NAME, hashes=None):
    raw = {"timestamp": ts, "host": host, "event_id": 1, "process_guid": "{g}",
           "process_name": name, "process_path": path, "command_line": name}
    if hashes is not None:
        raw["hashes"] = hashes
    return raw


def _linux_proc(ts, host="CORP-JENKINS01"):
    # source_type routes through the linux normalizer; carries NO hashes
    return {"source_type": "linux_auditd", "timestamp": ts, "host": host, "type": "EXECVE",
            "pid": 10, "ppid": 1, "uid": "deploy", "exe": "/usr/bin/curl", "comm": "curl", "a0": "curl"}


def _write_feed(tmp_path, lines):
    p = tmp_path / "feed.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in lines))
    return [str(p)]


def _topo():
    return default_topology()


def test_hash_in_accepted_not_in_unmatchable():
    assert "hash" in _EVENT_TYPES
    assert "hash" not in _UNMATCHABLE


def test_hash_matches_known_windows_process(tmp_path):
    digest = _derive(_WIN_PATH, _WIN_NAME)
    feed = _write_feed(tmp_path, [_win_proc("2026-01-01T09:00:00+00:00", hashes=digest)])
    out = match_iocs([{"type": "hash", "value": digest["sha256"]}], feed, [], _topo(), [])
    r = out["iocs"][0]
    assert r["matched"] is True and r["hit_count"] == 1 and r["target"] == "event"
    assert r["hits"][0]["host"] == _H and r["hits"][0]["matched_field"] == "sha256"


def test_hash_case_insensitive(tmp_path):
    digest = _derive(_WIN_PATH, _WIN_NAME)
    feed = _write_feed(tmp_path, [_win_proc("2026-01-01T09:00:00+00:00", hashes=digest)])
    out = match_iocs([{"type": "hash", "value": digest["sha256"].upper()}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is True


def test_hash_matches_md5_too(tmp_path):
    digest = _derive(_WIN_PATH, _WIN_NAME)
    feed = _write_feed(tmp_path, [_win_proc("2026-01-01T09:00:00+00:00", hashes=digest)])
    out = match_iocs([{"type": "hash", "value": digest["md5"]}], feed, [], _topo(), [])
    r = out["iocs"][0]
    assert r["matched"] is True and r["hits"][0]["matched_field"] == "md5"


def test_hash_clean_miss(tmp_path):
    digest = _derive(_WIN_PATH, _WIN_NAME)
    feed = _write_feed(tmp_path, [_win_proc("2026-01-01T09:00:00+00:00", hashes=digest)])
    out = match_iocs([{"type": "hash", "value": "f" * 64}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is False and out["iocs"][0]["hit_count"] == 0


def test_hash_never_matches_linux_event(tmp_path):
    # Linux event carries no hashes -> a hash IOC can never hit it.
    feed = _write_feed(tmp_path, [_linux_proc("2026-01-01T09:00:00+00:00")])
    out = match_iocs([{"type": "hash", "value": "a" * 64}], feed, [], _topo(), [])
    assert out["iocs"][0]["matched"] is False


def test_hash_honesty_note_synthetic_caveat(tmp_path):
    feed = _write_feed(tmp_path, [_win_proc("2026-01-01T09:00:00+00:00", hashes=_derive(_WIN_PATH, _WIN_NAME))])
    out = match_iocs([{"type": "hash", "value": "a" * 64}], feed, [], _topo(), [])
    note = out["summary"]["honesty_note"]
    assert note == HONESTY_NOTE
    assert "synthetic" in note.lower()


def test_ip_accepted_domain_accepted(tmp_path):
    # ip is now accepted too (Increment 3) — clean miss, not a reject.
    out = match_iocs([{"type": "ip", "value": "203.0.113.99"}], _write_feed(tmp_path, []), [], _topo(), [])
    assert out["iocs"][0]["matched"] is False and out["iocs"][0]["type"] == "ip"
    out = match_iocs([{"type": "domain", "value": "x.example.com"}], _write_feed(tmp_path, []), [], _topo(), [])
    assert out["iocs"][0]["matched"] is False and out["iocs"][0]["type"] == "domain"
