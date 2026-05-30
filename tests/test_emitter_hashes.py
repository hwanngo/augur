"""TDD: deterministic synthetic Windows-only hashes on the simulator emitter path."""
from datetime import datetime, timezone

from augur.simulator.intents import EventIntent
from augur.simulator.emitters import emit


def _win_pc(path="C:\\Windows\\System32\\rundll32.exe", name="rundll32.exe"):
    return EventIntent(kind="process_create", host="HR_User_PC",
                       timestamp=datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc),
                       pid=1234, ppid=1, user="alice",
                       process_name=name, process_path=path,
                       command_line=name, parent_process_name="explorer.exe")


def test_eventintent_accepts_hashes_field():
    intent = _win_pc()
    intent.hashes = {"sha256": "deadbeef"}
    assert intent.hashes == {"sha256": "deadbeef"}


import hashlib


def _expected(path, name):
    seed = f"{path}|{name}".encode()
    return {"sha256": hashlib.sha256(seed).hexdigest(),
            "md5": hashlib.md5(seed).hexdigest()}


def test_windows_process_create_has_deterministic_hashes():
    raw = emit("windows", _win_pc())
    assert raw["event_id"] == 1
    assert raw["hashes"] == _expected("C:\\Windows\\System32\\rundll32.exe", "rundll32.exe")


def test_windows_same_binary_same_hash_across_calls():
    a = emit("windows", _win_pc())
    b = emit("windows", _win_pc())
    assert a["hashes"] == b["hashes"]  # deterministic: no now()/random


def test_windows_different_binary_different_hash():
    a = emit("windows", _win_pc("C:\\Windows\\System32\\cmd.exe", "cmd.exe"))
    b = emit("windows", _win_pc("C:\\Windows\\System32\\reg.exe", "reg.exe"))
    assert a["hashes"] != b["hashes"]


def test_windows_explicit_hashes_override_respected():
    intent = _win_pc()
    intent.hashes = {"sha256": "0" * 64}
    raw = emit("windows", intent)
    assert raw["hashes"] == {"sha256": "0" * 64}


def test_windows_image_load_has_no_hashes():
    intent = EventIntent(kind="image_load", host="HR_User_PC",
                         timestamp=datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc),
                         pid=1234, image_loaded="C:\\Windows\\System32\\evil.dll", signed=False)
    raw = emit("windows", intent)
    assert raw["event_id"] == 7
    assert "hashes" not in raw


def test_linux_and_macos_carry_no_hashes():
    li = emit("linux", _win_pc("/usr/bin/curl", "curl"))
    ma = emit("macos", _win_pc("/usr/bin/curl", "curl"))
    assert "hashes" not in li
    assert "hashes" not in ma
