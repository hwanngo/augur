from datetime import datetime, timezone
from augur.simulator.intents import EventIntent
from augur.simulator.emitters import emit
from augur.normalize.registry import normalize_event

T = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)


def _proc(host):
    return EventIntent(kind="process_create", host=host, timestamp=T, pid=10, ppid=1,
                       user="alice", process_name="curl", process_path="/usr/bin/curl",
                       command_line="curl -s http://x", parent_process_name="bash")


def test_round_trip_process_create_each_os():
    for os_family in ("windows", "linux", "macos"):
        raw = emit(os_family, _proc("H1"))
        e = normalize_event(raw)
        assert e.kind == "process_create"
        assert e.process_name == "curl"
        assert e.command_line == "curl -s http://x"
        assert e.process_guid == "H1:10"
        assert e.os_family == os_family


def test_round_trip_image_load_each_os():
    img = {"windows": "C:\\x\\evil.dll", "linux": "/tmp/evil.so", "macos": "/tmp/evil.dylib"}
    ext = {"windows": ".dll", "linux": ".so", "macos": ".dylib"}
    for os_family in ("windows", "linux", "macos"):
        intent = EventIntent(kind="image_load", host="H1", timestamp=T, pid=10,
                             image_loaded=img[os_family], signed=False, is_injected=True)
        e = normalize_event(emit(os_family, intent))
        assert e.kind == "image_load" and e.image_loaded == img[os_family]
        assert e.extension == ext[os_family] and e.signed is False


def test_round_trip_behavior_windows_and_linux():
    for os_family in ("windows", "linux"):
        intent = EventIntent(kind="behavior", host="H1", timestamp=T, pid=10,
                             behavior="cred_dump", target="lsass.exe", granted_access="0x1410")
        e = normalize_event(emit(os_family, intent))
        assert e.kind == "behavior" and e.target == "lsass.exe" and e.granted_access == "0x1410"


def test_emit_sets_source_type_and_is_json_safe():
    import json
    raw = emit("linux", _proc("H1"))
    assert raw["source_type"] == "linux_auditd"
    json.dumps(raw)            # must be JSON-serializable
