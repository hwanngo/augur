from datetime import timezone
from augur.normalize.ecs import normalize_event, NormalizedEvent


def test_normalize_process_create():
    raw = {
        "timestamp": "2026-05-01T10:00:00+00:00", "event_id": 1, "host": "HR_User_PC",
        "user": "alice", "process_guid": "p1", "process_name": "evil.exe",
        "process_path": "C:\\Users\\a\\AppData\\Local\\Temp\\evil.exe",
        "command_line": "evil.exe -nop -w hidden", "parent_process_guid": "p0",
        "parent_process_name": "explorer.exe", "integrity_level": "High",
    }
    ev = normalize_event(raw)
    assert isinstance(ev, NormalizedEvent)
    assert ev.kind == "process_create"
    assert ev.process_guid == "p1"
    assert ev.timestamp.tzinfo is not None
    assert ev.command_line == "evil.exe -nop -w hidden"


def test_normalize_image_load_and_edr():
    img = normalize_event({"timestamp": "2026-05-01T10:00:05+00:00", "event_id": 7, "host": "HR_User_PC",
                           "process_guid": "p1", "image_loaded": "C:\\x\\eviltricks.dll",
                           "signed": False, "is_injected": True, "api_hooking_detected": True})
    assert img.kind == "image_load"
    assert img.is_injected is True
    assert img.extension == ".dll"

    edr = normalize_event({"timestamp": "2026-05-01T10:00:10+00:00", "event_id": "edr", "host": "HR_User_PC",
                           "process_guid": "p1", "behavior": "lsass_access", "target": "lsass.exe",
                           "granted_access": "0x1410"})
    assert edr.kind == "behavior"
    assert edr.behavior == "lsass_access"
    assert edr.granted_access == "0x1410"
