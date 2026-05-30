import pytest
from augur.normalize.windows_sysmon import normalize
from augur.normalize.model import NormalizedEvent


def test_process_create():
    raw = {"timestamp": "2026-05-01T10:00:00+00:00", "event_id": 1, "host": "HR_User_PC",
           "user": "alice", "process_guid": "p1", "process_name": "dropper.exe",
           "process_path": "C:\\Users\\alice\\AppData\\Local\\Temp\\dropper.exe",
           "command_line": "powershell -nop -w hidden -enc AAAA", "parent_process_name": "explorer.exe"}
    e = normalize(raw)
    assert isinstance(e, NormalizedEvent)
    assert e.kind == "process_create" and e.process_name == "dropper.exe" and e.host == "HR_User_PC"


def test_image_load_extension_derived():
    raw = {"timestamp": "2026-05-01T10:00:30+00:00", "event_id": 7, "host": "HR_User_PC",
           "process_guid": "p2", "image_loaded": "C:\\x\\evil.dll", "signed": False, "is_injected": True}
    e = normalize(raw)
    assert e.kind == "image_load" and e.extension == ".dll" and e.is_injected is True


def test_behavior():
    raw = {"timestamp": "2026-05-01T10:01:00+00:00", "event_id": "edr", "host": "HR_User_PC",
           "process_guid": "p2", "behavior": "lsass_access", "target": "lsass.exe", "granted_access": "0x1410"}
    e = normalize(raw)
    assert e.kind == "behavior" and e.target == "lsass.exe" and e.granted_access == "0x1410"


def test_unknown_event_id_raises():
    with pytest.raises(ValueError):
        normalize({"timestamp": "2026-05-01T10:00:00+00:00", "event_id": 999, "host": "h"})
