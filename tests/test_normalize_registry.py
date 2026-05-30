import pytest
from augur.normalize.registry import normalize_event, normalize_events, REGISTRY


def test_absent_source_type_uses_windows_path():
    e = normalize_event({"timestamp": "2026-05-01T10:00:00+00:00", "event_id": 1, "host": "h",
                         "process_name": "x.exe"})
    assert e.kind == "process_create" and e.os_family == "windows"


def test_registry_has_three_source_types():
    assert {"windows_sysmon", "linux_auditd", "macos_esf"} <= set(REGISTRY)


def test_explicit_windows_source_type():
    e = normalize_event({"source_type": "windows_sysmon", "timestamp": "2026-05-01T10:00:00+00:00",
                         "event_id": 1, "host": "h"})
    assert e.kind == "process_create"


def test_unknown_source_type_raises():
    with pytest.raises(ValueError):
        normalize_event({"source_type": "bogus", "timestamp": "2026-05-01T10:00:00+00:00", "host": "h"})


def test_unknown_event_id_without_source_type_still_raises():
    with pytest.raises(ValueError):
        normalize_event({"timestamp": "2026-05-01T10:00:00+00:00", "event_id": 42, "host": "h"})


def test_normalize_events_filters_none(monkeypatch):
    # a normalizer that drops everything
    monkeypatch.setitem(REGISTRY, "dropper", lambda raw: None)
    out = normalize_events([{"source_type": "dropper", "timestamp": "x", "host": "h"},
                            {"timestamp": "2026-05-01T10:00:00+00:00", "event_id": 1, "host": "h"}])
    assert len(out) == 1 and out[0].kind == "process_create"
