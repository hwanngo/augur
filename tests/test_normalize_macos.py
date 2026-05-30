from augur.normalize.macos_esf import normalize


def test_exec_to_process_create():
    raw = {"source_type": "macos_esf", "timestamp": "2026-05-31T09:00:00+00:00", "host": "DESIGN-MBP-07",
           "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC", "user": "jsmith",
           "process": {"executable": {"path": "/usr/bin/osascript"}, "audit_token": "0xA1", "ppid": 501,
                       "signing_id": "com.apple.osascript", "is_platform_binary": True},
           "event": {"exec": {"args": ["osascript", "-e", "do shell script x"]}}}
    e = normalize(raw)
    assert e.kind == "process_create" and e.os_family == "macos"
    assert e.process_name == "osascript" and e.process_path == "/usr/bin/osascript"
    assert e.command_line == "osascript -e do shell script x"
    assert e.process_guid == "0xA1" and e.parent_process_guid == "DESIGN-MBP-07:501"
    assert e.user == "jsmith"


def test_mmap_to_image_load_unsigned():
    raw = {"source_type": "macos_esf", "timestamp": "2026-05-31T09:00:05+00:00", "host": "h",
           "event_type": "ES_EVENT_TYPE_NOTIFY_MMAP",
           "process": {"executable": {"path": "/usr/bin/osascript"}, "audit_token": "0xA1"},
           "event": {"mmap": {"source": {"path": "/tmp/evil.dylib"}, "is_platform_binary": False}}}
    e = normalize(raw)
    assert e.kind == "image_load" and e.image_loaded == "/tmp/evil.dylib" and e.extension == ".dylib"
    assert e.signed is False


def test_unknown_event_type_returns_none():
    assert normalize({"source_type": "macos_esf", "timestamp": "x", "host": "h",
                      "event_type": "ES_EVENT_TYPE_NOTIFY_OPEN"}) is None
