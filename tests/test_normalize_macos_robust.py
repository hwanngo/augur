"""
Robustness tests for macos_esf normalizer — real-world field variations.
All tests exercise NEW fallback behaviors; existing tests continue to pass unchanged.
"""
import pytest
from augur.normalize.macos_esf import normalize


# ---------------------------------------------------------------------------
# 1. parent_process_name (P5 gap): populate from parent_executable.path
# ---------------------------------------------------------------------------

def test_parent_process_name_from_process_parent_executable():
    """parent_executable.path inside process block → parent_process_name."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "MBP-01",
        "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
        "user": "alice",
        "process": {
            "executable": {"path": "/usr/bin/python3"},
            "audit_token": "tok-42",
            "ppid": 1001,
            "parent_executable": {"path": "/Applications/Terminal.app/Contents/MacOS/Terminal"},
        },
        "event": {"exec": {"args": ["python3", "script.py"]}},
    }
    e = normalize(raw)
    assert e is not None
    assert e.parent_process_name == "Terminal"


def test_parent_process_name_from_top_level_parent_process():
    """top-level parent_process.executable.path → parent_process_name."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "MBP-01",
        "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
        "user": "alice",
        "process": {
            "executable": {"path": "/bin/bash"},
            "audit_token": "tok-99",
            "ppid": 500,
        },
        "parent_process": {
            "executable": {"path": "/usr/sbin/sshd"},
        },
        "event": {"exec": {"args": ["bash", "-c", "id"]}},
    }
    e = normalize(raw)
    assert e is not None
    assert e.parent_process_name == "sshd"


def test_parent_process_name_none_when_no_parent_info():
    """No parent info → parent_process_name is None (current behavior preserved)."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "MBP-01",
        "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
        "user": "alice",
        "process": {
            "executable": {"path": "/usr/bin/ssh"},
            "audit_token": "tok-77",
            "ppid": 300,
        },
        "event": {"exec": {"args": ["ssh", "server"]}},
    }
    e = normalize(raw)
    assert e is not None
    assert e.parent_process_name is None


def test_parent_executable_takes_priority_over_top_level_parent_process():
    """process.parent_executable takes priority over top-level parent_process."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "MBP-01",
        "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
        "user": "alice",
        "process": {
            "executable": {"path": "/bin/sh"},
            "audit_token": "tok-11",
            "ppid": 200,
            "parent_executable": {"path": "/usr/bin/primary"},
        },
        "parent_process": {
            "executable": {"path": "/usr/bin/secondary"},
        },
        "event": {"exec": {"args": ["sh"]}},
    }
    e = normalize(raw)
    assert e.parent_process_name == "primary"


# ---------------------------------------------------------------------------
# 1b. parent_process_guid from parent_audit_token when present
# ---------------------------------------------------------------------------

def test_parent_process_guid_from_parent_audit_token():
    """parent_audit_token in process block → parent_process_guid."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "MBP-01",
        "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
        "user": "alice",
        "process": {
            "executable": {"path": "/usr/bin/curl"},
            "audit_token": "tok-child",
            "ppid": 888,
            "parent_audit_token": "tok-parent-XYZ",
        },
        "event": {"exec": {"args": ["curl", "http://example.com"]}},
    }
    e = normalize(raw)
    assert e is not None
    assert e.parent_process_guid == "tok-parent-XYZ"


def test_parent_process_guid_falls_back_to_host_ppid_when_no_token():
    """Without parent_audit_token, parent_process_guid is host:ppid (existing behavior)."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "MBP-02",
        "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
        "user": "bob",
        "process": {
            "executable": {"path": "/usr/bin/id"},
            "audit_token": "tok-child2",
            "ppid": 777,
        },
        "event": {"exec": {"args": ["id"]}},
    }
    e = normalize(raw)
    assert e.parent_process_guid == "MBP-02:777"


# ---------------------------------------------------------------------------
# 2. Args robustness: args may be absent or a string
# ---------------------------------------------------------------------------

def test_args_as_string_used_directly_as_command_line():
    """event.exec.args is a string → used as command_line directly."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "MBP-01",
        "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
        "user": "carol",
        "process": {
            "executable": {"path": "/bin/zsh"},
            "audit_token": "tok-55",
            "ppid": 400,
        },
        "event": {"exec": {"args": "zsh -c 'echo hi'"}},
    }
    e = normalize(raw)
    assert e is not None
    assert e.command_line == "zsh -c 'echo hi'"


def test_args_absent_gives_none_command_line():
    """event.exec.args absent → command_line is None."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "MBP-01",
        "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
        "user": "dave",
        "process": {
            "executable": {"path": "/usr/bin/grep"},
            "audit_token": "tok-66",
            "ppid": 500,
        },
        "event": {"exec": {}},
    }
    e = normalize(raw)
    assert e is not None
    assert e.command_line is None


def test_args_empty_list_gives_none_command_line():
    """event.exec.args == [] → command_line is None."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "MBP-01",
        "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
        "user": "eve",
        "process": {
            "executable": {"path": "/usr/bin/true"},
            "audit_token": "tok-70",
            "ppid": 600,
        },
        "event": {"exec": {"args": []}},
    }
    e = normalize(raw)
    assert e.command_line is None


def test_args_list_joined_with_space():
    """event.exec.args is a list → joined with spaces (existing behavior)."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "MBP-01",
        "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
        "user": "frank",
        "process": {
            "executable": {"path": "/usr/bin/ls"},
            "audit_token": "tok-80",
            "ppid": 700,
        },
        "event": {"exec": {"args": ["ls", "-la", "/tmp"]}},
    }
    e = normalize(raw)
    assert e.command_line == "ls -la /tmp"


# ---------------------------------------------------------------------------
# 3. MMAP path key variants: source.path OR file.path
# ---------------------------------------------------------------------------

def test_mmap_source_path_variant(  ):
    """event.mmap.source.path is the existing key — must still work."""
    raw = {
        "timestamp": "2026-05-31T09:00:05+00:00", "host": "MBP-01",
        "event_type": "ES_EVENT_TYPE_NOTIFY_MMAP",
        "process": {"executable": {"path": "/usr/bin/bash"}, "audit_token": "tok-A"},
        "event": {"mmap": {"source": {"path": "/usr/lib/libc.dylib"}}},
    }
    e = normalize(raw)
    assert e is not None
    assert e.kind == "image_load"
    assert e.image_loaded == "/usr/lib/libc.dylib"
    assert e.extension == ".dylib"


def test_mmap_file_path_variant():
    """event.mmap.file.path is the alternative key — must also work."""
    raw = {
        "timestamp": "2026-05-31T09:00:05+00:00", "host": "MBP-01",
        "event_type": "ES_EVENT_TYPE_NOTIFY_MMAP",
        "process": {"executable": {"path": "/usr/bin/bash"}, "audit_token": "tok-B"},
        "event": {"mmap": {"file": {"path": "/tmp/injected.dylib"}}},
    }
    e = normalize(raw)
    assert e is not None
    assert e.kind == "image_load"
    assert e.image_loaded == "/tmp/injected.dylib"
    assert e.extension == ".dylib"


def test_mmap_source_takes_priority_over_file():
    """When both source.path and file.path present, source.path wins."""
    raw = {
        "timestamp": "2026-05-31T09:00:05+00:00", "host": "MBP-01",
        "event_type": "ES_EVENT_TYPE_NOTIFY_MMAP",
        "process": {"executable": {"path": "/usr/bin/bash"}, "audit_token": "tok-C"},
        "event": {"mmap": {
            "source": {"path": "/primary.dylib"},
            "file": {"path": "/secondary.dylib"},
        }},
    }
    e = normalize(raw)
    assert e.image_loaded == "/primary.dylib"
