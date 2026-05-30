"""
Robustness tests for linux_auditd normalizer — real-world field variations.
All tests exercise NEW fallback behaviors; existing tests continue to pass unchanged.
"""
import pytest
from augur.normalize.linux_auditd import normalize


# ---------------------------------------------------------------------------
# 1. command_line from proctitle / cmdline (fallback when a0..aN absent)
# ---------------------------------------------------------------------------

def test_proctitle_space_separated_used_when_no_argv():
    """proctitle with spaces → command_line when a0..aN absent."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "srv1",
        "type": "EXECVE", "pid": 100, "ppid": 99,
        "comm": "bash", "exe": "/bin/bash",
        "proctitle": "bash -c echo hello",
    }
    e = normalize(raw)
    assert e is not None
    assert e.command_line == "bash -c echo hello"


def test_proctitle_nul_separated_converted_to_spaces():
    """proctitle with NUL separators → spaces."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "srv1",
        "type": "EXECVE", "pid": 100, "ppid": 99,
        "comm": "python3", "exe": "/usr/bin/python3",
        "proctitle": "python3\x00/opt/run.py\x00--debug",
    }
    e = normalize(raw)
    assert e is not None
    assert e.command_line == "python3 /opt/run.py --debug"


def test_cmdline_used_when_no_argv_and_no_proctitle():
    """cmdline field → command_line when neither a0..aN nor proctitle present."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "srv1",
        "type": "EXECVE", "pid": 100, "ppid": 99,
        "comm": "sshd", "exe": "/usr/sbin/sshd",
        "cmdline": "sshd -D",
    }
    e = normalize(raw)
    assert e is not None
    assert e.command_line == "sshd -D"


def test_argv_takes_priority_over_proctitle():
    """a0..aN args are primary source; proctitle is only a fallback."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "srv1",
        "type": "EXECVE", "pid": 100, "ppid": 99,
        "comm": "curl", "exe": "/usr/bin/curl",
        "a0": "curl", "a1": "-s", "a2": "http://example.com",
        "proctitle": "SHOULD NOT APPEAR",
    }
    e = normalize(raw)
    assert e is not None
    assert e.command_line == "curl -s http://example.com"


def test_argv_takes_priority_over_cmdline():
    """a0..aN args are primary; cmdline is only a fallback."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "srv1",
        "type": "EXECVE", "pid": 100, "ppid": 99,
        "comm": "ls", "exe": "/bin/ls",
        "a0": "ls", "a1": "-la",
        "cmdline": "SHOULD NOT APPEAR",
    }
    e = normalize(raw)
    assert e.command_line == "ls -la"


# ---------------------------------------------------------------------------
# 2. process_name fallback: comm absent AND exe absent → None (no crash)
# ---------------------------------------------------------------------------

def test_process_name_none_when_comm_and_exe_absent():
    """No comm, no exe → process_name is None, no exception raised."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "srv1",
        "type": "EXECVE", "pid": 200, "ppid": 199,
        "uid": 0,
    }
    e = normalize(raw)
    assert e is not None
    assert e.process_name is None
    assert e.process_path is None


def test_process_name_falls_back_to_exe_basename_when_no_comm():
    """comm absent but exe present → basename(exe)."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "srv1",
        "type": "EXECVE", "pid": 200, "ppid": 199,
        "exe": "/usr/local/bin/myapp",
    }
    e = normalize(raw)
    assert e.process_name == "myapp"


# ---------------------------------------------------------------------------
# 3. String pids — auditd emits pids as strings
# ---------------------------------------------------------------------------

def test_string_pid_forms_correct_guid():
    """pid and ppid as strings still produce correct guids."""
    raw = {
        "timestamp": "2026-05-31T09:00:00+00:00", "host": "HOST-X",
        "type": "EXECVE", "pid": "1234", "ppid": "1000",
        "comm": "bash", "exe": "/bin/bash",
    }
    e = normalize(raw)
    assert e is not None
    assert e.process_guid == "HOST-X:1234"
    assert e.parent_process_guid == "HOST-X:1000"


def test_string_pid_in_syscall_event():
    """String pid in SYSCALL (image_load) event produces correct guid."""
    raw = {
        "timestamp": "2026-05-31T09:00:05+00:00", "host": "HOST-X",
        "type": "SYSCALL", "pid": "5678",
        "name": "/lib/x86_64-linux-gnu/libc.so.6",
    }
    e = normalize(raw)
    assert e is not None
    assert e.process_guid == "HOST-X:5678"


def test_string_pid_in_edr_event():
    """String pid in EDR (behavior) event produces correct guid."""
    raw = {
        "timestamp": "2026-05-31T09:00:10+00:00", "host": "HOST-X",
        "type": "EDR", "pid": "9999",
        "behavior": "cred_dump", "target": "/etc/shadow",
    }
    e = normalize(raw)
    assert e is not None
    assert e.process_guid == "HOST-X:9999"


# ---------------------------------------------------------------------------
# 4. File-event nametype: accepted as sanity signal but NOT required
# ---------------------------------------------------------------------------

def test_syscall_image_load_no_nametype_still_works():
    """SYSCALL with a name but no nametype is still treated as image_load."""
    raw = {
        "timestamp": "2026-05-31T09:00:05+00:00", "host": "h",
        "type": "SYSCALL", "pid": 111,
        "name": "/usr/lib/libssl.so.3",
    }
    e = normalize(raw)
    assert e is not None
    assert e.kind == "image_load"
    assert e.image_loaded == "/usr/lib/libssl.so.3"


def test_syscall_image_load_with_nametype_normal():
    """SYSCALL with nametype=NORMAL still produces image_load."""
    raw = {
        "timestamp": "2026-05-31T09:00:05+00:00", "host": "h",
        "type": "SYSCALL", "pid": 111,
        "name": "/usr/lib/libcrypto.so.3", "nametype": "NORMAL",
    }
    e = normalize(raw)
    assert e is not None
    assert e.kind == "image_load"


def test_syscall_image_load_with_nametype_create():
    """SYSCALL with nametype=CREATE still produces image_load."""
    raw = {
        "timestamp": "2026-05-31T09:00:05+00:00", "host": "h",
        "type": "SYSCALL", "pid": 111,
        "name": "/tmp/injected.so", "nametype": "CREATE",
    }
    e = normalize(raw)
    assert e is not None
    assert e.kind == "image_load"


def test_syscall_without_name_returns_none():
    """SYSCALL without a name field still returns None (existing behavior)."""
    raw = {
        "timestamp": "2026-05-31T09:00:05+00:00", "host": "h",
        "type": "SYSCALL", "pid": 111,
        "syscall": "open",
    }
    e = normalize(raw)
    assert e is None
