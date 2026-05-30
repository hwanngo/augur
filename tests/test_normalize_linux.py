from augur.normalize.linux_auditd import normalize


def test_execve_to_process_create():
    raw = {"source_type": "linux_auditd", "timestamp": "2026-05-31T09:00:00+00:00",
           "host": "CORP-JENKINS01", "type": "EXECVE", "pid": 4412, "ppid": 4410, "auid": 1000, "uid": 1000,
           "exe": "/usr/bin/curl", "comm": "curl", "argc": 4, "a0": "curl", "a1": "-s", "a2": "-o",
           "a3": "/tmp/x.sh", "ppid_exe": "/usr/bin/bash"}
    e = normalize(raw)
    assert e.kind == "process_create" and e.os_family == "linux"
    assert e.process_name == "curl" and e.process_path == "/usr/bin/curl"
    assert e.command_line == "curl -s -o /tmp/x.sh" and e.parent_process_name == "bash"
    # process_guid is stable per (host, pid) — NO event timestamp — so the exec event and this process's
    # later .so-load / behavior events share one guid and the graph builder links them.
    assert e.process_guid == "CORP-JENKINS01:4412"
    assert e.parent_process_guid == "CORP-JENKINS01:4410"
    assert e.user == "1000" and e.integrity_level is None


def test_so_load_to_image_load():
    raw = {"source_type": "linux_auditd", "timestamp": "2026-05-31T09:00:05+00:00", "host": "h",
           "type": "SYSCALL", "syscall": "openat", "pid": 4412, "exe": "/usr/bin/curl",
           "name": "/tmp/.evil.so", "is_injected": True}
    e = normalize(raw)
    assert e.kind == "image_load" and e.image_loaded == "/tmp/.evil.so" and e.extension == ".so"
    assert e.is_injected is True


def test_behavior_marker():
    raw = {"source_type": "linux_auditd", "timestamp": "2026-05-31T09:00:10+00:00", "host": "h",
           "type": "EDR", "pid": 4412, "behavior": "cred_dump", "target": "/etc/shadow"}
    e = normalize(raw)
    assert e.kind == "behavior" and e.target == "/etc/shadow"


def test_unknown_type_returns_none():
    assert normalize({"source_type": "linux_auditd", "timestamp": "x", "host": "h", "type": "PATH"}) is None
