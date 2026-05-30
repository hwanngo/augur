from augur.normalize.registry import normalize_events
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.pipeline import default_topology


def test_mixed_os_batch_builds_process_and_file_nodes():
    raws = [
        # Windows process_create (no source_type -> legacy path)
        {"timestamp": "2026-05-31T09:00:00+00:00", "event_id": 1, "host": "HR_User_PC",
         "process_guid": "w1", "process_name": "powershell.exe", "process_path": "C:\\x\\powershell.exe",
         "command_line": "powershell -enc AAAA", "parent_process_name": "explorer.exe"},
        # Linux EXECVE
        {"source_type": "linux_auditd", "timestamp": "2026-05-31T09:00:01+00:00", "host": "CORP-JENKINS01",
         "type": "EXECVE", "pid": 10, "ppid": 1, "uid": 1000, "exe": "/usr/bin/curl", "comm": "curl",
         "a0": "curl", "a1": "http://x"},
        # Linux .so load on the same pid
        {"source_type": "linux_auditd", "timestamp": "2026-05-31T09:00:02+00:00", "host": "CORP-JENKINS01",
         "type": "SYSCALL", "syscall": "openat", "pid": 10, "name": "/tmp/.evil.so"},
        # macOS exec
        {"source_type": "macos_esf", "timestamp": "2026-05-31T09:00:03+00:00", "host": "DESIGN-MBP-07",
         "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
         "process": {"executable": {"path": "/usr/bin/osascript"}, "audit_token": "m1", "ppid": 1},
         "event": {"exec": {"args": ["osascript", "-e", "x"]}}},
    ]
    events = sorted(normalize_events(raws), key=lambda e: e.timestamp)
    assert len(events) == 4
    backend = NetworkXBackend()
    build_graph(events, default_topology(), backend)
    # find_nodes requires a predicate arg (no default) — pass a tautology, per the existing convention
    # in test_builder.py / test_networkx_backend.py.
    procs = backend.find_nodes("Process", lambda n: True)
    files = backend.find_nodes("File", lambda n: True)
    # 3 process_create events -> 3 process nodes; 1 image_load -> 1 file node
    assert len(procs) == 3 and len(files) == 1
    # the Linux curl process and its loaded .so are both present
    assert any(p.name == "curl" for p in procs)
    assert any(f.path == "/tmp/.evil.so" for f in files)
