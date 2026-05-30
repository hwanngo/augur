import hashlib

from augur.simulator.intents import EventIntent


def _guid(host: str, pid) -> str | None:
    return f"{host}:{pid}" if pid is not None else None


def _iso(intent: EventIntent) -> str:
    return intent.timestamp.isoformat()


def _derive_hashes(intent: EventIntent) -> dict:
    """Deterministic synthetic file hashes for a Windows process_create.

    Derived purely from the binary's stable identity (process_path|process_name) so the SAME
    binary always gets the SAME digest across the whole corpus — no wall-clock, no randomness
    (Invariant 1). This lives in simulator/emitter land ONLY; the engine never reads `hashes`.
    """
    if intent.hashes is not None:
        return intent.hashes
    seed = f"{intent.process_path}|{intent.process_name}".encode()
    return {"sha256": hashlib.sha256(seed).hexdigest(),
            "md5": hashlib.md5(seed).hexdigest()}


def _windows(intent: EventIntent) -> dict:
    base = {"source_type": "windows_sysmon", "timestamp": _iso(intent), "host": intent.host}
    if intent.kind == "process_create":
        return {**base, "event_id": 1, "user": intent.user, "process_guid": _guid(intent.host, intent.pid),
                "process_name": intent.process_name, "process_path": intent.process_path,
                "command_line": intent.command_line, "parent_process_guid": _guid(intent.host, intent.ppid),
                "parent_process_name": intent.parent_process_name,
                "integrity_level": intent.integrity_level, "hashes": _derive_hashes(intent)}
    if intent.kind == "image_load":
        return {**base, "event_id": 7, "process_guid": _guid(intent.host, intent.pid),
                "image_loaded": intent.image_loaded, "signed": intent.signed,
                "is_injected": intent.is_injected, "api_hooking_detected": intent.api_hooking_detected}
    if intent.kind == "dns_query":
        return {**base, "event_id": 22, "process_guid": _guid(intent.host, intent.pid),
                "query_name": intent.domain}
    if intent.kind == "network_connect":
        return {**base, "event_id": 3, "process_guid": _guid(intent.host, intent.pid),
                "dest_ip": intent.dest_ip, "dest_port": intent.dest_port}
    return {**base, "event_id": "edr", "process_guid": _guid(intent.host, intent.pid),
            "behavior": intent.behavior, "target": intent.target, "granted_access": intent.granted_access}


def _linux(intent: EventIntent) -> dict:
    base = {"source_type": "linux_auditd", "timestamp": _iso(intent), "host": intent.host}
    if intent.kind == "process_create":
        d = {**base, "type": "EXECVE", "pid": intent.pid, "ppid": intent.ppid,
             "uid": intent.user, "auid": intent.user, "exe": intent.process_path,
             "comm": intent.process_name, "ppid_exe": f"/usr/bin/{intent.parent_process_name}"
             if intent.parent_process_name else None}
        for i, tok in enumerate((intent.command_line or "").split(" ")):
            if tok:
                d[f"a{i}"] = tok
        return d
    if intent.kind == "image_load":
        return {**base, "type": "SYSCALL", "syscall": "openat", "pid": intent.pid,
                "name": intent.image_loaded, "signed": intent.signed, "is_injected": intent.is_injected}
    if intent.kind == "network_connect":
        return {**base, "type": "SYSCALL", "syscall": "connect", "pid": intent.pid,
                "daddr": intent.dest_ip, "dport": intent.dest_port}
    if intent.kind == "dns_query":
        return {**base, "type": "EDR", "behavior": "dns_query", "pid": intent.pid,
                "query_name": intent.domain}
    return {**base, "type": "EDR", "pid": intent.pid, "behavior": intent.behavior,
            "target": intent.target, "granted_access": intent.granted_access}


def _macos_exe_path(intent: EventIntent) -> str | None:
    """Return a POSIX-style path whose basename == process_name, so the macOS normalizer can derive
    process_name correctly from _basename(exe_path). Fall back to process_path if name is unavailable."""
    if intent.process_name:
        return f"/usr/bin/{intent.process_name}"
    return intent.process_path


def _macos(intent: EventIntent) -> dict:
    base = {"source_type": "macos_esf", "timestamp": _iso(intent), "host": intent.host}
    token = _guid(intent.host, intent.pid)
    if intent.kind == "process_create":
        return {**base, "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC", "user": intent.user,
                "process": {"executable": {"path": _macos_exe_path(intent)}, "audit_token": token,
                            "ppid": intent.ppid, "is_platform_binary": False},
                "event": {"exec": {"args": (intent.command_line or "").split(" ") if intent.command_line else []}}}
    if intent.kind == "image_load":
        return {**base, "event_type": "ES_EVENT_TYPE_NOTIFY_MMAP",
                "process": {"executable": {"path": intent.process_path}, "audit_token": token},
                "event": {"mmap": {"source": {"path": intent.image_loaded},
                                   "is_platform_binary": bool(intent.signed)}}}
    if intent.kind == "network_connect":
        return {**base, "event_type": "ES_AGENT_NOTIFY_NETWORK_CONNECT",
                "process": {"audit_token": token},
                "dest_ip": intent.dest_ip, "dest_port": intent.dest_port}
    if intent.kind == "dns_query":
        return {**base, "event_type": "ES_AGENT_NOTIFY_DNS_QUERY",
                "process": {"audit_token": token},
                "query_name": intent.domain}
    # macOS behavior overlay (rare in v1; emit a generic NOTIFY with EDR-style fields)
    return {**base, "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
            "process": {"executable": {"path": intent.process_path}, "audit_token": token},
            "event": {"exec": {"args": []}}}


_EMITTERS = {"windows": _windows, "linux": _linux, "macos": _macos}


def emit(os_family: str, intent: EventIntent) -> dict:
    return _EMITTERS[os_family](intent)
