from datetime import datetime

from augur.normalize.model import NormalizedEvent, _ext


def _argv(raw: dict) -> str | None:
    """Return command line string from the raw auditd event.

    Priority order:
    1. a0..aN positional args (most structured, canonical auditd EXECVE form)
    2. proctitle field  (NUL- or space-separated, real kernels emit this)
    3. cmdline field    (some EDR/agent overlays emit this instead)
    4. comm             (last resort: just the executable name)
    """
    args = []
    i = 0
    while f"a{i}" in raw:
        args.append(str(raw[f"a{i}"]))
        i += 1
    if args:
        return " ".join(args)
    # Fallback: proctitle (NUL-separated in real auditd; may also be space-separated)
    proctitle = raw.get("proctitle")
    if proctitle:
        return proctitle.replace("\x00", " ")
    # Fallback: cmdline overlay field
    cmdline = raw.get("cmdline")
    if cmdline:
        return cmdline
    # Last resort: just comm (existing behaviour when nothing else is present)
    return raw.get("comm")


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def normalize(raw: dict) -> NormalizedEvent | None:
    t = raw.get("type")
    host = raw["host"]
    # process_guid is stable per (host, pid) so all of a process's events (exec, .so load, behavior)
    # share one guid and the builder forms SPAWNED/LOADED/EXHIBITED edges. (pid reuse within a long run
    # is a documented PoC limitation; fine for bounded sim windows + hand-written fixtures.)
    def _guid(pid):
        return f"{host}:{pid}" if pid is not None else None
    if t not in ("EXECVE", "SYSCALL", "EDR"):
        return None
    ts = datetime.fromisoformat(raw["timestamp"])  # only parsed when type is known
    if t == "EXECVE":
        return NormalizedEvent(
            timestamp=ts, kind="process_create", host=host, event_id="EXECVE",
            user=str(raw["uid"]) if "uid" in raw else None,
            user_sid=str(raw["auid"]) if "auid" in raw else None,
            process_guid=_guid(raw.get("pid")),
            process_name=raw.get("comm") or _basename(raw.get("exe")),
            process_path=raw.get("exe"), command_line=_argv(raw),
            parent_process_guid=_guid(raw.get("ppid")),
            parent_process_name=_basename(raw.get("ppid_exe")),
            integrity_level=None,
            source_type="linux_auditd", os_family="linux", raw_event_type="EXECVE")
    if t == "SYSCALL" and raw.get("syscall") == "connect":
        # Realistic auditd connect(2) capture: decoded destination (daddr/dport). Inert: the engine
        # never reads dest_ip/dest_port (Invariant 6). Honest-native — the most native of the 4 new paths.
        return NormalizedEvent(
            timestamp=ts, kind="network_connect", host=host, event_id="SYSCALL",
            process_guid=_guid(raw.get("pid")),
            dest_ip=raw.get("daddr"), dest_port=raw.get("dport"),
            source_type="linux_auditd", os_family="linux", raw_event_type="SYSCALL")
    if t == "SYSCALL" and raw.get("name"):
        img = raw["name"]
        return NormalizedEvent(
            timestamp=ts, kind="image_load", host=host, event_id="SYSCALL",
            process_guid=_guid(raw.get("pid")),
            image_loaded=img, extension=_ext(img),
            signed=raw.get("signed"), is_injected=bool(raw.get("is_injected", False)),
            api_hooking_detected=bool(raw.get("api_hooking_detected", False)),
            hooked_functions=raw.get("hooked_functions", []),
            source_type="linux_auditd", os_family="linux", raw_event_type="SYSCALL")
    if t == "EDR" and raw.get("behavior") == "dns_query":
        # Agent/EDR DNS overlay — auditd does NOT resolve DNS; this is an explicit overlay record
        # (Falco/eBPF/vendor agent). Inert: domain is in no criteria field map (Invariant 6).
        return NormalizedEvent(
            timestamp=ts, kind="dns_query", host=host, event_id="EDR",
            process_guid=_guid(raw.get("pid")),
            domain=raw.get("query_name"),
            source_type="linux_auditd", os_family="linux", raw_event_type="EDR")
    if t == "EDR":
        return NormalizedEvent(
            timestamp=ts, kind="behavior", host=host, event_id="EDR",
            process_guid=_guid(raw.get("pid")),
            behavior=raw.get("behavior"), target=raw.get("target"),
            granted_access=raw.get("granted_access"), reason=raw.get("reason"),
            source_type="linux_auditd", os_family="linux", raw_event_type="EDR")
    return None                                      # unhandled auditd record -> drop
