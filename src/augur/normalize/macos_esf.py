from datetime import datetime

from augur.normalize.model import NormalizedEvent, _ext


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _parent_process_name(proc: dict, raw: dict) -> str | None:
    """Return basename of the parent executable path, or None.

    Priority:
    1. proc["parent_executable"]["path"]   — inline parent info on the process block
    2. raw["parent_process"]["executable"]["path"] — top-level parent_process block
    """
    pe_path = (proc.get("parent_executable", {}) or {}).get("path")
    if pe_path:
        return _basename(pe_path)
    pp_path = ((raw.get("parent_process", {}) or {}).get("executable", {}) or {}).get("path")
    if pp_path:
        return _basename(pp_path)
    return None


def _command_line(args) -> str | None:
    """Convert ESF args to a command-line string.

    - list  → joined with spaces (existing behavior)
    - str   → used directly (real ESF sometimes sends a pre-joined string)
    - absent/None/empty → None
    """
    if args is None:
        return None
    if isinstance(args, str):
        return args if args else None
    # list path
    return " ".join(str(a) for a in args) if args else None


def normalize(raw: dict) -> NormalizedEvent | None:
    et = raw.get("event_type")
    host = raw["host"]
    if et not in ("ES_EVENT_TYPE_NOTIFY_EXEC", "ES_EVENT_TYPE_NOTIFY_MMAP",
                  "ES_AGENT_NOTIFY_NETWORK_CONNECT", "ES_AGENT_NOTIFY_DNS_QUERY"):
        return None
    ts = datetime.fromisoformat(raw["timestamp"])  # only parsed when event_type is known
    proc = raw.get("process", {}) or {}
    exe_path = (proc.get("executable", {}) or {}).get("path")
    token = proc.get("audit_token")
    ppid = proc.get("ppid")
    if et == "ES_EVENT_TYPE_NOTIFY_EXEC":
        args = ((raw.get("event", {}) or {}).get("exec", {}) or {}).get("args")
        # parent_process_guid: prefer parent_audit_token when present (more stable than host:ppid)
        parent_token = proc.get("parent_audit_token")
        parent_guid = parent_token if parent_token is not None else (
            f"{host}:{ppid}" if ppid is not None else None
        )
        return NormalizedEvent(
            timestamp=ts, kind="process_create", host=host, event_id=et, user=raw.get("user"),
            process_guid=token, process_name=_basename(exe_path), process_path=exe_path,
            command_line=_command_line(args),
            parent_process_guid=parent_guid,
            parent_process_name=_parent_process_name(proc, raw),
            signed=proc.get("is_platform_binary"), signature_vendor=proc.get("signing_id"),
            source_type="macos_esf", os_family="macos", raw_event_type=et)
    if et == "ES_EVENT_TYPE_NOTIFY_MMAP":
        mmap = ((raw.get("event", {}) or {}).get("mmap", {}) or {})
        # Accept source.path (existing) OR file.path (alternative real-ESF key)
        img = (mmap.get("source", {}) or {}).get("path") or (mmap.get("file", {}) or {}).get("path")
        return NormalizedEvent(
            timestamp=ts, kind="image_load", host=host, event_id=et, process_guid=token,
            image_loaded=img, extension=_ext(img),
            signed=mmap.get("is_platform_binary", None) if "is_platform_binary" in mmap else None,
            source_type="macos_esf", os_family="macos", raw_event_type=et)
    if et == "ES_AGENT_NOTIFY_NETWORK_CONNECT":
        # Agent/Network-Extension overlay — stable ESF has no socket-connect NOTIFY. Inert (Invariant 6).
        return NormalizedEvent(
            timestamp=ts, kind="network_connect", host=host, event_id=et, process_guid=token,
            dest_ip=raw.get("dest_ip"), dest_port=raw.get("dest_port"),
            source_type="macos_esf", os_family="macos", raw_event_type=et)
    if et == "ES_AGENT_NOTIFY_DNS_QUERY":
        # Agent/NEDNSProxyProvider overlay — DNS is NOT in raw ESF. Inert (Invariant 6).
        return NormalizedEvent(
            timestamp=ts, kind="dns_query", host=host, event_id=et, process_guid=token,
            domain=raw.get("query_name"),
            source_type="macos_esf", os_family="macos", raw_event_type=et)
    return None                                      # unhandled ESF event -> drop
