"""Real-Sysmon-field normalizer (source_type='windows_sysmon_real').

Maps REAL Microsoft-Sysmon field names (Image, TargetImage, GrantedAccess, Hostname, Hashes-string,
@timestamp/UtcTime) onto the canonical NormalizedEvent — distinct from the synthetic legacy
`windows_sysmon` normalizer (which is the source_type=None default and stays byte-untouched).

Covers EID 1/3/7/8/10/13/22. EID 8 (CreateRemoteThread / process injection) and EID 13 (RegistryEvent
SetValue / Run-key persistence) map onto the existing `behavior` kind — distinct `behavior` markers the
engine already matches via `Behavior_Markers`, so NO engine/criteria change is needed. Unmodeled EIDs
return None (real captures carry many EIDs; normalize_events skips None).
"""
from datetime import datetime, timezone

from augur.normalize.model import NormalizedEvent, _ext

# EID 8 (CreateRemoteThread) + 10 (ProcessAccess) + 13 (RegistryEvent SetValue) + 4104 (PowerShell
# ScriptBlock logging) all normalize to the `behavior` kind, distinguished by the per-EID `behavior`
# marker set in the behavior branch below. NOTE 4104 is a PowerShell-provider event, not Sysmon.
_KIND_BY_EID = {1: "process_create", 7: "image_load", 3: "network_connect", 22: "dns_query",
                8: "behavior", 10: "behavior", 13: "behavior", 4104: "behavior"}


# Windows EventIDs are NOT unique across providers: Microsoft-Windows-Kernel-IO ALSO emits EventID 1
# (volume-mount; no ProcessGuid/Image), Security emits its own EID 1, etc. A real Sysmon parser MUST
# gate on the provider, not the bare EventID — otherwise a foreign EID-1 is mis-read as a Sysmon
# process_create with process_guid=None, which crashes build_graph (None NetworkX node id).
def _is_sysmon_provider(raw: dict) -> bool:
    """True iff this record is Microsoft-Sysmon telemetry (or carries no provider hint at all).

    Primary gate: SourceName == 'Microsoft-Windows-Sysmon' (real OTRF value). Fallback: Channel
    contains 'Sysmon' (e.g. 'Microsoft-Windows-Sysmon/Operational') when SourceName is absent. A
    record with NEITHER field is treated as Sysmon, preserving minimal/synthetic fixtures verbatim."""
    src = raw.get("SourceName")
    if src is not None:
        return src == "Microsoft-Windows-Sysmon"
    chan = raw.get("Channel")
    if chan is not None:
        return "Sysmon" in chan
    return True  # no provider hint — keep (synthetic/minimal fixtures stay byte-identical)


def _is_powershell_provider(raw: dict) -> bool:
    """True iff this record is Microsoft-Windows-PowerShell telemetry (the channel that emits EID 4104
    ScriptBlock logging). EID 4104 is NOT Sysmon — it must be gated on the PowerShell provider so a
    foreign EID-4104 (if any) is not mis-read. No provider hint ⇒ kept (minimal fixtures)."""
    src = raw.get("SourceName")
    if src is not None:
        return src == "Microsoft-Windows-PowerShell"
    chan = raw.get("Channel")
    if chan is not None:
        return "PowerShell" in chan
    return True


def _parse_ts(raw: dict) -> datetime:
    at = raw.get("@timestamp")
    if at:
        s = at[:-1] + "+00:00" if at.endswith("Z") else at
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    # fall back to Sysmon UtcTime: "YYYY-MM-DD HH:MM:SS.fff" (naive, UTC by Sysmon convention)
    dt = datetime.fromisoformat(raw["UtcTime"].replace(" ", "T"))
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _parse_hashes(s) -> dict:
    if not s or not isinstance(s, str):
        return {}
    out: dict[str, str] = {}
    for part in s.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _basename(path) -> str | None:
    if not path:
        return None
    return path.replace("/", "\\").split("\\")[-1]


def normalize(raw: dict) -> NormalizedEvent | None:
    eid = raw.get("EventID", raw.get("event_id"))   # real OTRF uses capital EventID; keep lowercase fallback
    kind = _KIND_BY_EID.get(eid)
    if kind is None:
        return None  # unmodeled EID — drop (do NOT raise; real captures are noisy)
    # Per-EID provider gate: EID 4104 is PowerShell-provider; everything else is Sysmon. A modeled EID
    # from a FOREIGN provider (e.g. Kernel-IO EID-1 volume-mount) is dropped, not mis-read.
    gate = _is_powershell_provider if eid == 4104 else _is_sysmon_provider
    if not gate(raw):
        return None

    ts = _parse_ts(raw)
    host = raw.get("Hostname")  # NOT raw["host"] — that's the WEC forwarder
    common = dict(
        timestamp=ts, kind=kind, host=host, event_id=eid,
        source_type="windows_sysmon_real", os_family="windows", raw_event_type=str(eid),
    )

    if kind == "behavior":
        if eid == 10:  # ProcessAccess — actor is Source*, NOT ProcessGuid/Image (null here)
            src_image = raw.get("SourceImage")
            return NormalizedEvent(
                **common,
                process_guid=raw.get("SourceProcessGUID"),   # accessor guid (capital GUID); ProcessGuid is null on EID-10
                process_name=src_image,                      # so the if-absent upsert ProcessNode is shaped right
                process_path=src_image,
                behavior="ProcessAccess",
                target=_basename(raw.get("TargetImage")),    # lsass.exe
                granted_access=raw.get("GrantedAccess"),     # 0x1010
                reason=raw.get("CallTrace"),
            )
        if eid == 8:  # CreateRemoteThread — process injection. Actor is the Source* process.
            src_image = raw.get("SourceImage")
            return NormalizedEvent(
                **common,
                process_guid=raw.get("SourceProcessGuid") or raw.get("SourceProcessGUID"),
                process_name=src_image, process_path=src_image,
                behavior="CreateRemoteThread",
                target=_basename(raw.get("TargetImage")),    # the injected process (e.g. notepad.exe)
                reason=raw.get("StartFunction"),             # e.g. LoadLibraryA (context, not matched)
            )
        if eid == 13:  # RegistryEvent (SetValue) — persistence (e.g. Run-key). Actor = the writing process.
            image = raw.get("Image")
            return NormalizedEvent(
                **common,
                process_guid=raw.get("ProcessGuid"),
                process_name=image, process_path=image,
                behavior="RegistrySetValue",
                target=raw.get("TargetObject"),              # full registry path (matched via TargetProcess)
                reason=raw.get("Details"),                   # the value written (context, not matched)
            )
        if eid == 4104:  # PowerShell ScriptBlock logging — the script TEXT is the signal.
            # 4104 carries NO Sysmon ProcessGuid (it is a PowerShell-provider event). Anchor the behavior
            # on a DETERMINISTIC synthetic node keyed by (host, ExecutionProcessID) so all script blocks
            # from one PS process share a node; the if-absent upsert in build_graph materializes it. The
            # node is standalone (not in the Sysmon spawn chain) — honest: a single-step "malicious script
            # block seen" detection, not a process-tree claim.
            pid = raw.get("ExecutionProcessID")
            anchor = f"psh:{host}:{pid}" if pid is not None else f"psh:{host}:{raw.get('ScriptBlockId')}"
            return NormalizedEvent(
                **common,
                process_guid=anchor,
                process_name="powershell.exe", process_path="powershell.exe",
                behavior="PowerShellScriptBlock",
                target=raw.get("ScriptBlockText"),           # the script text (matched via TargetProcess)
                reason=str(raw.get("ScriptBlockId")),        # script-block id (context, not matched)
            )

    if kind == "process_create":  # EID 1
        return NormalizedEvent(
            **common,
            process_guid=raw.get("ProcessGuid"),
            process_name=raw.get("Image"),
            process_path=raw.get("Image"),
            command_line=raw.get("CommandLine"),
            parent_process_guid=raw.get("ParentProcessGuid"),
            parent_process_name=raw.get("ParentImage"),
            integrity_level=raw.get("IntegrityLevel"),
            user=raw.get("User"),
            user_sid=raw.get("UserSid"),
            hashes=_parse_hashes(raw.get("Hashes")),
        )

    if kind == "image_load":  # EID 7
        image = raw.get("ImageLoaded")
        return NormalizedEvent(
            **common,
            process_guid=raw.get("ProcessGuid"),
            image_loaded=image, extension=_ext(image),
            signed=(raw.get("Signed") == "true") if raw.get("Signed") is not None else None,
            signature_vendor=raw.get("Signature"),
            hashes=_parse_hashes(raw.get("Hashes")),
        )

    if kind == "dns_query":  # EID 22
        return NormalizedEvent(**common, process_guid=raw.get("ProcessGuid"), domain=raw.get("QueryName"))

    # network_connect (EID 3)
    port = raw.get("DestinationPort")
    return NormalizedEvent(
        **common, process_guid=raw.get("ProcessGuid"),
        dest_ip=raw.get("DestinationIp"),
        dest_port=int(port) if port not in (None, "") else None,
    )


def normalize_real_sysmon(raw: dict) -> NormalizedEvent | None:
    """Committed explicit entry for REAL OTRF Sysmon (no source_type required).

    Real OTRF events carry `source_type: null`, so generic registry dispatch would route them to the
    legacy windows_sysmon path. Callers ingesting real Sysmon invoke THIS directly. Bounded to EID
    1/3/7/10/22; unmodeled EIDs (noise) return None.
    """
    return normalize(raw)


def normalize_real_sysmon_events(raws: list[dict]) -> list[NormalizedEvent]:
    """Explicit opt-in ingest path for real Sysmon: map normalize over raws, dropping None."""
    out: list[NormalizedEvent] = []
    for r in raws:
        ev = normalize_real_sysmon(r)
        if ev is not None:
            out.append(ev)
    return out
