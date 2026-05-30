from datetime import datetime

from augur.normalize.model import NormalizedEvent, _ext

_KIND_BY_EVENT = {1: "process_create", 7: "image_load", 22: "dns_query", 3: "network_connect", "edr": "behavior"}


def normalize(raw: dict) -> NormalizedEvent:
    eid = raw.get("event_id")
    kind = _KIND_BY_EVENT.get(eid)
    if kind is None:
        raise ValueError(f"unknown event_id: {eid!r}")
    ts = datetime.fromisoformat(raw["timestamp"])
    return NormalizedEvent(
        timestamp=ts, kind=kind, host=raw["host"], event_id=eid, user=raw.get("user"),
        process_guid=raw.get("process_guid"), process_name=raw.get("process_name"),
        process_path=raw.get("process_path"), command_line=raw.get("command_line"),
        parent_process_guid=raw.get("parent_process_guid"),
        parent_process_name=raw.get("parent_process_name"),
        integrity_level=raw.get("integrity_level"), user_sid=raw.get("user_sid"),
        hashes=raw.get("hashes", {}),
        image_loaded=raw.get("image_loaded"), extension=_ext(raw.get("image_loaded")),
        signed=raw.get("signed"), signature_vendor=raw.get("signature_vendor"),
        is_injected=bool(raw.get("is_injected", False)),
        api_hooking_detected=bool(raw.get("api_hooking_detected", False)),
        hooked_functions=raw.get("hooked_functions", []),
        behavior=raw.get("behavior"), target=raw.get("target"),
        granted_access=raw.get("granted_access"), reason=raw.get("reason"),
        domain=raw.get("query_name"),
        dest_ip=raw.get("dest_ip"), dest_port=raw.get("dest_port"),  # Sysmon DestinationIp/DestinationPort
        source_type=raw.get("source_type"), os_family="windows", raw_event_type=str(eid),
    )
