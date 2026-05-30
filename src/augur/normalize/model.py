from dataclasses import dataclass, field
from datetime import datetime


def _ext(path: str | None) -> str | None:
    if not path:
        return None
    name = path.replace("/", "\\").split("\\")[-1]
    return ("." + name.rsplit(".", 1)[1].lower()) if "." in name else ""


@dataclass
class NormalizedEvent:
    timestamp: datetime
    kind: str                      # process_create | image_load | behavior | dns_query | network_connect
                                   #   (dns_query/network_connect are engine-blind: build_graph drops them,
                                   #    they feed only the read-only IOC overlay — see DATA_MODEL.md §1.4)
    host: str
    event_id: object
    user: str | None = None
    # process
    process_guid: str | None = None
    process_name: str | None = None
    process_path: str | None = None
    command_line: str | None = None
    parent_process_guid: str | None = None
    parent_process_name: str | None = None
    integrity_level: str | None = None
    user_sid: str | None = None
    hashes: dict = field(default_factory=dict)
    # image load
    image_loaded: str | None = None
    extension: str | None = None
    signed: bool | None = None
    signature_vendor: str | None = None
    is_injected: bool = False
    api_hooking_detected: bool = False
    hooked_functions: list = field(default_factory=list)
    # behavior
    behavior: str | None = None
    target: str | None = None
    granted_access: str | None = None
    reason: str | None = None
    # network (Increment 2: optional + inert; the matcher never reads this — domain is in no field map)
    domain: str | None = None
    # network-connection (Increment 3: optional + inert; Sysmon EID 3 / DestinationIp + DestinationPort).
    # dest_ip is the matchable IOC value; dest_port is context-only. NEITHER is in any criteria field map.
    dest_ip: str | None = None
    dest_port: int | None = None
    # provenance (P1: optional + inert; the matcher never reads these)
    source_type: str | None = None
    os_family: str | None = None
    raw_event_type: str | None = None
