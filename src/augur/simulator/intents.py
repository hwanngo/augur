from dataclasses import dataclass
from datetime import datetime


@dataclass
class EventIntent:
    kind: str                       # process_create | image_load | behavior | dns_query | network_connect
    host: str
    timestamp: datetime
    pid: int | None = None
    ppid: int | None = None
    user: str | None = None
    process_name: str | None = None
    process_path: str | None = None
    command_line: str | None = None
    parent_process_name: str | None = None
    integrity_level: str | None = None
    image_loaded: str | None = None
    signed: bool | None = None
    is_injected: bool = False
    api_hooking_detected: bool = False
    behavior: str | None = None
    target: str | None = None
    granted_access: str | None = None
    hashes: dict | None = None      # optional override; Windows process_create derives one in the emitter
    domain: str | None = None       # Increment 2: queried name for a dns_query intent (Windows only)
    dest_ip: str | None = None      # Increment 3: dest IP for a network_connect intent (Windows only)
    dest_port: int | None = None    # Increment 3: dest port (context-only; not a matchable IOC in v1)
