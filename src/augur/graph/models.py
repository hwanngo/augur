from dataclasses import dataclass, field
from datetime import datetime
from augur.enums import Zone, Criticality


@dataclass
class HostNode:
    id: str
    hostname: str
    ip: str
    os: str
    zone: Zone
    criticality: Criticality
    node_type: str = "Host"


@dataclass
class ProcessNode:
    id: str
    name: str | None
    path: str | None
    command_line: str | None
    parent_guid: str | None
    parent_process_name: str | None
    host: str
    timestamp: datetime | None
    user_sid: str | None = None
    integrity_level: str | None = None
    hashes: dict = field(default_factory=dict)
    node_type: str = "Process"


@dataclass
class FileNode:
    id: str
    name: str | None
    path: str | None
    extension: str | None
    is_signed: bool | None
    is_injected: bool
    api_hooking_detected: bool
    host: str
    timestamp: datetime | None
    signature_vendor: str | None = None
    hooked_functions: list = field(default_factory=list)
    node_type: str = "File"


@dataclass
class Edge:
    src_id: str
    dst_id: str
    edge_type: str          # SPAWNED | LOADED | EXHIBITED | RUNS_ON
    timestamp: datetime
    attrs: dict = field(default_factory=dict)
