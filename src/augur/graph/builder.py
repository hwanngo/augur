from dataclasses import dataclass, field

from augur.graph.interface import GraphBackend
from augur.graph.models import HostNode, ProcessNode, FileNode
from augur.normalize.ecs import NormalizedEvent
from augur.topology.network import Topology


@dataclass
class IngestState:
    """Cross-batch carry-over state for incremental ingest.

    ``build_graph`` used these as per-call locals. For streaming, they MUST persist across batches:
    ``load_seq`` keys FileNode ids as ``{guid}|{image}|{seq}`` — resetting it per batch would mint a
    duplicate ``seq=0`` id for the same process re-loading the same image in a later batch. Kept
    monotonic (never decremented on eviction) so a re-load after a prune gets a fresh, non-colliding id.
    """
    seen_hosts: dict[str, HostNode] = field(default_factory=dict)
    load_seq: dict[str, int] = field(default_factory=dict)


def ingest_events(events: list[NormalizedEvent], topology: Topology, backend: GraphBackend,
                  *, state: IngestState | None = None) -> IngestState:
    """Append events to the backend (UPSERT, no reset). The single source of truth for graph
    construction — ``build_graph`` is a thin reset()+ingest wrapper, so the one-shot and streaming
    paths run byte-identical upsert code. Returns the (possibly newly created) IngestState."""
    state = state if state is not None else IngestState()
    seen_hosts = state.seen_hosts
    load_seq = state.load_seq

    def ensure_host(hostname: str) -> HostNode:
        key = hostname.lower()
        if key not in seen_hosts:
            asset = topology.lookup(hostname)
            zone, crit = topology.enrich(hostname)
            host = HostNode(id=key, hostname=hostname, ip=(asset.ip if asset else "0.0.0.0"),
                            os=(asset.os if asset else "unknown"), zone=zone, criticality=crit)
            backend.add_host(host)
            seen_hosts[key] = host
        return seen_hosts[key]

    for ev in events:
        host = ensure_host(ev.host)
        if ev.kind == "process_create":
            proc = ProcessNode(id=ev.process_guid, name=ev.process_name, path=ev.process_path,
                               command_line=ev.command_line, parent_guid=ev.parent_process_guid,
                               parent_process_name=ev.parent_process_name, host=ev.host,
                               timestamp=ev.timestamp, user_sid=ev.user_sid,
                               integrity_level=ev.integrity_level, hashes=ev.hashes)
            backend.add_process(proc)
            backend.add_edge(proc.id, host.id, "RUNS_ON", ev.timestamp)
            if ev.parent_process_guid:
                backend.add_edge(ev.parent_process_guid, proc.id, "SPAWNED", ev.timestamp)
        elif ev.kind == "image_load":
            seq = load_seq.get(ev.process_guid, 0)
            load_seq[ev.process_guid] = seq + 1
            fid = f"{ev.process_guid}|{ev.image_loaded}|{seq}"
            fnode = FileNode(id=fid, name=(ev.image_loaded or "").replace("/", "\\").split("\\")[-1],
                             path=ev.image_loaded, extension=ev.extension,
                             is_signed=ev.signed, is_injected=ev.is_injected,
                             api_hooking_detected=ev.api_hooking_detected, host=ev.host,
                             timestamp=ev.timestamp, signature_vendor=ev.signature_vendor,
                             hooked_functions=ev.hooked_functions)
            backend.add_file(fnode)
            backend.add_edge(ev.process_guid, fid, "LOADED", ev.timestamp, is_injected=ev.is_injected)
        elif ev.kind == "behavior":
            if backend.get_node(ev.process_guid) is None:
                # First real-data-driven correctness fix: a behavior event is its own provenance of
                # last resort when the actor's process_create (EID 1) predates the capture window.
                # if-absent ⇒ strict NO-OP on synthetic data (the actor always has a process_create
                # first there, so get_node is non-None). Mirrors the process_create branch's
                # ProcessNode shape exactly so an upserted node is shaped identically to a normal one.
                # No RUNS_ON edge: host_of's name-fallback keeps Topology authoritative for zone.
                backend.add_process(ProcessNode(
                    id=ev.process_guid, name=ev.process_name, path=ev.process_path,
                    command_line=ev.command_line, parent_guid=ev.parent_process_guid,
                    parent_process_name=ev.parent_process_name, host=ev.host,
                    timestamp=ev.timestamp, user_sid=ev.user_sid,
                    integrity_level=ev.integrity_level, hashes=ev.hashes))
            backend.add_edge(ev.process_guid, ev.process_guid, "EXHIBITED", ev.timestamp,
                             behavior=ev.behavior, target=ev.target,
                             granted_access=ev.granted_access, reason=ev.reason)
    return state


def build_graph(events: list[NormalizedEvent], topology: Topology, backend: GraphBackend) -> None:
    """One-shot build: reset the backend, then ingest. Byte-identical to the pre-refactor behavior —
    a fresh IngestState per call reproduces the old per-call locals exactly."""
    backend.reset()
    ingest_events(events, topology, backend)
