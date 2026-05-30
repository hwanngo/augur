"""Investigation Pivot Graph — pure, deterministic, bounded k-hop neighborhood of a detection.

Seeds from a public detection dict's matched_steps (resolving the synthetic |EXH| behavior id to
its owning process), BFS-expands to `hops` deep over BOTH edge directions (edges_from + edges_to),
enriches node criticality/zone via topology.enrich, and returns a static node-link graph under a
MAX_NODES/MAX_EDGES budget with honest truncation. No engine/scoring/persistence import, no now().
"""
from augur.graph.interface import GraphBackend, Node
from augur.graph.models import HostNode, ProcessNode, FileNode
from augur.topology.network import Topology

DEFAULT_HOPS = 2
MAX_NODES = 300
MAX_EDGES = 600

HONESTY_NOTE = (
    "Edges are host-local causal relationships — process spawn (SPAWNED), module load "
    "(LOADED), exhibited behavior (EXHIBITED) — plus host membership (RUNS_ON). They are "
    "NOT network reachability or proof of lateral movement: the topology carries no host "
    "adjacency and every relationship shown is same-host. Expanded neighbors are drawn "
    "from the full knowledge graph for context, not from the matched detection alone."
)


def _resolve_seed_id(element_id: str) -> str:
    """Behavior steps carry a synthetic `f'{proc.id}|EXH|{i}'` element_id — resolve to the process."""
    return element_id.split("|EXH|")[0] if "|EXH|" in element_id else element_id


def _node_label(node: Node) -> str:
    if isinstance(node, HostNode):
        return node.hostname
    name = getattr(node, "name", None)
    return name or node.id


def _node_payload(node: Node, topology: Topology, hostname: str, seed: bool, hop: int) -> dict:
    zone, crit = topology.enrich(hostname)
    out = {
        "id": node.id,
        "node_type": node.node_type,
        "label": _node_label(node),
        "host": hostname,
        "criticality": crit.value,
        "zone": zone.value,
        "seed": seed,
        "hop": hop,
    }
    if isinstance(node, ProcessNode):
        out["name"] = node.name
        out["command"] = node.command_line
        out["integrity_level"] = node.integrity_level
    elif isinstance(node, FileNode):
        out["name"] = node.name
        out["path"] = node.path
        out["is_signed"] = node.is_signed
        out["is_injected"] = node.is_injected
        out["extension"] = node.extension
    return out


def _hostname_of(node: Node, backend: GraphBackend) -> str:
    if isinstance(node, HostNode):
        return node.hostname
    h = backend.host_of(node.id)
    if h is not None:
        return h.hostname
    return getattr(node, "host", "") or ""


def build_pivot_graph(detection: dict, backend: GraphBackend, topology: Topology,
                      *, hops: int = DEFAULT_HOPS) -> dict:
    hops = max(1, min(3, hops))

    # 1. Seed node set from matched_steps (resolve |EXH|, skip ids with no graph node).
    seed_ids: list[str] = []
    for st in detection["matched_steps"]:
        eid = st.get("element_id")
        if not eid:
            continue
        rid = _resolve_seed_id(eid)
        if backend.get_node(rid) is not None and rid not in seed_ids:
            seed_ids.append(rid)

    if not seed_ids:
        raise ValueError(
            f"no resolvable seed node for detection {detection.get('scenario_id')!r}")

    # depth[id] = BFS hop (0 for seeds).
    depth: dict[str, int] = {sid: 0 for sid in seed_ids}
    seed_set = set(seed_ids)

    # Spec §6.1 — always include each seed's host at hop 1, even for File seeds that have
    # no outgoing RUNS_ON and would otherwise miss their host at hops=1.
    _extra_host_ids: list[str] = []
    for sid in seed_ids:
        seed_node = backend.get_node(sid)
        if seed_node is not None and not isinstance(seed_node, HostNode):
            h = backend.host_of(sid)
            if h is not None and h.id not in depth:
                depth[h.id] = 1
                _extra_host_ids.append(h.id)

    # 2. BFS k-hop closure — Process/File nodes expand both directions (edges_from + edges_to);
    #    Host nodes are terminal context: only edges_from(host) is returned.
    #    This prevents a busy host's full co-resident process set from consuming the MAX_NODES
    #    budget before the seed's genuinely interesting causal nodes are discovered.
    def neighbor_edges(node_id):
        node = backend.get_node(node_id)
        out = backend.edges_from(node_id)
        if not isinstance(node, HostNode):
            out = out + backend.edges_to(node_id)
        return out

    nodes_total = 0
    edges_seen: dict[str, dict] = {}      # edge id -> emitted edge dict (dedupes EXHIBITED self-loops)
    kept_nodes: dict[str, dict] = {}      # node id -> node payload (insertion = discovery order)
    nodes_truncated = False

    def try_add_node(node_id: str, hop: int) -> bool:
        """Add a node payload if budget allows. Returns True if the node is in the kept set."""
        nonlocal nodes_total, nodes_truncated
        if node_id in kept_nodes:
            return True
        node = backend.get_node(node_id)
        if node is None:
            return False
        nodes_total += 1
        if len(kept_nodes) >= MAX_NODES:
            nodes_truncated = True
            return False
        hostname = _hostname_of(node, backend)
        kept_nodes[node_id] = _node_payload(node, topology, hostname,
                                            seed=node_id in seed_set, hop=hop)
        return True

    # Seed nodes first (deterministic: sort by (node_type, id)).
    for sid in sorted(seed_ids, key=lambda i: ((backend.get_node(i).node_type if backend.get_node(i) else ""), i)):
        try_add_node(sid, 0)

    # BFS frontier. Process queue sorted by (node_type, id) each level for determinism.
    # _extra_host_ids are hosts injected at hop-1 (spec §6.1); include them so their
    # neighbors are reachable at subsequent hops, but emit them now at hop 1.
    frontier = list(seed_ids)
    for hop in range(1, hops + 1):
        next_frontier: list[str] = []
        # On the first BFS iteration, add explicit seed hosts that BFS might not reach yet.
        if hop == 1:
            for hid in _extra_host_ids:
                try_add_node(hid, 1)
                next_frontier.append(hid)   # treat as discovered so their neighbors expand next hop
        for node_id in sorted(frontier, key=lambda i: ((backend.get_node(i).node_type if backend.get_node(i) else ""), i)):
            for e in neighbor_edges(node_id):
                other = e.dst_id if e.src_id == node_id else e.src_id
                if other not in depth:
                    depth[other] = hop
                    next_frontier.append(other)
                try_add_node(other, depth.get(other, hop))
        frontier = next_frontier

    # 3. Collect edges: only those with BOTH endpoints in the kept node set.
    kept_ids = set(kept_nodes)
    for node_id in list(kept_ids):
        for e in backend.edges_from(node_id):
            if e.dst_id not in kept_ids:
                continue
            eid = f"{e.src_id}->{e.dst_id}:{e.edge_type}:{e.timestamp.isoformat()}"
            if eid in edges_seen:
                continue
            payload = {"id": eid, "src": e.src_id, "dst": e.dst_id,
                       "edge_type": e.edge_type, "timestamp": e.timestamp.isoformat()}
            if e.edge_type == "LOADED":
                payload["is_injected"] = bool(e.attrs.get("is_injected", False))
            edges_seen[eid] = payload

    edges_total = len(edges_seen)
    edges_list = sorted(edges_seen.values(),
                        key=lambda e: (e["timestamp"], e["edge_type"], e["src"], e["dst"]))
    edges_truncated = False
    if len(edges_list) > MAX_EDGES:
        edges_truncated = True
        edges_list = edges_list[:MAX_EDGES]

    nodes_list = sorted(kept_nodes.values(), key=lambda n: (n["hop"], n["node_type"], n["id"]))

    return {
        "seed": {
            "scenario_id": detection["scenario_id"],
            "name": detection["name"],
            "severity": detection["severity"],
            "seed_node_ids": list(seed_ids),
            "affected_hosts": list(detection.get("affected_hosts", [])),
        },
        "nodes": nodes_list,
        "edges": edges_list,
        "summary": {
            "node_count": len(nodes_list),
            "edge_count": len(edges_list),
            "nodes_total": nodes_total,
            "edges_total": edges_total,
            "nodes_truncated": nodes_truncated,
            "edges_truncated": edges_truncated,
            "hops": hops,
            "honesty_note": HONESTY_NOTE,
        },
    }
