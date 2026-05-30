from datetime import datetime
from typing import Callable
import networkx as nx
from augur.graph.interface import GraphBackend, Node
from augur.graph.models import HostNode, ProcessNode, FileNode, Edge
from augur.graph.eviction import PruneStats


class NetworkXBackend(GraphBackend):
    def __init__(self) -> None:
        self._g = nx.MultiDiGraph()

    def _add_node(self, node: Node) -> None:
        self._g.add_node(node.id, obj=node, node_type=node.node_type)

    def add_host(self, host: HostNode) -> None:
        self._add_node(host)

    def add_process(self, proc: ProcessNode) -> None:
        self._add_node(proc)

    def add_file(self, f: FileNode) -> None:
        self._add_node(f)

    def add_edge(self, src_id, dst_id, edge_type, timestamp: datetime, **attrs) -> None:
        self._g.add_edge(src_id, dst_id, edge_type=edge_type, timestamp=timestamp, attrs=dict(attrs))

    def find_nodes(self, node_type: str, predicate: Callable[[Node], bool]) -> list[Node]:
        out = []
        for _id, data in self._g.nodes(data=True):
            if data.get("node_type") == node_type:
                obj = data["obj"]
                if predicate(obj):
                    out.append(obj)
        return sorted(out, key=lambda n: ((n.timestamp.timestamp() if getattr(n, "timestamp", None) else 0), n.id))

    def edges_from(self, node_id: str, edge_type: str | None = None) -> list[Edge]:
        out = []
        if node_id not in self._g:
            return out
        for _s, d, data in self._g.out_edges(node_id, data=True):
            if edge_type is None or data["edge_type"] == edge_type:
                out.append(Edge(src_id=node_id, dst_id=d, edge_type=data["edge_type"],
                                timestamp=data["timestamp"], attrs=data["attrs"]))
        return sorted(out, key=lambda e: (e.timestamp.timestamp(), e.dst_id))

    def edges_to(self, node_id: str, edge_type: str | None = None) -> list[Edge]:
        out = []
        if node_id not in self._g:
            return out
        for s, _d, data in self._g.in_edges(node_id, data=True):
            if edge_type is None or data["edge_type"] == edge_type:
                out.append(Edge(src_id=s, dst_id=node_id, edge_type=data["edge_type"],
                                timestamp=data["timestamp"], attrs=data["attrs"]))
        return sorted(out, key=lambda e: (e.timestamp.timestamp(), e.src_id))

    def host_of(self, node_id: str) -> HostNode | None:
        node = self.get_node(node_id)
        if isinstance(node, HostNode):
            return node
        if isinstance(node, ProcessNode):
            for e in self.edges_from(node_id, "RUNS_ON"):
                tgt = self.get_node(e.dst_id)
                if isinstance(tgt, HostNode):
                    return tgt
            # fallback: match by hostname attr
            return self._host_by_name(node.host)
        if isinstance(node, FileNode):
            # find process that LOADED this file
            for _s, _d, data in self._g.in_edges(node_id, data=True):
                if data["edge_type"] == "LOADED":
                    return self.host_of(_s)
            return self._host_by_name(node.host)
        return None

    def _host_by_name(self, hostname: str | None) -> HostNode | None:
        if not hostname:
            return None
        for h in self.find_nodes("Host", lambda n: n.hostname.lower() == hostname.lower()):
            return h
        return None

    def get_node(self, node_id: str) -> Node | None:
        if node_id in self._g:
            return self._g.nodes[node_id].get("obj")
        return None

    def reset(self) -> None:
        self._g.clear()

    def prune_before(self, cutoff: datetime) -> PruneStats:
        """Time-window eviction. Removes, in order:
          1. Process/File nodes whose `timestamp < cutoff` (strict; `== cutoff` is kept, matching the
             `>= cutoff` event filter scan.py's windowed rebuild uses). Removing a node drops its incident
             edges automatically (NetworkX), covering all orphan cases (RUNS_ON/SPAWNED/LOADED/EXHIBITED).
          2. Any remaining edge whose `timestamp < cutoff`, even if both endpoints survive (stale EXHIBITED
             self-edges and LOADED edges carry their own event time).
        HostNodes have no timestamp ⇒ structural ⇒ never evicted. After this call no node or edge with
        ts < cutoff remains. Idempotent and monotonic (cutoff only advances)."""
        g = self._g
        doomed = [nid for nid, data in g.nodes(data=True)
                  if (ts := getattr(data.get("obj"), "timestamp", None)) is not None and ts < cutoff]
        edges_before = g.number_of_edges()
        g.remove_nodes_from(doomed)
        stale_edges = [(u, v, k) for u, v, k, data in g.edges(keys=True, data=True)
                       if data["timestamp"] < cutoff]
        g.remove_edges_from(stale_edges)
        # Bare anchor nodes (auto-created by add_edge to an uncreated parent guid) carry no `obj` and
        # no timestamp. Once their edge is gone they are pure orphans — drop them so they don't linger
        # unbounded across a stream. Hosts have an `obj` (HostNode) ⇒ kept even when isolated.
        bare_orphans = [n for n in list(g.nodes)
                        if g.nodes[n].get("obj") is None and g.degree(n) == 0]
        g.remove_nodes_from(bare_orphans)
        return PruneStats(nodes_removed=len(doomed) + len(bare_orphans),
                          edges_removed=edges_before - g.number_of_edges(), cutoff=cutoff)
