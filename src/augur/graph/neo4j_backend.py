from datetime import datetime
from typing import Callable
from augur.graph.interface import GraphBackend, Node
from augur.graph.models import HostNode, ProcessNode, FileNode, Edge
from augur.enums import Zone, Criticality


class Neo4jBackend(GraphBackend):
    """Opt-in adapter. Requires `pip install augur[neo4j]` and a running Neo4j.

    Stores each node's full attribute dict as properties and resolves host/edges via Cypher.
    Not exercised by the default test suite (see tests/test_neo4j_backend.py).
    """

    def __init__(self, uri: str, user: str, password: str) -> None:
        from neo4j import GraphDatabase
        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self._driver.close()

    def _run(self, cypher: str, **params):
        with self._driver.session() as s:
            return list(s.run(cypher, **params))

    def add_host(self, host: HostNode) -> None:
        self._run(
            "MERGE (h:Host {id:$id}) SET h.hostname=$hostname, h.ip=$ip, h.os=$os, "
            "h.zone=$zone, h.criticality=$crit",
            id=host.id, hostname=host.hostname, ip=host.ip, os=host.os,
            zone=host.zone.value, crit=host.criticality.value,
        )

    def add_process(self, proc: ProcessNode) -> None:
        self._run(
            "MERGE (p:Process {id:$id}) SET p.name=$name, p.path=$path, p.command_line=$cl, "
            "p.parent_process_name=$ppn, p.host=$host, p.timestamp=$ts, p.integrity_level=$il",
            id=proc.id, name=proc.name, path=proc.path, cl=proc.command_line,
            ppn=proc.parent_process_name, host=proc.host,
            ts=(proc.timestamp.isoformat() if proc.timestamp else None), il=proc.integrity_level,
        )

    def add_file(self, f: FileNode) -> None:
        self._run(
            "MERGE (f:File {id:$id}) SET f.name=$name, f.path=$path, f.extension=$ext, "
            "f.is_signed=$signed, f.is_injected=$inj, f.api_hooking_detected=$hook, "
            "f.host=$host, f.timestamp=$ts",
            id=f.id, name=f.name, path=f.path, ext=f.extension, signed=f.is_signed,
            inj=f.is_injected, hook=f.api_hooking_detected, host=f.host,
            ts=(f.timestamp.isoformat() if f.timestamp else None),
        )

    def add_edge(self, src_id, dst_id, edge_type, timestamp: datetime, **attrs) -> None:
        self._run(
            f"MATCH (a {{id:$src}}), (b {{id:$dst}}) "
            f"MERGE (a)-[r:{edge_type} {{ts:$ts}}]->(b) SET r += $attrs",
            src=src_id, dst=dst_id, ts=timestamp.isoformat(), attrs=attrs,
        )

    def _to_node(self, labels, props) -> Node:
        if "Host" in labels:
            return HostNode(id=props["id"], hostname=props["hostname"], ip=props.get("ip", ""),
                            os=props.get("os", ""), zone=Zone(props["zone"]),
                            criticality=Criticality(props["criticality"]))
        if "Process" in labels:
            ts = datetime.fromisoformat(props["timestamp"]) if props.get("timestamp") else None
            return ProcessNode(id=props["id"], name=props.get("name"), path=props.get("path"),
                               command_line=props.get("command_line"), parent_guid=None,
                               parent_process_name=props.get("parent_process_name"),
                               host=props.get("host", ""), timestamp=ts,
                               integrity_level=props.get("integrity_level"))
        ts = datetime.fromisoformat(props["timestamp"]) if props.get("timestamp") else None
        return FileNode(id=props["id"], name=props.get("name"), path=props.get("path"),
                        extension=props.get("extension"), is_signed=props.get("is_signed"),
                        is_injected=props.get("is_injected", False),
                        api_hooking_detected=props.get("api_hooking_detected", False),
                        host=props.get("host", ""), timestamp=ts)

    def find_nodes(self, node_type: str, predicate: Callable[[Node], bool]) -> list[Node]:
        rows = self._run(f"MATCH (n:{node_type}) RETURN labels(n) AS l, properties(n) AS p")
        nodes = [self._to_node(r["l"], r["p"]) for r in rows]
        nodes = [n for n in nodes if predicate(n)]
        return sorted(nodes, key=lambda n: ((n.timestamp.timestamp() if getattr(n, "timestamp", None) else 0), n.id))

    def edges_from(self, node_id: str, edge_type: str | None = None) -> list[Edge]:
        rel = f":{edge_type}" if edge_type else ""
        rows = self._run(
            f"MATCH (a {{id:$id}})-[r{rel}]->(b) RETURN type(r) AS t, b.id AS dst, "
            f"r.ts AS ts, properties(r) AS p", id=node_id)
        edges = []
        for r in rows:
            attrs = {k: v for k, v in r["p"].items() if k != "ts"}
            edges.append(Edge(src_id=node_id, dst_id=r["dst"], edge_type=r["t"],
                              timestamp=datetime.fromisoformat(r["ts"]), attrs=attrs))
        return sorted(edges, key=lambda e: (e.timestamp.timestamp(), e.dst_id))

    def edges_to(self, node_id: str, edge_type: str | None = None) -> list[Edge]:
        rel = f":{edge_type}" if edge_type else ""
        rows = self._run(
            f"MATCH (a)-[r{rel}]->(b {{id:$id}}) RETURN type(r) AS t, a.id AS src, "
            f"r.ts AS ts, properties(r) AS p", id=node_id)
        edges = []
        for r in rows:
            attrs = {k: v for k, v in r["p"].items() if k != "ts"}
            edges.append(Edge(src_id=r["src"], dst_id=node_id, edge_type=r["t"],
                              timestamp=datetime.fromisoformat(r["ts"]), attrs=attrs))
        return sorted(edges, key=lambda e: (e.timestamp.timestamp(), e.src_id))

    def host_of(self, node_id: str) -> HostNode | None:
        node = self.get_node(node_id)
        if isinstance(node, HostNode):
            return node
        if isinstance(node, FileNode):
            rows = self._run("MATCH (p:Process)-[:LOADED]->(f {id:$id}) RETURN p.id AS pid", id=node_id)
            return self.host_of(rows[0]["pid"]) if rows else self._host_by_name(node.host)
        if isinstance(node, ProcessNode):
            rows = self._run("MATCH (p {id:$id})-[:RUNS_ON]->(h:Host) RETURN properties(h) AS p, labels(h) AS l", id=node_id)
            if rows:
                return self._to_node(rows[0]["l"], rows[0]["p"])
            return self._host_by_name(node.host)
        return None

    def _host_by_name(self, hostname: str | None) -> HostNode | None:
        if not hostname:
            return None
        rows = self._run("MATCH (h:Host) WHERE toLower(h.hostname)=toLower($n) RETURN properties(h) AS p, labels(h) AS l", n=hostname)
        return self._to_node(rows[0]["l"], rows[0]["p"]) if rows else None

    def get_node(self, node_id: str) -> Node | None:
        rows = self._run("MATCH (n {id:$id}) RETURN labels(n) AS l, properties(n) AS p", id=node_id)
        return self._to_node(rows[0]["l"], rows[0]["p"]) if rows else None

    def reset(self) -> None:
        self._run("MATCH (n) DETACH DELETE n")
