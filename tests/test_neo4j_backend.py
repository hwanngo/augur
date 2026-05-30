import os
import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("AUGUR_NEO4J_TEST") != "1",
    reason="Neo4j integration test disabled (set AUGUR_NEO4J_TEST=1 with a running DB)",
)


def test_neo4j_backend_implements_interface():
    from augur.graph.neo4j_backend import Neo4jBackend
    from augur.graph.interface import GraphBackend
    assert issubclass(Neo4jBackend, GraphBackend)


def test_neo4j_roundtrip():
    from augur.graph.neo4j_backend import Neo4jBackend
    from augur.graph.models import HostNode, ProcessNode
    from augur.enums import Zone, Criticality
    from datetime import datetime, timezone
    b = Neo4jBackend(uri="bolt://localhost:7687", user="neo4j", password="augur")
    b.reset()
    b.add_host(HostNode(id="h", hostname="HR_User_PC", ip="1", os="o", zone=Zone.User_Endpoint, criticality=Criticality.MEDIUM))
    b.add_process(ProcessNode(id="p1", name="evil.exe", path="C:\\x", command_line="x",
                              parent_guid=None, parent_process_name=None, host="HR_User_PC",
                              timestamp=datetime(2026,5,1,tzinfo=timezone.utc)))
    b.add_edge("p1", "h", "RUNS_ON", datetime(2026,5,1,tzinfo=timezone.utc))
    assert b.host_of("p1").hostname == "HR_User_PC"
    incoming = b.edges_to("h", "RUNS_ON")
    assert [e.src_id for e in incoming] == ["p1"]
    b.close()
