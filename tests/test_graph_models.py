from augur.graph.models import HostNode, ProcessNode, FileNode, Edge
from augur.graph.interface import GraphBackend
from augur.enums import Zone, Criticality
import abc


def test_node_types():
    h = HostNode(id="hr_user_pc", hostname="HR_User_PC", ip="1.2.3.4", os="Win11",
                 zone=Zone.User_Endpoint, criticality=Criticality.MEDIUM)
    assert h.node_type == "Host"
    p = ProcessNode(id="p1", name="evil.exe", path="C:\\x.exe", command_line="x",
                    parent_guid="p0", parent_process_name="explorer.exe", host="HR_User_PC",
                    timestamp=None)
    assert p.node_type == "Process"
    f = FileNode(id="p1|x.dll|0", name="x.dll", path="C:\\x.dll", extension=".dll",
                 is_signed=False, is_injected=True, api_hooking_detected=False, host="HR_User_PC",
                 timestamp=None)
    assert f.node_type == "File"


def test_backend_is_abstract():
    assert issubclass(GraphBackend, abc.ABC)
    with_methods = {"add_host", "add_process", "add_file", "add_edge", "find_nodes",
                    "edges_from", "host_of", "get_node", "reset"}
    assert with_methods <= set(dir(GraphBackend))
