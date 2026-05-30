from augur.engine.criteria import (
    match_value, is_behavior_step, node_matches, behavior_edge_matches, node_matches_nonbehavior,
)
from augur.graph.models import ProcessNode, FileNode


def test_match_value_operators():
    assert match_value("a.exe", "a.exe") is True
    assert match_value({"regex": r"^C:\\.*\.exe$"}, "C:\\x\\a.exe") is True
    assert match_value({"in": ["a", "b"]}, "b") is True
    assert match_value({"equals": False}, False) is True
    assert match_value({"exists": True}, "x") is True
    assert match_value({"exists": False}, None) is True
    assert match_value("a.exe", "b.exe") is False


def test_is_behavior_step():
    assert is_behavior_step({"Node_Type": "Process", "TargetProcess": "lsass.exe"}) is True
    assert is_behavior_step({"Node_Type": "Process", "Behavior_Markers": ["x"]}) is True
    assert is_behavior_step({"Node_Type": "Process", "ProcessName": "a.exe"}) is False


def test_node_matches_process_and_file():
    p = ProcessNode(id="p", name="rundll32.exe", path="C:\\t.exe", command_line="x",
                    parent_guid=None, parent_process_name="evil.exe", host="H", timestamp=None)
    assert node_matches(p, {"Node_Type": "Process", "ProcessName": {"in": ["rundll32.exe"]}}) is True
    assert node_matches(p, {"Node_Type": "Process", "ProcessName": "regsvr32.exe"}) is False
    f = FileNode(id="f", name="x.dll", path="C:\\x.dll", extension=".dll", is_signed=False,
                 is_injected=True, api_hooking_detected=False, host="H", timestamp=None)
    assert node_matches(f, {"Node_Type": "File", "Extension": ".dll", "IsSigned": False, "IsInjected": True}) is True


def test_behavior_edge_matches():
    attrs = {"behavior": "lsass_access", "target": "lsass.exe", "granted_access": "0x1410"}
    assert behavior_edge_matches(attrs, {"Node_Type": "Process", "TargetProcess": "lsass.exe",
                                         "GrantedAccess": "0x1410"}) is True
    assert behavior_edge_matches({"behavior": "credential_dump"},
                                 {"Node_Type": "Process", "Behavior_Markers": ["credential_dump", "x"]}) is True
    assert behavior_edge_matches({"behavior": "other"},
                                 {"Node_Type": "Process", "Behavior_Markers": ["credential_dump"]}) is False
