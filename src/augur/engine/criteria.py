import re
from typing import Any
from augur.graph.models import ProcessNode, FileNode

BEHAVIOR_KEYS = {"TargetProcess", "GrantedAccess", "Behavior_Markers"}

PROCESS_KEY_MAP = {
    "ProcessName": "name", "ProcessPath": "path", "CommandLine": "command_line",
    "ParentProcessName": "parent_process_name", "IntegrityLevel": "integrity_level",
    "ProcessGuid": "id",
}
FILE_KEY_MAP = {
    "Extension": "extension", "IsSigned": "is_signed", "IsInjected": "is_injected",
    "ApiHookingDetected": "api_hooking_detected", "FileName": "name", "Path": "path",
    "SignatureVendor": "signature_vendor",
}
_SKIP = {"Node_Type"} | BEHAVIOR_KEYS


def match_value(criterion: Any, actual: Any) -> bool:
    if isinstance(criterion, dict):
        if "regex" in criterion:
            return actual is not None and re.search(criterion["regex"], str(actual)) is not None
        if "equals" in criterion:
            return actual == criterion["equals"]
        if "in" in criterion:
            return actual in criterion["in"]
        if "exists" in criterion:
            return (actual is not None) == bool(criterion["exists"])
        raise ValueError(f"unknown operator in {criterion}")
    return actual == criterion


def is_behavior_step(criteria: dict) -> bool:
    return any(k in BEHAVIOR_KEYS for k in criteria)


def _key_map(node) -> dict:
    return PROCESS_KEY_MAP if isinstance(node, ProcessNode) else FILE_KEY_MAP


def node_matches(node, criteria: dict) -> bool:
    key_map = _key_map(node)
    for key, crit in criteria.items():
        if key in _SKIP:
            continue
        attr = key_map.get(key)
        if attr is None:
            return False
        if not match_value(crit, getattr(node, attr, None)):
            return False
    return True


def node_matches_nonbehavior(node, criteria: dict) -> bool:
    """For behavior steps: check only the non-behavior process attributes on the source node."""
    return node_matches(node, criteria)


def behavior_edge_matches(edge_attrs: dict, criteria: dict) -> bool:
    if "TargetProcess" in criteria and not match_value(criteria["TargetProcess"], edge_attrs.get("target")):
        return False
    if "GrantedAccess" in criteria and not match_value(criteria["GrantedAccess"], edge_attrs.get("granted_access")):
        return False
    if "Behavior_Markers" in criteria:
        if edge_attrs.get("behavior") not in criteria["Behavior_Markers"]:
            return False
    return True
