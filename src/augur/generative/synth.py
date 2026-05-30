import re
from datetime import datetime, timedelta, timezone

from augur.engine.criteria import is_behavior_step
from augur.enums import Criticality
from augur.scenarios.schema import Scenario
from augur.topology.network import Topology

_BASE = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)


def _sample_value(crit):
    """A concrete value satisfying a single matching-criteria value (literal or operator)."""
    if isinstance(crit, dict):
        if "in" in crit:
            return crit["in"][0]
        if "equals" in crit:
            return crit["equals"]
        if "exists" in crit:
            return "present" if crit["exists"] else None
        if "regex" in crit:
            return _sample_regex(crit["regex"])
    return crit


def _sample_regex(pattern: str) -> str | None:
    """Best-effort string matching a regex (covers the library's patterns). None if unsure."""
    s = pattern
    s = s.replace("^", "").replace("$", "")
    # first alternation branch inside groups: (a|b) -> a
    s = re.sub(r"\(([^()|]+)\|[^()]*\)", r"\1", s)
    s = s.replace(".*", "x").replace(".+", "x").replace(".", "x")
    s = s.replace("\\\\", "\\").replace("\\x", "x")     # \\ -> \, \. already became x
    s = re.sub(r"\[[^\]]*\]", "a", s)                   # [abc] -> a
    s = s.replace("\\s", " ").replace("\\S", "x").replace("\\d", "1").replace("\\w", "w")
    s = s.replace("+", "").replace("*", "").replace("?", "")
    candidate = ("C:\\Users\\u\\AppData\\Local\\Temp\\" + s + ".exe") if "Temp" in pattern else s
    try:
        return candidate if re.search(pattern, candidate) else (s if re.search(pattern, s) else None)
    except re.error:
        return None


def _pick_hosts(scenario: Scenario, topology: Topology) -> list[str]:
    """A host in an applicable zone (CRITICAL if required), plus a second for cross_host steps."""
    sc = scenario.spatial_constraints
    ok = [a for a in topology.assets if a.zone.value in sc.applicable_zones
          and (not sc.critical_assets_only or a.criticality == Criticality.CRITICAL)]
    if not ok:
        return []
    return [a.hostname for a in ok[:2]] if len(ok) >= 2 else [ok[0].hostname, ok[0].hostname]


def synthesize_trace(scenario: Scenario, topology: Topology) -> list[dict] | None:
    hosts = _pick_hosts(scenario, topology)
    if not hosts:
        return None
    h0, h1 = hosts[0], hosts[1]
    events: list[dict] = []
    cur_host = h0
    t = _BASE
    proc_seq = 0
    for step in scenario.attack_sequence_flow.steps:
        crit = step.matching_criteria
        link = step.temporal_link
        if link is not None:
            # advance within the window; choose a host per link_scope
            t = t + timedelta(seconds=min(link.max_time_delta_seconds, max(link.min_time_delta_seconds, 5)))
            if link.link_scope.value == "cross_host":
                cur_host = h1 if cur_host == h0 else h0
            elif link.link_scope.value == "same_host":
                pass  # keep cur_host
        proc_seq += 1
        guid = f"syn-p{proc_seq}"
        # always emit a process-create so host resolution works for any node/edge
        pc = {"timestamp": t.isoformat(), "event_id": 1, "host": cur_host, "user": "synth",
              "process_guid": guid, "process_name": "proc.exe",
              "process_path": "C:\\Windows\\proc.exe", "command_line": "proc",
              "parent_process_name": "explorer.exe", "integrity_level": "Medium"}
        # apply process-attribute criteria
        for key in ("ProcessName", "ProcessPath", "CommandLine", "ParentProcessName", "IntegrityLevel"):
            if key in crit:
                v = _sample_value(crit[key])
                if v is None:
                    return None
                field = {"ProcessName": "process_name", "ProcessPath": "process_path",
                         "CommandLine": "command_line", "ParentProcessName": "parent_process_name",
                         "IntegrityLevel": "integrity_level"}[key]
                pc[field] = v
        events.append(pc)

        if is_behavior_step(crit):
            edr = {"timestamp": t.isoformat(), "event_id": "edr", "host": cur_host, "process_guid": guid}
            if "TargetProcess" in crit:
                edr["target"] = _sample_value(crit["TargetProcess"])
            if "GrantedAccess" in crit:
                edr["granted_access"] = _sample_value(crit["GrantedAccess"])
            if "Behavior_Markers" in crit:
                markers = crit["Behavior_Markers"]
                edr["behavior"] = markers[0] if isinstance(markers, list) and markers else "marker"
            events.append(edr)
        elif crit.get("Node_Type") == "File":
            # Derive image_loaded from Path and/or FileName criteria.
            # FileNode.path == image_loaded; FileNode.name == last segment of image_loaded.
            # Priority: explicit Path criterion > construct from FileName + default dir.
            ext = _sample_value(crit.get("Extension", ".dll")) or ".dll"

            if "FileName" in crit:
                # FileName takes priority for the leaf name; embed in a path that also
                # satisfies any Path regex.
                fname_val = _sample_value(crit["FileName"])
                if fname_val is None:
                    return None
                if "Path" in crit:
                    path_val = _sample_value(crit["Path"])
                    if path_val is None:
                        return None
                    # Use the path_val as directory base + required filename as leaf.
                    base = path_val.replace("/", "\\").rsplit("\\", 1)[0]
                    image_loaded = base + "\\" + fname_val
                else:
                    image_loaded = "C:\\Windows\\System32\\" + fname_val
            elif "Path" in crit:
                path_val = _sample_value(crit["Path"])
                if path_val is None:
                    return None
                # Ensure the path has the required extension as the leaf filename.
                # path_val from _sample_regex may be a bare pattern fragment; wrap it
                # in a full Windows path so that both the path regex and the extension
                # check pass.
                leaf = "mod" + ext
                image_loaded = "C:\\" + path_val.strip("\\") + "\\" + leaf
            else:
                image_loaded = "C:\\x\\mod" + ext

            img = {"timestamp": t.isoformat(), "event_id": 7, "host": cur_host, "process_guid": guid,
                   "image_loaded": image_loaded}
            if "IsSigned" in crit:
                img["signed"] = _sample_value(crit["IsSigned"])
            if "IsInjected" in crit:
                img["is_injected"] = _sample_value(crit["IsInjected"])
            if "ApiHookingDetected" in crit:
                img["api_hooking_detected"] = _sample_value(crit["ApiHookingDetected"])
            events.append(img)
    return events
