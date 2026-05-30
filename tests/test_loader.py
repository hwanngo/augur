from pathlib import Path
import pytest
from augur.scenarios.loader import load_scenario, load_scenarios
from augur.scenarios.schema import Scenario


def test_load_single_scenario(tmp_path: Path):
    yaml_text = """
scenario_metadata:
  scenario_id: SCEN-X-1
  name: X
  description: d
  severity: HIGH
  mitre_mappings: [{tactic: TA0006, technique: T1003}]
spatial_constraints:
  applicable_zones: [User_Endpoint]
  required_log_sources: [Windows_Sysmon]
attack_sequence_flow:
  steps:
    - {step_id: 1, name: s1, matching_criteria: {Node_Type: Process, ProcessName: a.exe}}
actionable_hunting_outputs:
  validation_queries: [{engine: KQL, query: "x"}]
"""
    f = tmp_path / "s.yaml"
    f.write_text(yaml_text)
    s = load_scenario(f)
    assert isinstance(s, Scenario)
    assert s.scenario_id == "SCEN-X-1"


def test_load_dir_returns_sorted_list(tmp_path: Path):
    (tmp_path / "a.yaml").write_text(_scn("SCEN-A"))
    (tmp_path / "b.yaml").write_text(_scn("SCEN-B"))
    scns = load_scenarios(tmp_path)
    assert [s.scenario_id for s in scns] == ["SCEN-A", "SCEN-B"]


def _scn(sid: str) -> str:
    return f"""
scenario_metadata: {{scenario_id: {sid}, name: n, description: d, severity: LOW,
  mitre_mappings: [{{tactic: TA0001, technique: T1059}}]}}
spatial_constraints: {{applicable_zones: [User_Endpoint], required_log_sources: [Windows_Sysmon]}}
attack_sequence_flow: {{steps: [{{step_id: 1, name: s, matching_criteria: {{Node_Type: Process}}}}]}}
actionable_hunting_outputs: {{validation_queries: [{{engine: KQL, query: x}}]}}
"""
