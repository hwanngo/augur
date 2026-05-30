import yaml
from augur.scenarios.schema import Scenario


def _scn(meta_extra=""):
    return yaml.safe_load(f"""
scenario_metadata:
  scenario_id: "SCEN-TEST-OS"
  name: "t"
  description: "d"
  severity: "HIGH"
  mitre_mappings: [{{tactic: "TA0001", technique: "T1059"}}]
  {meta_extra}
spatial_constraints: {{applicable_zones: ["User_Endpoint"], critical_assets_only: false, required_log_sources: ["x"]}}
attack_sequence_flow:
  steps:
    - {{step_id: 1, name: a, matching_criteria: {{Node_Type: Process, ProcessName: {{in: [x]}}}}}}
    - {{step_id: 2, name: b, temporal_link: {{previous_step: 1, link_scope: same_host, min_time_delta_seconds: 0, max_time_delta_seconds: 60}}, matching_criteria: {{Node_Type: Process, ProcessName: {{in: [y]}}}}}}
    - {{step_id: 3, name: c, temporal_link: {{previous_step: 2, link_scope: same_host, min_time_delta_seconds: 0, max_time_delta_seconds: 60}}, matching_criteria: {{Node_Type: Process, ProcessName: {{in: [z]}}}}}}
actionable_hunting_outputs: {{validation_queries: [{{engine: "KQL", query: "x"}}]}}
""")


def test_os_family_defaults_to_windows():
    assert Scenario(**_scn()).os_family == "windows"


def test_os_family_can_be_set():
    assert Scenario(**_scn('os_family: "linux"')).os_family == "linux"
