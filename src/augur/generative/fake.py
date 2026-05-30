from augur.generative.base import GenerationRequest

SAMPLE_VALID_YAML = """\
scenario_metadata:
  scenario_id: "SCEN-GEN-0001"
  name: "Generated: PowerShell Encoded Exec then LSASS Access"
  description: "Mutation candidate."
  severity: "HIGH"
  mitre_mappings:
    - { tactic: "TA0002", technique: "T1059.001" }
    - { tactic: "TA0006", technique: "T1003" }
spatial_constraints:
  applicable_zones: ["User_Endpoint"]
  critical_assets_only: false
  required_log_sources: ["Windows_Sysmon", "EDR_Telemetry"]
attack_sequence_flow:
  steps:
    - step_id: 1
      name: "Encoded_PowerShell"
      matching_criteria:
        Node_Type: "Process"
        ProcessName: { in: ["powershell.exe"] }
        CommandLine: { regex: ".*-enc.*" }
    - step_id: 2
      name: "Child_Rundll32"
      temporal_link: { previous_step: 1, link_scope: same_host, min_time_delta_seconds: 0, max_time_delta_seconds: 60 }
      matching_criteria:
        Node_Type: "Process"
        ProcessName: { in: ["rundll32.exe"] }
    - step_id: 3
      name: "LSASS_Access"
      temporal_link: { previous_step: 2, link_scope: same_host, min_time_delta_seconds: 0, max_time_delta_seconds: 300 }
      matching_criteria:
        Node_Type: "Process"
        TargetProcess: "lsass.exe"
        GrantedAccess: "0x1410"
actionable_hunting_outputs:
  validation_queries:
    - { engine: "KQL", query: "DeviceProcessEvents | where FileName == 'powershell.exe'" }
"""

SAMPLE_INVALID_YAML = "scenario_metadata: not valid\nthis is: missing everything\n"


class FakeScenarioGenerator:
    """Deterministic generator for the default test suite (no network)."""
    def __init__(self, include_invalid: bool = False) -> None:
        self.include_invalid = include_invalid

    def generate(self, request: GenerationRequest, n: int) -> list[str]:
        out: list[str] = []
        for i in range(n):
            if self.include_invalid and i == 0:
                out.append(SAMPLE_INVALID_YAML)
                continue
            out.append(SAMPLE_VALID_YAML.replace("SCEN-GEN-0001", f"SCEN-GEN-{i:04d}"))
        return out
