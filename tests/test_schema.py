import pytest
from pydantic import ValidationError
from augur.scenarios.schema import Scenario
from augur.enums import Severity, LinkScope

VALID = {
    "scenario_metadata": {
        "scenario_id": "SCEN-T-001",
        "name": "Test Scenario",
        "description": "desc",
        "severity": "HIGH",
        "mitre_mappings": [{"tactic": "TA0006", "technique": "T1003"}],
    },
    "spatial_constraints": {
        "applicable_zones": ["User_Endpoint"],
        "critical_assets_only": False,
        "required_log_sources": ["Windows_Sysmon"],
    },
    "attack_sequence_flow": {
        "steps": [
            {"step_id": 1, "name": "s1", "matching_criteria": {"Node_Type": "Process", "ProcessName": "a.exe"}},
            {"step_id": 2, "name": "s2",
             "temporal_link": {"previous_step": 1, "min_time_delta_seconds": 0, "max_time_delta_seconds": 60},
             "matching_criteria": {"Node_Type": "Process", "TargetProcess": "lsass.exe"}},
        ]
    },
    "actionable_hunting_outputs": {
        "validation_queries": [{"engine": "KQL", "query": "DeviceProcessEvents | take 1"}]
    },
}


def test_valid_scenario_parses():
    s = Scenario(**VALID)
    assert s.scenario_metadata.severity == Severity.HIGH
    assert s.step_count == 2
    # step 1 has no temporal_link; step 2 defaults link_scope to same_host
    assert s.attack_sequence_flow.steps[0].temporal_link is None
    assert s.attack_sequence_flow.steps[1].temporal_link.link_scope == LinkScope.same_host


def test_unknown_field_rejected():
    bad = {**VALID, "scenario_metadata": {**VALID["scenario_metadata"], "junk": 1}}
    with pytest.raises(ValidationError):
        Scenario(**bad)


def test_step_ids_must_start_at_one_and_be_contiguous():
    bad = {**VALID}
    bad = {
        **VALID,
        "attack_sequence_flow": {"steps": [
            {"step_id": 2, "name": "s", "matching_criteria": {"Node_Type": "Process"}},
        ]},
    }
    with pytest.raises(ValidationError):
        Scenario(**bad)


def test_bad_regex_rejected():
    bad = {
        **VALID,
        "attack_sequence_flow": {"steps": [
            {"step_id": 1, "name": "s", "matching_criteria": {"Node_Type": "Process", "ProcessPath": {"regex": "([unclosed"}}},
        ]},
    }
    with pytest.raises(ValidationError):
        Scenario(**bad)
