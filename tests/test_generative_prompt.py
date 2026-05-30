import re

from augur.generative.prompt import build_system_prompt, build_user_prompt
from augur.generative.base import GenerationRequest


def test_system_prompt_contains_required_elements():
    prompt = build_system_prompt()
    assert "Node_Type" in prompt
    assert "applicable_zones" in prompt
    # at least one real zone name
    assert any(zone in prompt for zone in ("User_Endpoint", "Internal_Server", "DMZ", "Active_Directory"))
    # at least one real scenario_id from the library (v2 anchors: SCEN-{WIN,LNX,MAC,CLD}-NNN)
    assert re.search(r"SCEN-(WIN|LNX|MAC|CLD)-\d{3}", prompt)


def test_user_prompt_contains_seed_and_axes():
    seed_yaml = "scenario_metadata:\n  scenario_id: SCEN-WIN-001\n"
    request = GenerationRequest(seed_id="SCEN-WIN-001", axes=["lolbin", "zone"])
    prompt = build_user_prompt(request, seed_yaml)
    assert "SCEN-WIN-001" in prompt
    assert "lolbin" in prompt
    assert "zone" in prompt
    assert seed_yaml in prompt
