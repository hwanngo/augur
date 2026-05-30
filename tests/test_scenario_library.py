from augur.scenarios.loader import load_scenarios

SCENARIOS_DIR = "scenarios"


def test_library_scenarios_are_valid_and_unique():
    scns = load_scenarios(SCENARIOS_DIR)
    assert len(scns) == 40              # the v2 library
    ids = {s.scenario_id for s in scns}
    assert len(ids) == len(scns)        # all scenario_ids unique
    for s in scns:
        assert s.step_count >= 3
        assert len(s.scenario_metadata.mitre_mappings) >= 1


def test_lsass_dump_is_canonical_chain():
    scns = {s.scenario_id: s for s in load_scenarios(SCENARIOS_DIR)}
    s = scns["SCEN-WIN-001"]
    assert s.step_count == 3
    assert s.attack_sequence_flow.steps[-1].matching_criteria.get("TargetProcess") == "lsass.exe"
