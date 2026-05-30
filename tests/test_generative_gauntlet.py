import yaml
from augur.generative.gauntlet import run_gauntlet, GauntletResult
from augur.generative.fake import SAMPLE_VALID_YAML, SAMPLE_INVALID_YAML
from augur.scenarios.loader import load_scenarios

EXISTING = load_scenarios("scenarios")


def test_clean_candidate_passes():
    r = run_gauntlet(SAMPLE_VALID_YAML, EXISTING)
    assert r.passed is True and r.scenario_id.startswith("SCEN-GEN-") and 0.0 <= r.plausibility <= 1.0


def test_invalid_schema_rejected():
    r = run_gauntlet(SAMPLE_INVALID_YAML, EXISTING)
    assert r.passed is False and r.reject_stage == "schema"


def test_duplicate_of_existing_rejected():
    # serialize an existing scenario back to yaml and feed it.
    # mode="json" is REQUIRED — plain model_dump() leaves Severity/LinkScope as enum
    # OBJECTS, which yaml.safe_dump cannot represent (raises RepresenterError).
    s = {x.scenario_id: x for x in EXISTING}["SCEN-WIN-001"]
    dup = s.model_dump(mode="json")
    r = run_gauntlet(yaml.safe_dump(dup), EXISTING)
    assert r.passed is False and r.reject_stage == "dedup"


def test_fires_on_benign_rejected():
    # Mutate step 1 to match a benign process (chrome/notepad on Finance_User_PC, a
    # User_Endpoint host present in the benign corpus). Step 1 alone matches => proximity
    # 1/3 = 0.333 >= 0.30 fire threshold => MUST be hard-rejected at the fp_guard stage.
    benign_firing = SAMPLE_VALID_YAML.replace('{ in: ["powershell.exe"] }', '{ in: ["chrome.exe","notepad.exe"] }') \
        .replace('CommandLine: { regex: ".*-enc.*" }', 'CommandLine: { regex: ".*" }')
    r = run_gauntlet(benign_firing, EXISTING)
    assert r.passed is False and r.reject_stage == "fp_guard"
