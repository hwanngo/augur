from augur.generative.eval import evaluate
from augur.generative.fake import FakeScenarioGenerator
from augur.scenarios.loader import load_scenarios

EXISTING = load_scenarios("scenarios")
_REQUIRED_KEYS = {"schema_valid_rate", "fp_on_benign_rate", "detectability_rate",
                  "dedup_rate", "mitre_coverage", "yield"}


def test_eval_with_invalid_generator():
    """With include_invalid=True, schema_valid_rate < 1.0; fp_on_benign_rate == 0.0."""
    gen = FakeScenarioGenerator(include_invalid=True)
    seeds = ["SCEN-WIN-001", "SCEN-WIN-014"]
    report = evaluate(gen, seeds, EXISTING)
    assert set(report.keys()) >= _REQUIRED_KEYS
    assert report["schema_valid_rate"] < 1.0
    assert report["fp_on_benign_rate"] == 0.0


def test_eval_all_keys_present():
    """Clean generator: all metric keys present, fp_on_benign_rate == 0."""
    gen = FakeScenarioGenerator()
    report = evaluate(gen, ["SCEN-WIN-001"], EXISTING)
    assert set(report.keys()) >= _REQUIRED_KEYS
    assert report["fp_on_benign_rate"] == 0.0
