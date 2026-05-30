import yaml
from augur.generative.fake import FakeScenarioGenerator, SAMPLE_VALID_YAML, SAMPLE_INVALID_YAML
from augur.generative.base import GenerationRequest
from augur.scenarios.schema import Scenario


def test_fake_returns_n_valid_yaml():
    out = FakeScenarioGenerator().generate(GenerationRequest(seed_id="SCEN-WIN-001"), 3)
    assert len(out) == 3
    for y in out:
        Scenario(**yaml.safe_load(y))            # all parse + validate


def test_fake_can_emit_a_bad_one():
    g = FakeScenarioGenerator(include_invalid=True)
    out = g.generate(GenerationRequest(seed_id="X"), 2)
    assert any("not valid" in y or "Node_Type" not in y for y in out)  # at least one is junk
