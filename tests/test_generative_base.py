from augur.generative.base import GenerationRequest, ScenarioGenerator
from augur.generative.config import load_ai_config


def test_generation_request_defaults():
    r = GenerationRequest(seed_id="SCEN-WIN-001")
    assert r.seed_id == "SCEN-WIN-001" and r.n == 5 and r.axes == []


def test_config_defaults(monkeypatch):
    monkeypatch.delenv("AUGUR_AI_MODEL", raising=False)
    monkeypatch.delenv("AUGUR_AI_GENERATOR", raising=False)
    c = load_ai_config()
    assert c.model == "claude-opus-4-8" and c.generator == "fake" and c.max_n == 10
