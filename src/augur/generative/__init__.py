from augur.generative.base import GenerationRequest, ScenarioGenerator
from augur.generative.fake import FakeScenarioGenerator


def get_generator(name: str | None = None):
    from augur.generative.config import load_ai_config
    name = name or load_ai_config().generator
    if name == "claude":
        from augur.generative.claude import ClaudeScenarioGenerator  # Task 7, lazy
        return ClaudeScenarioGenerator()
    return FakeScenarioGenerator()
