import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AIConfig:
    generator: str            # "fake" | "claude"
    model: str
    max_n: int
    max_tokens: int
    max_calls: int = 30          # generation calls per window before a per-admin lockout
    window_seconds: int = 900

    @property
    def api_key(self) -> str | None:
        return os.environ.get("ANTHROPIC_API_KEY")


def load_ai_config() -> AIConfig:
    return AIConfig(
        generator=os.environ.get("AUGUR_AI_GENERATOR", "fake"),
        model=os.environ.get("AUGUR_AI_MODEL", "claude-opus-4-8"),
        max_n=int(os.environ.get("AUGUR_AI_MAX_N", "10")),
        max_tokens=int(os.environ.get("AUGUR_AI_MAX_TOKENS", "4096")),
        max_calls=int(os.environ.get("AUGUR_AI_MAX_CALLS", "30")),
        window_seconds=int(os.environ.get("AUGUR_AI_WINDOW_SECONDS", "900")),
    )
