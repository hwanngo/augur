from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class GenerationRequest:
    seed_id: str | None = None        # an existing scenario_id to mutate
    category: str | None = None       # or a category/technique target
    technique: str | None = None
    n: int = 5
    axes: list[str] = field(default_factory=list)   # lolbin, zone, timing, permute, blend


@runtime_checkable
class ScenarioGenerator(Protocol):
    def generate(self, request: GenerationRequest, n: int) -> list[str]: ...  # raw YAML strings
