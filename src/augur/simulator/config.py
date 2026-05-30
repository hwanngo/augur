from pydantic import BaseModel, ConfigDict, Field


class Injection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_id: str
    host: str
    start_offset_seconds: int = 0


class SimConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seed: int = 1337
    duration_seconds: int = Field(default=3600, ge=1)
    rate_per_minute: int = Field(default=12, ge=1)
    injections: list[Injection] = Field(default_factory=list)
