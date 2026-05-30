import re
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from augur.enums import Severity, LinkScope


class MitreMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tactic: str
    technique: str


class ScenarioMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_id: str
    name: str
    description: str
    severity: Severity
    mitre_mappings: list[MitreMapping] = Field(min_length=1)
    os_family: str = "windows"


class SpatialConstraints(BaseModel):
    model_config = ConfigDict(extra="forbid")
    applicable_zones: list[str] = Field(min_length=1)
    critical_assets_only: bool = False
    required_log_sources: list[str] = Field(default_factory=list)


class TemporalLink(BaseModel):
    model_config = ConfigDict(extra="forbid")
    previous_step: int
    link_scope: LinkScope = LinkScope.same_host
    min_time_delta_seconds: int = 0
    max_time_delta_seconds: int

    @model_validator(mode="after")
    def _check_window(self):
        if self.max_time_delta_seconds < self.min_time_delta_seconds:
            raise ValueError("max_time_delta_seconds must be >= min_time_delta_seconds")
        return self


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")
    step_id: int
    name: str
    temporal_link: TemporalLink | None = None
    matching_criteria: dict[str, Any]

    @field_validator("matching_criteria")
    @classmethod
    def _validate_criteria(cls, v: dict[str, Any]) -> dict[str, Any]:
        if "Node_Type" not in v:
            raise ValueError("matching_criteria must include Node_Type")
        if v["Node_Type"] not in ("Process", "File"):
            raise ValueError("Node_Type must be 'Process' or 'File'")
        for key, val in v.items():
            if isinstance(val, dict) and "regex" in val:
                try:
                    re.compile(val["regex"])
                except re.error as e:
                    raise ValueError(f"invalid regex for {key}: {e}")
        return v


class AttackSequenceFlow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    steps: list[Step] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_steps(self):
        ids = [s.step_id for s in self.steps]
        if ids != list(range(1, len(ids) + 1)):
            raise ValueError(f"step_ids must be 1..N contiguous, got {ids}")
        for s in self.steps:
            if s.step_id == 1 and s.temporal_link is not None:
                raise ValueError("step 1 must not have a temporal_link")
            if s.step_id > 1:
                if s.temporal_link is None:
                    raise ValueError(f"step {s.step_id} requires a temporal_link")
                if s.temporal_link.previous_step != s.step_id - 1:
                    raise ValueError(f"step {s.step_id} temporal_link.previous_step must be {s.step_id - 1}")
        return self


class HuntingQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    engine: str
    query: str | None = None
    query_path: str | None = None

    @model_validator(mode="after")
    def _need_one(self):
        if not self.query and not self.query_path:
            raise ValueError("hunting query needs query or query_path")
        return self


class ActionableHuntingOutputs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    validation_queries: list[HuntingQuery] = Field(min_length=1)


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_metadata: ScenarioMetadata
    spatial_constraints: SpatialConstraints
    attack_sequence_flow: AttackSequenceFlow
    actionable_hunting_outputs: ActionableHuntingOutputs

    @property
    def step_count(self) -> int:
        return len(self.attack_sequence_flow.steps)

    @property
    def os_family(self) -> str:
        return self.scenario_metadata.os_family

    @property
    def scenario_id(self) -> str:
        return self.scenario_metadata.scenario_id

    @property
    def name(self) -> str:
        return self.scenario_metadata.name

    @property
    def severity(self) -> Severity:
        return self.scenario_metadata.severity
