"""Coverage results model. It holds no timestamp and no local path."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from agent_detection_gauntlet.metrics.report import Count, Rate
from agent_detection_gauntlet.schema.common import STRICT_MODEL, RuleId, Tier
from agent_detection_gauntlet.validation.model import CoverageThresholds, ResultRule, Sha256

PopulationName = Literal["clean_heldout", "payload_mutations", "attack_variants"]


class Reason(StrEnum):
    """Why a technique is mapped but not covered in one population."""

    RECALL_TOO_LOW = "recall_too_low"
    FPR_TOO_HIGH = "fpr_too_high"
    NO_SUCCESSFUL_ATTACKS = "no_successful_attacks"


class InputRef(BaseModel):
    model_config = STRICT_MODEL

    path: str = Field(description="Relative to the repository root.")
    sha256: Sha256


class RuleEvidence(BaseModel):
    """One rule on one pooled population, compared with the thresholds on point estimates."""

    model_config = STRICT_MODEL

    rule_id: RuleId
    tier: Tier
    recall: Rate
    fpr: Rate
    meets_recall: bool
    meets_fpr: bool


class Population(BaseModel):
    """A pooled result set: clean held-out attacks, or one Phase 4 category with guardrails off."""

    model_config = STRICT_MODEL

    name: PopulationName
    source: str = Field(description="Where in the golden file the pooled rows come from.")
    succeeded_traces: Count
    succeeded_groups: Count
    succeeded_by_class: dict[str, Count]
    rules: list[RuleEvidence]


class Verdict(BaseModel):
    """One technique on one population."""

    model_config = STRICT_MODEL

    population: PopulationName
    covered: bool
    covering_rules: list[RuleId]
    reason: Reason | None = Field(description="Null when covered.")
    own_succeeded_traces: Count | None = Field(
        description="Succeeded traces of the technique's classes. Null when no class is tied to it."
    )
    best_rule: RuleEvidence = Field(description="Highest recall, then lowest FPR, then rule id.")


class TechniqueCount(BaseModel):
    """A mapped rule on the technique's own classes. Shown beside the verdict, never decides it."""

    model_config = STRICT_MODEL

    rule_id: RuleId
    recall: Rate


class Technique(BaseModel):
    model_config = STRICT_MODEL

    family: str
    id: str
    name: str
    verified: bool
    rules: list[RuleId]
    classes: list[str] = Field(description="Attack classes the source threat model files here.")
    ineffective_only: bool = Field(description="Every tied class is ineffective.")
    verdicts: list[Verdict]
    clean_technique_counts: list[TechniqueCount]


class AttackedWithoutRule(BaseModel):
    """An ID the source threat model files a class under, which no rule here may reference."""

    model_config = STRICT_MODEL

    id: str
    classes: list[str]
    clean_succeeded_traces: Count


class CoverageReport(BaseModel):
    """Byte-identical for equal inputs, so CI regenerates it and compares."""

    model_config = STRICT_MODEL

    schema_version: Literal["1.0"]
    thresholds: CoverageThresholds
    class_map_source_commit: str
    ineffective_classes: list[str]
    inputs: list[InputRef]
    rules: list[ResultRule]
    populations: list[Population]
    techniques: list[Technique]
    attacked_without_rule: list[AttackedWithoutRule]
