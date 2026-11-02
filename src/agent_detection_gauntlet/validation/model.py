"""Pre-registration and results models. Neither holds a timestamp or a local path."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field

from agent_detection_gauntlet.metrics.report import (
    AttackFailed,
    Confusion,
    Count,
    InputFile,
    Population,
    Rate,
    Rates,
    RuleMetrics,
    TierMetrics,
    Unit,
)
from agent_detection_gauntlet.schema.common import STRICT_MODEL, RuleId, SemVer, Tier
from agent_detection_gauntlet.schema.labels import Guardrails, Split

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
GitSha = Annotated[str, Field(pattern=r"^[0-9a-f]{40,64}$")]


class FrozenRule(BaseModel):
    """A rule as it stood when scoring was pre-registered."""

    model_config = STRICT_MODEL

    id: RuleId
    version: SemVer
    tier: Tier
    path: str = Field(description="Rule file, relative to the repository root.")
    sha256: Sha256


class CoverageThresholds(BaseModel):
    """What Phase 5 needs to call a technique covered. Compared with the point estimates."""

    model_config = STRICT_MODEL

    min_heldout_recall: Unit
    max_fpr: Unit


class TierComparisonPlan(BaseModel):
    model_config = STRICT_MODEL

    method: Literal["paired_group_bootstrap_percentile"]
    unit: Literal["variant_group"]
    pairs: list[tuple[Tier, Tier]]
    resamples: Annotated[int, Field(ge=1)]
    seed: int
    confidence: Annotated[float, Field(ge=0.95, le=0.95)]


class Preregistration(BaseModel):
    """Everything fixed before the held-out split is scored. Frozen once committed."""

    model_config = STRICT_MODEL

    schema_version: Literal["1.0"]
    results_path: str
    report_path: str
    split: Split
    tooling_commit: GitSha = Field(description="The commit holding the scorer and this generator.")
    rules: list[FrozenRule]
    baseline_sidecars: list[str] = Field(
        description="Separate baseline files. Empty: fitted values live inside the rule files."
    )
    split_manifest_sha256: Sha256
    labels_sha256: Sha256
    commands: list[str]
    ineffective_classes: list[str]
    below_floor_classes: list[str]
    content_ref_ks: list[int]
    primary_k: int
    small_n_below: Annotated[int, Field(ge=1)]
    coverage: CoverageThresholds
    tier_comparison: TierComparisonPlan


class ResultRule(BaseModel):
    model_config = STRICT_MODEL

    id: RuleId
    version: SemVer
    tier: Tier
    sha256: Sha256


class GroupedPopulation(Population):
    """Traces per bucket, and the distinct variant groups behind them."""

    benign_groups: Count
    malicious_succeeded_groups: Count
    attack_failed_groups: Count


class CombinedMetrics(BaseModel):
    """A trace counts as detected when any rule in the set fires on it."""

    model_config = STRICT_MODEL

    rule_ids: list[RuleId]
    confusion: Confusion
    attack_failed: AttackFailed
    rates: Rates


class Section(BaseModel):
    model_config = STRICT_MODEL

    per_rule: list[RuleMetrics]
    per_tier: list[TierMetrics]
    all_tiers: CombinedMetrics


class GuardrailsSection(BaseModel):
    model_config = STRICT_MODEL

    guardrails: Guardrails
    population: GroupedPopulation
    section: Section


class RecallCell(BaseModel):
    model_config = STRICT_MODEL

    name: str = Field(description="A rule id, a tier, or all_tiers.")
    recall: Rate
    attack_failed: AttackFailed


class RecallTable(BaseModel):
    model_config = STRICT_MODEL

    per_rule: list[RecallCell]
    per_tier: list[RecallCell]
    all_tiers: RecallCell


class ClassSection(BaseModel):
    """Secondary: one attack class. Read with its sample size and interval."""

    model_config = STRICT_MODEL

    attack_class: str
    traces: Count
    succeeded_traces: Count
    succeeded_groups: Count
    attack_failed_traces: Count
    attack_failed_groups: Count
    small_n: bool = Field(description="The recall denominator is below small_n_below.")
    below_floor: bool = Field(description="The class is below the corpus group floor.")
    table: RecallTable


class AttackFailedClass(BaseModel):
    model_config = STRICT_MODEL

    attack_class: str
    guardrails_off: Count
    guardrails_on: Count
    total: Count
    groups: Count


class AttackFailedSection(BaseModel):
    model_config = STRICT_MODEL

    total: Count
    by_class: list[AttackFailedClass]


class FiredCell(BaseModel):
    model_config = STRICT_MODEL

    name: str = Field(description="A rule id, a tier, or all_tiers.")
    fired: Rate = Field(description="Traces the rule or tier fired on, over the traces present.")


class IneffectiveSection(BaseModel):
    """Classes kept out of recall. A fired rule here is reported, never counted in FPR."""

    model_config = STRICT_MODEL

    classes: list[str]
    traces: Count
    succeeded_traces: Count
    per_rule: list[FiredCell]
    per_tier: list[FiredCell]
    all_tiers: FiredCell


class ProvenanceRun(BaseModel):
    model_config = STRICT_MODEL

    k: int
    per_rule: list[RuleMetrics]
    tier: TierMetrics


class SetAside(BaseModel):
    """Recall with some succeeded traces removed, as a sensitivity check."""

    model_config = STRICT_MODEL

    name: str
    registered: bool = Field(description="False for a row added after scoring.")
    set_aside_traces: Count
    set_aside_groups: Count
    remaining_groups: Count
    table: RecallTable


class BootstrapInterval(BaseModel):
    model_config = STRICT_MODEL

    method: Literal["paired_group_bootstrap_percentile"]
    confidence: Annotated[float, Field(ge=0.95, le=0.95)]
    resamples: int
    seed: int
    lower: float
    upper: float


class PairedDifference(BaseModel):
    """Rate of a minus rate of b, on the same traces."""

    model_config = STRICT_MODEL

    a: Rate
    b: Rate
    difference: float | None
    a_only: Count
    b_only: Count
    both: Count
    neither: Count
    groups: Count
    ci95: BootstrapInterval | None


class TierComparison(BaseModel):
    model_config = STRICT_MODEL

    a: Tier
    b: Tier
    recall: PairedDifference
    fpr: PairedDifference


class BaselineResults(BaseModel):
    """The golden file. Byte-identical for equal inputs, so CI can compare it directly."""

    model_config = STRICT_MODEL

    schema_version: Literal["1.0"]
    split: Split
    preregistration_sha256: Sha256
    rules: list[ResultRule]
    inputs: list[InputFile]
    population: GroupedPopulation
    pooled: Section
    by_guardrails: list[GuardrailsSection]
    per_class: list[ClassSection]
    attack_failed: AttackFailedSection
    ineffective: IneffectiveSection
    provenance_sensitivity: list[ProvenanceRun]
    set_asides: list[SetAside]
    tier_comparison: list[TierComparison]
