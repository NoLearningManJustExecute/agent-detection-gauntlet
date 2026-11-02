"""Phase 4 registration and results models. Neither holds a timestamp or a local path."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field

from agent_detection_gauntlet.metrics.report import AttackFailed, Count, InputFile, Rate
from agent_detection_gauntlet.schema.common import STRICT_MODEL
from agent_detection_gauntlet.schema.labels import Guardrails, Split
from agent_detection_gauntlet.validation.model import (
    BootstrapInterval,
    FrozenRule,
    GitSha,
    ResultRule,
    Sha256,
)

Category = Literal["payload_mutation", "attack_variant"]


class BaseScenario(BaseModel):
    """A held-out scenario that is mutated, chosen from labels alone."""

    model_config = STRICT_MODEL

    scenario_id: str
    variant_group: str
    attack_class: str


class BootstrapPlan(BaseModel):
    model_config = STRICT_MODEL

    method: Literal["paired_group_bootstrap_percentile"]
    resamples: Annotated[int, Field(ge=1)]
    seed: int
    confidence: Annotated[float, Field(ge=0.95, le=0.95)]


class EvasionPlan(BaseModel):
    """Everything fixed before any evasion input is generated. Frozen once committed."""

    model_config = STRICT_MODEL

    schema_version: Literal["1.0"]
    results_path: str
    report_path: str
    inputs_dir: str
    split: Split
    tooling_commit: GitSha = Field(description="The commit holding the tooling and this generator.")
    source_commit: GitSha = Field(description="The source lab commit that runs the inputs.")
    attack_variants_sha256: Sha256
    baseline_preregistration_sha256: Sha256
    baseline_results_sha256: Sha256
    split_manifest_sha256: Sha256
    labels_sha256: Sha256
    rules: list[FrozenRule]
    payload_mutations: list[str]
    attack_routes: list[str]
    bases: list[BaseScenario]
    attack_variants: list[str]
    mutation_seed: int
    homoglyph_rate: float
    chunk_size: int
    decode_instruction: str
    split_instruction: str
    model: str
    model_digest: str
    temperature: float
    run_seed: int
    runs_per_input: Annotated[int, Field(ge=1)]
    arms: list[str]
    content_ref_ks: list[int]
    primary_k: int
    small_n_below: Annotated[int, Field(ge=1)]
    ineffective_classes: list[str]
    below_floor_classes: list[str]
    bootstrap: BootstrapPlan
    commands: list[str]


class PairedDelta(BaseModel):
    """Evasion minus baseline, on the attacks that survived the variation and their own bases."""

    model_config = STRICT_MODEL

    mutated: Rate
    baseline: Rate
    delta: float | None
    groups: Count
    unpaired_traces: Count = Field(description="Succeeded traces whose base did not succeed.")
    ci95: BootstrapInterval | None


class EvasionRow(BaseModel):
    model_config = STRICT_MODEL

    name: str = Field(description="A rule id, a tier, or all_tiers.")
    recall: Rate = Field(description="Over every succeeded evasion trace in this population.")
    attack_failed: AttackFailed
    paired: PairedDelta


class AttackSuccess(BaseModel):
    """How often the attack still worked. A mutation that breaks it is not an evasion win."""

    model_config = STRICT_MODEL

    runs: Rate = Field(description="Oracle-confirmed successes over completed runs.")
    inputs: Rate = Field(description="Inputs with at least one success, over inputs.")
    paired: PairedDelta = Field(description="Runs, against the same inputs' bases in this arm.")


class EvasionPopulation(BaseModel):
    model_config = STRICT_MODEL

    traces: Count
    succeeded_traces: Count
    succeeded_groups: Count
    attack_failed_traces: Count


class EvasionTable(BaseModel):
    model_config = STRICT_MODEL

    per_rule: list[EvasionRow]
    per_tier: list[EvasionRow]
    all_tiers: EvasionRow


class ArmSection(BaseModel):
    model_config = STRICT_MODEL

    guardrails: Guardrails
    population: EvasionPopulation
    attack_success: AttackSuccess
    table: EvasionTable


class EvasionSection(BaseModel):
    """One mutation class, or one category pooled."""

    model_config = STRICT_MODEL

    name: str
    category: Category
    pooled: bool
    arms: list[ArmSection]


class ClassCell(BaseModel):
    model_config = STRICT_MODEL

    name: str
    recall: Rate


class ClassRow(BaseModel):
    """Secondary: one attack class under one mutation, guardrails off."""

    model_config = STRICT_MODEL

    mutation: str
    attack_class: str
    succeeded_traces: Count
    succeeded_groups: Count
    attack_failed_traces: Count
    small_n: bool
    below_floor: bool
    cells: list[ClassCell]


class FprCell(BaseModel):
    model_config = STRICT_MODEL

    name: str
    fpr: Rate


class OfflineRow(BaseModel):
    """A content rule on captured text with the payload mutated. Same traces on both sides."""

    model_config = STRICT_MODEL

    name: str
    original: Rate
    offline: Rate
    delta: float | None
    groups: Count
    ci95: BootstrapInterval | None


class OfflineSection(BaseModel):
    model_config = STRICT_MODEL

    mutation: str
    rows: list[OfflineRow]


class ProvenanceRow(BaseModel):
    """The sequence tier at one content-reference K, guardrails off."""

    model_config = STRICT_MODEL

    mutation: str
    k: int
    recall: Rate
    baseline: Rate


class Disjointness(BaseModel):
    """Evasion inputs against the corpus, recomputed from the committed files."""

    model_config = STRICT_MODEL

    bases_outside_heldout: list[str]
    inputs_matching_corpus_payloads: Count
    traces_matching_corpus_hashes: Count
    corpus_labels_with_mutation: Count
    corpus_payloads_checked_at_generation: Count


class EvasionResults(BaseModel):
    """The golden file. Byte-identical for equal inputs, so CI can compare it directly."""

    model_config = STRICT_MODEL

    schema_version: Literal["1.0"]
    split: Split
    preregistration_sha256: Sha256
    baseline_results_sha256: Sha256
    rules: list[ResultRule]
    inputs: list[InputFile]
    raw_runs: Count
    unique_traces: Count
    error_runs: Count
    disjointness: Disjointness
    benign_fpr: list[FprCell]
    sections: list[EvasionSection]
    per_class: list[ClassRow]
    offline: list[OfflineSection]
    provenance: list[ProvenanceRow]
