"""Ground-truth label model. Labels live in their own file and never inside traces."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, StrictBool, model_validator

from agent_detection_gauntlet.schema.common import (
    STRICT_MODEL,
    Identifier,
    NonEmptyStr,
    SchemaVersion,
)


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    BENIGN = "benign"


class Guardrails(StrEnum):
    ON = "on"
    OFF = "off"


class Split(StrEnum):
    DEV = "dev"
    HELDOUT = "heldout"


class LabelSource(StrEnum):
    SYNTHETIC = "synthetic"
    RAG_ATTACK_LAB = "rag-attack-lab"
    AGENT_RISK_FRAMEWORK = "agent-risk-framework"


# Optional fields added in 0.2. A 0.1 record must not carry them.
FIELDS_SINCE_0_2: tuple[str, ...] = ("scenario_id", "task_id", "condition", "source_run_id")
# Optional fields added in 0.3. A 0.1 or 0.2 record must not carry them.
FIELDS_SINCE_0_3: tuple[str, ...] = ("variant_group", "derived_from")


class LabelRecord(BaseModel):
    """Ground truth for one trace. Read by the metrics stage only, never by the engine."""

    model_config = STRICT_MODEL

    schema_version: SchemaVersion
    trace_id: Identifier
    label: Verdict
    attack_class: NonEmptyStr | None = Field(
        description="Attack class for malicious traces, null for benign."
    )
    attack_succeeded: StrictBool | None = Field(
        description="Whether the attack achieved its goal. Required for malicious, null for benign."
    )
    mutation: NonEmptyStr | None = Field(
        description="Evasion mutation applied, or null for an unmutated run."
    )
    guardrails: Guardrails
    split: Split | None = Field(
        description=(
            "dev or heldout. Null (0.2 only) means not yet assigned: an exporter's output "
            "before the split is frozen. Metrics refuse unassigned labels."
        )
    )
    source: LabelSource
    scenario_id: NonEmptyStr | None = Field(
        default=None,
        description="0.2: the attack scenario the trace ran. Malicious traces only.",
    )
    task_id: NonEmptyStr | None = Field(
        default=None,
        description="0.2: the benign task the trace ran. Benign traces only.",
    )
    condition: NonEmptyStr | None = Field(
        default=None,
        description="0.2: the experiment arm (condition) the trace ran under.",
    )
    source_run_id: NonEmptyStr | None = Field(
        default=None,
        description="0.2: the run's identifier in the source repository's run log.",
    )
    variant_group: NonEmptyStr | None = Field(
        default=None,
        description=(
            "0.3: the distinct input this trace ran. The held-out split assigns whole groups, "
            "so near-identical inputs never sit on both sides."
        ),
    )
    derived_from: NonEmptyStr | None = Field(
        default=None,
        description=(
            "0.3: the scenario a seeded variant was derived from (paraphrase or translation), "
            "or null for an authored scenario or task."
        ),
    )

    @model_validator(mode="after")
    def _check_consistency(self) -> LabelRecord:
        if self.schema_version == "0.1":
            # Any 0.2 key, even set to null, was an unknown key under 0.1.
            present = [name for name in FIELDS_SINCE_0_2 if name in self.model_fields_set]
            if present:
                raise ValueError(f"fields {present} need schema_version 0.2")
            if self.split is None:
                raise ValueError("split must be dev or heldout in schema_version 0.1")
        if self.schema_version in ("0.1", "0.2"):
            newer = [name for name in FIELDS_SINCE_0_3 if name in self.model_fields_set]
            if newer:
                raise ValueError(f"fields {newer} need schema_version 0.3")
        if self.label is Verdict.MALICIOUS:
            if self.attack_class is None:
                raise ValueError("malicious labels need an attack_class")
            if self.attack_succeeded is None:
                raise ValueError("malicious labels need attack_succeeded (true or false)")
            if self.task_id is not None:
                raise ValueError("malicious labels must not carry a task_id")
        else:
            if self.attack_class is not None or self.attack_succeeded is not None:
                raise ValueError("benign labels must have null attack_class and attack_succeeded")
            if self.mutation is not None:
                raise ValueError("benign labels must have a null mutation")
            if self.scenario_id is not None:
                raise ValueError("benign labels must not carry a scenario_id")
            if self.derived_from is not None:
                raise ValueError("benign labels must not carry derived_from")
        return self
