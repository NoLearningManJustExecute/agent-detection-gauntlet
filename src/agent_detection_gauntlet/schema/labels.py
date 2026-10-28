"""Ground-truth label model. Labels live in their own file and never inside traces."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, StrictBool, model_validator

from agent_detection_gauntlet.schema.common import STRICT_MODEL, Identifier, NonEmptyStr


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


class LabelRecord(BaseModel):
    """Ground truth for one trace. Read by the metrics stage only, never by the engine."""

    model_config = STRICT_MODEL

    schema_version: Literal["0.1"]
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
    split: Split
    source: LabelSource

    @model_validator(mode="after")
    def _check_consistency(self) -> LabelRecord:
        if self.label is Verdict.MALICIOUS:
            if self.attack_class is None:
                raise ValueError("malicious labels need an attack_class")
            if self.attack_succeeded is None:
                raise ValueError("malicious labels need attack_succeeded (true or false)")
        else:
            if self.attack_class is not None or self.attack_succeeded is not None:
                raise ValueError("benign labels must have null attack_class and attack_succeeded")
            if self.mutation is not None:
                raise ValueError("benign labels must have a null mutation")
        return self
