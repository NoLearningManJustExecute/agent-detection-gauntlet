"""Metrics report model. The report body holds no timestamps, so equal inputs give equal bytes."""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, Field, model_validator

from agent_detection_gauntlet.schema.common import STRICT_MODEL, RuleId, SemVer, Tier
from agent_detection_gauntlet.schema.labels import Split

Count = Annotated[int, Field(ge=0)]
Unit = Annotated[float, Field(ge=0, le=1)]


class Interval(BaseModel):
    model_config = STRICT_MODEL

    method: Literal["wilson"]
    confidence: Annotated[float, Field(ge=0.95, le=0.95)]
    lower: Unit
    upper: Unit


class Rate(BaseModel):
    """A rate with its numerator and denominator. value and ci95 are null when undefined."""

    model_config = STRICT_MODEL

    value: Unit | None
    numerator: Count
    denominator: Count
    ci95: Interval | None = Field(
        description="Wilson score interval. Null when the denominator is zero, and always "
        "null for f1, which is not a binomial proportion."
    )


class Rates(BaseModel):
    model_config = STRICT_MODEL

    precision: Rate
    recall: Rate
    f1: Rate
    fpr: Rate
    detection_rate: Rate


class Confusion(BaseModel):
    """Session-level counts. attack_failed traces are not in any cell."""

    model_config = STRICT_MODEL

    tp: Count
    fp: Count
    tn: Count
    fn: Count


class AttackFailed(BaseModel):
    """Malicious traces whose attack did not succeed. Excluded from recall, reported here."""

    model_config = STRICT_MODEL

    count: Count
    detected: Count


class RuleMetrics(BaseModel):
    model_config = STRICT_MODEL

    rule_id: RuleId
    rule_version: SemVer
    tier: Tier
    confusion: Confusion
    attack_failed: AttackFailed
    rates: Rates


class TierMetrics(BaseModel):
    """A trace counts as detected by a tier when any rule in that tier fires on it."""

    model_config = STRICT_MODEL

    tier: Tier
    rule_ids: list[RuleId]
    confusion: Confusion
    attack_failed: AttackFailed
    rates: Rates


InputRole = Literal["rule", "trace", "detections", "labels"]


def _check_report_path(value: str) -> str:
    """Report paths are repository-relative with / separators: never absolute, never escaping."""
    if (
        value.startswith("/")
        or "\\" in value
        or re.match(r"[A-Za-z]:", value)
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        raise ValueError("path must be relative to the repository root, with / separators")
    return value


class InputFile(BaseModel):
    model_config = STRICT_MODEL

    role: InputRole
    path: Annotated[str, AfterValidator(_check_report_path)] = Field(
        description="Path relative to the repository root, or only the file name when external."
    )
    external: bool = Field(
        description="True when the file lies outside the repository root. Only its file name "
        "is recorded, and only when --external-basename was given."
    )
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @model_validator(mode="after")
    def _check_external(self) -> InputFile:
        if self.external and "/" in self.path:
            raise ValueError("an external input records its file name only")
        return self


class RuleRef(BaseModel):
    model_config = STRICT_MODEL

    id: RuleId
    version: SemVer
    tier: Tier


class Population(BaseModel):
    """Traces in the selected split, by outcome bucket."""

    model_config = STRICT_MODEL

    traces: Count
    benign: Count
    malicious_succeeded: Count
    attack_failed: Count


class Provenance(BaseModel):
    model_config = STRICT_MODEL

    package_version: str
    git_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40,64}$")] | None
    git_dirty: bool | None


class MetricsReport(BaseModel):
    model_config = STRICT_MODEL

    schema_version: Literal["0.1"]
    split: Split
    provenance: Provenance
    inputs: list[InputFile]
    rules: list[RuleRef]
    population: Population
    per_rule: list[RuleMetrics]
    per_tier: list[TierMetrics]
