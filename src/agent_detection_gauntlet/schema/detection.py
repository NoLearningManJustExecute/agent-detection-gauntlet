"""Detection record emitted by the engine, one per hit."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field, model_validator

from agent_detection_gauntlet.schema.common import (
    STRICT_MODEL,
    Identifier,
    RuleId,
    SchemaVersion,
    SemVer,
    Severity,
    Tier,
    UtcTimestamp,
)


class Detection(BaseModel):
    """One rule hit on one trace. Contains no wall-clock values, so output is reproducible."""

    model_config = STRICT_MODEL

    schema_version: SchemaVersion
    rule_id: RuleId
    rule_version: SemVer
    trace_id: Identifier
    tier: Tier
    severity: Severity
    matched_span_ids: Annotated[list[Identifier], Field(min_length=1)]
    first_timestamp: UtcTimestamp
    last_timestamp: UtcTimestamp

    @model_validator(mode="after")
    def _check_order(self) -> Detection:
        if self.last_timestamp < self.first_timestamp:
            raise ValueError("last_timestamp must not be before first_timestamp")
        return self

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.trace_id,
            self.rule_id,
            self.rule_version,
            self.first_timestamp,
            self.last_timestamp,
            tuple(self.matched_span_ids),
        )
