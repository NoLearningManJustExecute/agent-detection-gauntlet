"""Trace event model.

A trace is one agent session. Each event is one JSONL line. Attribute names follow the
OpenTelemetry GenAI semantic conventions where a name exists; everything else uses the
``adg.`` prefix. See docs/schema.md for the pinned conventions version.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, JsonValue, field_validator, model_validator

from agent_detection_gauntlet.schema.common import (
    IDENTIFIER_PATTERN,
    STRICT_MODEL,
    Identifier,
    UtcTimestamp,
)


class EventType(StrEnum):
    SESSION_START = "session.start"
    USER_PROMPT = "user.prompt"
    RETRIEVAL = "retrieval"
    LLM_REQUEST = "llm.request"
    LLM_RESPONSE = "llm.response"
    TOOL_CALL = "tool.call"
    TOOL_RESULT = "tool.result"
    GUARDRAIL_ACTION = "guardrail.action"
    SESSION_END = "session.end"


class SourceTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


class DataLabel(StrEnum):
    SECRET = "secret"
    PII = "pii"
    INTERNAL = "internal"
    PUBLIC = "public"


# Events that carry content and may therefore carry provenance attributes.
CONTENT_BEARING_EVENTS: frozenset[EventType] = frozenset(
    {
        EventType.USER_PROMPT,
        EventType.RETRIEVAL,
        EventType.LLM_REQUEST,
        EventType.LLM_RESPONSE,
        EventType.TOOL_CALL,
        EventType.TOOL_RESULT,
    }
)

ATTR_SOURCE_TRUST = "adg.source.trust"
ATTR_DATA_LABELS = "adg.data.labels"
ATTR_CONTENT_REF = "adg.content.ref"
ATTR_CONTENT_TEXT = "adg.content.text"
ATTR_GUARDRAIL_DECISION = "adg.guardrail.decision"

PROVENANCE_ATTRIBUTES: frozenset[str] = frozenset(
    {ATTR_SOURCE_TRUST, ATTR_DATA_LABELS, ATTR_CONTENT_REF, ATTR_CONTENT_TEXT}
)

GUARDRAIL_DECISIONS: frozenset[str] = frozenset({"allow", "block", "redact", "flag"})

# GenAI convention attributes whose value must be a string when present.
STRING_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "gen_ai.operation.name",
        "gen_ai.provider.name",
        "gen_ai.request.model",
        "gen_ai.response.model",
        "gen_ai.conversation.id",
        "gen_ai.agent.name",
        "gen_ai.data_source.id",
        "gen_ai.tool.name",
        "gen_ai.tool.call.id",
    }
)


def _check_source_trust(value: JsonValue) -> None:
    allowed = [member.value for member in SourceTrust]
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{ATTR_SOURCE_TRUST} must be one of {allowed}")


def _check_data_labels(value: JsonValue) -> None:
    allowed = [member.value for member in DataLabel]
    if not isinstance(value, list) or not value:
        raise ValueError(f"{ATTR_DATA_LABELS} must be a non-empty list drawn from {allowed}")
    for item in value:
        if not isinstance(item, str) or item not in allowed:
            raise ValueError(f"{ATTR_DATA_LABELS} entries must be drawn from {allowed}")
    if len(set(value)) != len(value):
        raise ValueError(f"{ATTR_DATA_LABELS} must not repeat a label")


_SPAN_ID = re.compile(IDENTIFIER_PATTERN)


def _check_content_ref(value: JsonValue) -> None:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{ATTR_CONTENT_REF} must be a non-empty list of span ids")
    for item in value:
        if not isinstance(item, str) or _SPAN_ID.fullmatch(item) is None:
            raise ValueError(f"{ATTR_CONTENT_REF} entries must be span ids")
    if len(set(value)) != len(value):
        raise ValueError(f"{ATTR_CONTENT_REF} must not repeat a span id")


def _check_text(key: str) -> Callable[[JsonValue], None]:
    def check(value: JsonValue) -> None:
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a string")

    return check


def _check_guardrail_decision(value: JsonValue) -> None:
    if not isinstance(value, str) or value not in GUARDRAIL_DECISIONS:
        raise ValueError(f"{ATTR_GUARDRAIL_DECISION} must be one of {sorted(GUARDRAIL_DECISIONS)}")


# Every adg.* attribute the schema knows. Unknown adg.* keys are rejected so typos fail closed.
ADG_ATTRIBUTES: dict[str, Callable[[JsonValue], None]] = {
    ATTR_SOURCE_TRUST: _check_source_trust,
    ATTR_DATA_LABELS: _check_data_labels,
    ATTR_CONTENT_REF: _check_content_ref,
    ATTR_CONTENT_TEXT: _check_text(ATTR_CONTENT_TEXT),
    ATTR_GUARDRAIL_DECISION: _check_guardrail_decision,
}


class TraceEvent(BaseModel):
    """One event in an agent session trace."""

    model_config = STRICT_MODEL

    schema_version: Literal["0.1"] = Field(description="Trace schema version.")
    trace_id: Identifier = Field(description="Identifier of the session this event belongs to.")
    span_id: Identifier = Field(description="Identifier of this event, unique within the trace.")
    parent_span_id: Identifier | None = Field(
        description="Span that caused this event, or null for a root event."
    )
    timestamp: UtcTimestamp = Field(description="Event time, RFC 3339 in UTC.")
    event_type: EventType
    attributes: dict[str, JsonValue] = Field(
        description="OpenTelemetry GenAI attributes plus adg.* extensions."
    )

    @field_validator("attributes")
    @classmethod
    def _check_attributes(cls, attributes: dict[str, JsonValue]) -> dict[str, JsonValue]:
        for key in sorted(attributes):
            value = attributes[key]
            if not key or key != key.strip():
                raise ValueError(f"attribute key {key!r} must be non-empty without padding")
            if key.startswith("adg."):
                check = ADG_ATTRIBUTES.get(key)
                if check is None:
                    raise ValueError(f"unknown adg attribute {key!r}")
                check(value)
            elif key in STRING_ATTRIBUTES and not isinstance(value, str):
                raise ValueError(f"{key} must be a string")
        return attributes

    @model_validator(mode="after")
    def _check_event(self) -> TraceEvent:
        if self.parent_span_id == self.span_id:
            raise ValueError("parent_span_id must not equal span_id")
        present = sorted(PROVENANCE_ATTRIBUTES.intersection(self.attributes))
        if present and self.event_type not in CONTENT_BEARING_EVENTS:
            raise ValueError(
                f"provenance attributes {present} are only allowed on content-bearing events"
            )
        if self.event_type is EventType.RETRIEVAL and ATTR_SOURCE_TRUST not in self.attributes:
            raise ValueError(f"retrieval events must carry {ATTR_SOURCE_TRUST}")
        refs = self.attributes.get(ATTR_CONTENT_REF)
        if isinstance(refs, list) and self.span_id in refs:
            raise ValueError(f"{ATTR_CONTENT_REF} must not reference the event itself")
        if ATTR_GUARDRAIL_DECISION in self.attributes and (
            self.event_type is not EventType.GUARDRAIL_ACTION
        ):
            raise ValueError(f"{ATTR_GUARDRAIL_DECISION} is only allowed on guardrail.action")
        return self

    def content_refs(self) -> tuple[str, ...]:
        refs = self.attributes.get(ATTR_CONTENT_REF)
        if isinstance(refs, list):
            return tuple(ref for ref in refs if isinstance(ref, str))
        return ()


def event_order_key(event: TraceEvent) -> tuple[object, str]:
    """Canonical order inside a trace: timestamp, then span_id."""
    return (event.timestamp, event.span_id)


@dataclass(frozen=True)
class Trace:
    """All events of one session, in canonical order."""

    trace_id: str
    events: tuple[TraceEvent, ...]


def integrity_problems(events: Sequence[TraceEvent]) -> list[tuple[int, str]]:
    """Check cross-event rules for one trace whose events are already in canonical order.

    Returns (index, message) pairs. Checks: one trace id, unique span ids, parent spans
    exist in the trace, and every content reference points to an earlier event.
    """
    problems: list[tuple[int, str]] = []
    trace_ids = {event.trace_id for event in events}
    if len(trace_ids) > 1:
        problems.append((0, f"events from several traces were grouped: {sorted(trace_ids)}"))
    position: dict[str, int] = {}
    for index, event in enumerate(events):
        if event.span_id in position:
            problems.append((index, f"duplicate span_id {event.span_id!r} in trace"))
        else:
            position[event.span_id] = index
    for index, event in enumerate(events):
        if event.parent_span_id is not None and event.parent_span_id not in position:
            problems.append(
                (index, f"parent_span_id {event.parent_span_id!r} is not a span in this trace")
            )
        for ref in event.content_refs():
            target = position.get(ref)
            if target is None:
                problems.append((index, f"{ATTR_CONTENT_REF} {ref!r} is not a span in this trace"))
            elif target >= index:
                problems.append(
                    (index, f"{ATTR_CONTENT_REF} {ref!r} must point to an earlier event")
                )
    return problems
