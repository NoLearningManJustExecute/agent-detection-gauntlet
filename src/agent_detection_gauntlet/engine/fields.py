"""Resolve rule field references against an event."""

from __future__ import annotations

from typing import Final

from pydantic import JsonValue

from agent_detection_gauntlet.rules.model import ATTRIBUTE_PREFIX
from agent_detection_gauntlet.schema.trace import TraceEvent


class _Missing:
    """Marker for a field that is absent (or JSON null) on an event."""

    _instance: _Missing | None = None

    def __new__(cls) -> _Missing:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "MISSING"


MISSING: Final = _Missing()


def resolve(event: TraceEvent, field: str) -> JsonValue | _Missing:
    """Return the value of ``field`` on ``event``, or MISSING. Null counts as missing."""
    value: JsonValue
    if field == "event_type":
        value = event.event_type.value
    elif field == "span_id":
        value = event.span_id
    elif field == "parent_span_id":
        value = event.parent_span_id
    elif field.startswith(ATTRIBUTE_PREFIX):
        value = event.attributes.get(field[len(ATTRIBUTE_PREFIX) :])
    else:
        raise ValueError(f"unsupported field reference {field!r}")
    return MISSING if value is None else value


def json_equal(left: JsonValue, right: JsonValue) -> bool:
    """Equality with JSON semantics: booleans never equal numbers, 1 equals 1.0."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, int | float) and isinstance(right, int | float):
        return left == right
    if isinstance(left, str) and isinstance(right, str):
        return left == right
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            json_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(json_equal(left[k], right[k]) for k in left)
    return left is None and right is None
