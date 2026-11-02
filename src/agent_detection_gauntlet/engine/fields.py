"""Resolve rule field references against an event."""

from __future__ import annotations

from typing import Final

from pydantic import JsonValue

from agent_detection_gauntlet.rules.model import (
    ALL_STRINGS_PATH,
    ATTRIBUTE_PREFIX,
    PATH_SEPARATOR,
)
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


def _strings_in(value: JsonValue) -> list[str]:
    """Every string inside a value: object keys in sorted order, list items in order."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [text for item in value for text in _strings_in(item)]
    if isinstance(value, dict):
        return [text for key in sorted(value) for text in _strings_in(value[key])]
    return []


def _walk(value: JsonValue, path: str) -> JsonValue:
    """Follow a value path. Anything the path does not reach comes back as None."""
    if path == ALL_STRINGS_PATH:
        strings = _strings_in(value)
        return "\n".join(strings) if strings else None
    for segment in path.split("."):
        if isinstance(value, dict):
            value = value.get(segment)
        elif isinstance(value, list) and segment.isdecimal() and int(segment) < len(value):
            value = value[int(segment)]
        else:
            return None
    return value


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
        key, separator, path = field[len(ATTRIBUTE_PREFIX) :].partition(PATH_SEPARATOR)
        value = event.attributes.get(key)
        if separator and value is not None:
            value = _walk(value, path)
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
