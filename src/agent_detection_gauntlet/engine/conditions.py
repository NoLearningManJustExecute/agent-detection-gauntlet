"""Evaluate match conditions and normalization pipelines on single events."""

from __future__ import annotations

import re
from collections.abc import Sequence
from functools import lru_cache

from pydantic import JsonValue

from agent_detection_gauntlet.engine.fields import MISSING, json_equal, resolve
from agent_detection_gauntlet.normalize import Normalization, normalize_text
from agent_detection_gauntlet.rules.model import (
    AllCondition,
    AnyCondition,
    EventMatch,
    FieldCondition,
    NotCondition,
    Operator,
)
from agent_detection_gauntlet.schema.trace import TraceEvent


@lru_cache(maxsize=1024)
def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _norm(value: JsonValue, steps: Sequence[Normalization]) -> JsonValue:
    """Normalize a string, or every string inside a list, so equals and in see lists too."""
    if isinstance(value, str):
        return normalize_text(value, steps)
    if isinstance(value, list):
        return [_norm(item, steps) for item in value]
    return value


def evaluate_field(condition: FieldCondition, event: TraceEvent) -> bool:
    value = resolve(event, condition.field)
    if condition.op is Operator.EXISTS:
        return (value is not MISSING) == condition.value
    if value is MISSING:
        return False
    steps = condition.normalize
    actual = _norm(value, steps)  # type: ignore[arg-type]
    expected = condition.value
    match condition.op:
        case Operator.EQUALS:
            return json_equal(actual, _norm(expected, steps))
        case Operator.IN:
            options = expected if isinstance(expected, list) else []
            return any(json_equal(actual, _norm(option, steps)) for option in options)
        case Operator.CONTAINS:
            if isinstance(actual, str):
                return isinstance(expected, str) and normalize_text(expected, steps) in actual
            if isinstance(actual, list):
                # List items were already normalized along with ``actual``.
                target = _norm(expected, steps)
                return any(json_equal(item, target) for item in actual)
            return False
        case Operator.STARTSWITH:
            return (
                isinstance(actual, str)
                and isinstance(expected, str)
                and actual.startswith(normalize_text(expected, steps))
            )
        case Operator.REGEX:
            return (
                isinstance(actual, str)
                and isinstance(expected, str)
                and _compiled(expected).search(actual) is not None
            )
    raise AssertionError(f"unhandled operator {condition.op}")  # pragma: no cover


def evaluate(
    condition: AllCondition | AnyCondition | NotCondition | FieldCondition, event: TraceEvent
) -> bool:
    if isinstance(condition, AllCondition):
        return all(evaluate(child, event) for child in condition.all_of)
    if isinstance(condition, AnyCondition):
        return any(evaluate(child, event) for child in condition.any_of)
    if isinstance(condition, NotCondition):
        return not evaluate(condition.negated, event)
    return evaluate_field(condition, event)


def matches(spec: EventMatch, event: TraceEvent) -> bool:
    if event.event_type not in spec.event_types:
        return False
    return spec.where is None or evaluate(spec.where, event)
