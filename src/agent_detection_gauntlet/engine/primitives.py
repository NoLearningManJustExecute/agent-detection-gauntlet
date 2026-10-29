"""The three logic primitives. Each returns hits as tuples of event indices into the trace.

Semantics are specified in docs/engine.md. Everything here is deterministic: events are
visited in canonical trace order and the first valid assignment in that order wins.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from pydantic import JsonValue

from agent_detection_gauntlet.engine.conditions import matches
from agent_detection_gauntlet.engine.fields import MISSING, _Missing, json_equal, resolve
from agent_detection_gauntlet.io.jsonl import canonical_json
from agent_detection_gauntlet.rules.model import (
    EventMatch,
    Requirement,
    RequireOp,
    SequenceSpec,
    SequenceStep,
    ThresholdOp,
    ThresholdSpec,
)
from agent_detection_gauntlet.schema.trace import Trace, TraceEvent

Hit = tuple[int, ...]


@dataclass
class TraceContext:
    """Per-trace lookups shared by every rule run against the trace."""

    trace: Trace
    _ancestors: dict[str, frozenset[str]] | None = field(default=None, init=False)

    def ancestors(self, span_id: str) -> frozenset[str]:
        """Every span this span's content derives from, following adg.content.ref transitively."""
        if self._ancestors is None:
            table: dict[str, frozenset[str]] = {}
            for event in self.trace.events:
                derived: set[str] = set()
                for ref in event.content_refs():
                    if ref in table:
                        derived.add(ref)
                        derived.update(table[ref])
                table[event.span_id] = frozenset(derived)
            self._ancestors = table
        return self._ancestors.get(span_id, frozenset())


def run_match(spec: EventMatch, context: TraceContext) -> list[Hit]:
    """One hit per matching event."""
    return [(index,) for index, event in enumerate(context.trace.events) if matches(spec, event)]


def _requirement_holds(
    requirement: Requirement,
    event: TraceEvent,
    bindings: Mapping[str, JsonValue],
    context: TraceContext,
) -> bool:
    bound = bindings[requirement.bound]
    if requirement.op is RequireOp.DERIVES_FROM:
        return isinstance(bound, str) and bound in context.ancestors(event.span_id)
    if requirement.field is None:  # pragma: no cover - rejected by the rule model
        return False
    value = resolve(event, requirement.field)
    if value is MISSING:
        return False
    if requirement.op is RequireOp.EQUALS:
        return json_equal(value, bound)  # type: ignore[arg-type]
    if isinstance(value, str):
        return isinstance(bound, str) and bound in value
    if isinstance(value, list):
        return any(json_equal(item, bound) for item in value)
    return False


def _apply_step(
    step: SequenceStep,
    event: TraceEvent,
    bindings: Mapping[str, JsonValue],
    context: TraceContext,
) -> dict[str, JsonValue] | None:
    """Check a step's requirements and add its bindings. None means the step does not hold."""
    for requirement in step.require:
        if not _requirement_holds(requirement, event, bindings, context):
            return None
    updated = dict(bindings)
    for name, ref in step.bind.items():
        value = resolve(event, ref)
        if value is MISSING:
            return None
        updated[name] = value  # type: ignore[assignment]
    return updated


@dataclass(frozen=True)
class _SequenceSearch:
    """Backtracking search for one fixed final event."""

    spec: SequenceSpec
    context: TraceContext
    candidates: list[list[bool]]
    end: int

    def in_window(self, first: int) -> bool:
        if self.spec.within_seconds is None:
            return True
        events = self.context.trace.events
        elapsed = (events[self.end].timestamp - events[first].timestamp).total_seconds()
        return elapsed <= self.spec.within_seconds

    def run(self) -> Hit | None:
        within = self.spec.within_events
        earliest = 0 if within is None else max(0, self.end - within + 1)
        return self._search(0, earliest, (), {})

    def _search(
        self, position: int, start: int, chosen: Hit, bindings: dict[str, JsonValue]
    ) -> Hit | None:
        steps = self.spec.steps
        events = self.context.trace.events
        last = len(steps) - 1
        if position == last:
            if start > self.end:
                return None
            if _apply_step(steps[last], events[self.end], bindings, self.context) is None:
                return None
            return (*chosen, self.end)
        for index in range(start, self.end - (last - position) + 1):
            if not self.candidates[position][index]:
                continue
            if position == 0 and not self.in_window(index):
                continue
            updated = _apply_step(steps[position], events[index], bindings, self.context)
            if updated is None:
                continue
            found = self._search(position + 1, index + 1, (*chosen, index), updated)
            if found is not None:
                return found
        return None


def run_sequence(spec: SequenceSpec, context: TraceContext) -> list[Hit]:
    """At most one hit per event that can serve as the last step.

    For each candidate last event, the preceding steps take the lexicographically smallest
    index assignment that satisfies order, window, and bind constraints.
    """
    events = context.trace.events
    candidates = [[matches(step.match, event) for event in events] for step in spec.steps]
    hits: list[Hit] = []
    for end in range(len(events)):
        if not candidates[-1][end]:
            continue
        hit = _SequenceSearch(spec, context, candidates, end).run()
        if hit is not None:
            hits.append(hit)
    return hits


def _compare(op: ThresholdOp, count: int, value: int) -> bool:
    if op is ThresholdOp.GTE:
        return count >= value
    if op is ThresholdOp.GT:
        return count > value
    return count == value


def _number_key(value: JsonValue) -> JsonValue:
    """Make whole floats count as the integer they equal, matching JSON equality elsewhere."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, list):
        return [_number_key(item) for item in value]
    if isinstance(value, dict):
        return {key: _number_key(item) for key, item in value.items()}
    return value


def run_threshold(spec: ThresholdSpec, context: TraceContext) -> list[Hit]:
    """One hit per trace when the (distinct) count of matching events passes the comparison."""
    events = context.trace.events
    indices = [index for index, event in enumerate(events) if matches(spec.match, event)]
    if spec.distinct is None:
        counted = indices
        count = len(indices)
    else:
        counted = []
        values: set[str] = set()
        for index in indices:
            value = resolve(events[index], spec.distinct)
            if isinstance(value, _Missing):
                continue
            counted.append(index)
            values.add(canonical_json(_number_key(value)))
        count = len(values)
    if counted and _compare(spec.op, count, spec.value):
        return [tuple(counted)]
    return []
