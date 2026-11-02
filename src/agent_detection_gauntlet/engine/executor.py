"""Run rules over traces and produce sorted, deduplicated detection records."""

from __future__ import annotations

from collections.abc import Sequence

from agent_detection_gauntlet.engine.primitives import (
    Hit,
    TraceContext,
    run_baseline,
    run_match,
    run_sequence,
    run_threshold,
)
from agent_detection_gauntlet.rules.model import BaselineLogic, MatchLogic, Rule, SequenceLogic
from agent_detection_gauntlet.schema.common import SCHEMA_VERSION
from agent_detection_gauntlet.schema.detection import Detection
from agent_detection_gauntlet.schema.trace import Trace


def rule_hits(rule: Rule, context: TraceContext) -> list[Hit]:
    logic = rule.logic
    if isinstance(logic, MatchLogic):
        return run_match(logic.match, context)
    if isinstance(logic, SequenceLogic):
        return run_sequence(logic.sequence, context)
    if isinstance(logic, BaselineLogic):
        if rule.fitted is None:
            raise ValueError(f"{rule.id} has no fitted baseline; run gauntlet fit-baselines")
        return run_baseline(logic.baseline, rule.fitted, context)
    return run_threshold(logic.threshold, context)


def detections_for_trace(rules: Sequence[Rule], trace: Trace) -> list[Detection]:
    context = TraceContext(trace)
    records: list[Detection] = []
    for rule in rules:
        for hit in rule_hits(rule, context):
            events = [trace.events[index] for index in hit]
            records.append(
                Detection(
                    schema_version=SCHEMA_VERSION,
                    rule_id=rule.id,
                    rule_version=rule.version,
                    trace_id=trace.trace_id,
                    tier=rule.tier,
                    severity=rule.severity,
                    matched_span_ids=[event.span_id for event in events],
                    first_timestamp=min(event.timestamp for event in events),
                    last_timestamp=max(event.timestamp for event in events),
                )
            )
    return records


def scan(rules: Sequence[Rule], traces: Sequence[Trace]) -> list[Detection]:
    """Evaluate every rule on every trace. The engine never sees labels."""
    ids = [rule.id for rule in rules]
    duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
    if duplicates:
        raise ValueError(f"duplicate rule ids: {duplicates}")
    unique: dict[tuple[object, ...], Detection] = {}
    for trace in traces:
        for record in detections_for_trace(rules, trace):
            unique.setdefault(record.sort_key(), record)
    return [unique[key] for key in sorted(unique)]
