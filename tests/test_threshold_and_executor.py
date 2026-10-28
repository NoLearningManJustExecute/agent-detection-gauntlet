from __future__ import annotations

import json
from typing import Any

import pytest

from agent_detection_gauntlet.engine.executor import scan
from agent_detection_gauntlet.engine.primitives import TraceContext, run_threshold
from agent_detection_gauntlet.rules.model import ThresholdSpec
from agent_detection_gauntlet.schema.trace import TraceEvent
from tests.conftest import make_event, make_rule, make_trace


def threshold(**data: Any) -> ThresholdSpec:
    base: dict[str, Any] = {"match": {"event_types": ["tool.call"]}, "op": "gte", "value": 2}
    base.update(data)
    return ThresholdSpec.model_validate_json(json.dumps(base))


def calls(*names: str | None) -> list[TraceEvent]:
    events = []
    for index, name in enumerate(names):
        attributes = {} if name is None else {"gen_ai.tool.name": name}
        events.append(make_event(f"c{index}", "tool.call", attributes, seconds=index))
    return events


def run(spec: ThresholdSpec, events: list[TraceEvent]) -> list[tuple[int, ...]]:
    return run_threshold(spec, TraceContext(make_trace(events)))


@pytest.mark.parametrize(
    ("op", "value", "count", "fires"),
    [
        ("gte", 2, 2, True),
        ("gte", 3, 2, False),
        ("gt", 1, 2, True),
        ("gt", 2, 2, False),
        ("eq", 2, 2, True),
        ("eq", 1, 2, False),
    ],
)
def test_count_comparisons(op: str, value: int, count: int, fires: bool) -> None:
    events = calls(*["send_email"] * count)
    result = run(threshold(op=op, value=value), events)
    assert (result == [tuple(range(count))]) is fires
    assert bool(result) is fires


def test_distinct_count_ignores_missing_field() -> None:
    events = calls("a", "b", "a", None)
    assert run(threshold(distinct="attributes.gen_ai.tool.name", value=2), events) == [(0, 1, 2)]
    assert run(threshold(distinct="attributes.gen_ai.tool.name", value=3), events) == []


def test_distinct_with_no_values_never_fires() -> None:
    events = calls(None, None)
    assert run(threshold(distinct="attributes.gen_ai.tool.name", value=1), events) == []


def test_threshold_respects_where_clause() -> None:
    spec = threshold(
        match={
            "event_types": ["tool.call"],
            "where": {"field": "attributes.gen_ai.tool.name", "op": "equals", "value": "x"},
        },
        value=1,
    )
    assert run(spec, calls("x", "y")) == [(0,)]


def test_no_matching_events() -> None:
    assert run(threshold(value=1), [make_event("s1", "session.start")]) == []


def match_rule() -> Any:
    return make_rule(
        id="ADG-9002",
        tier="content",
        telemetry=["tool.call"],
        logic={
            "match": {
                "event_types": ["tool.call"],
                "where": {"field": "attributes.gen_ai.tool.name", "op": "exists", "value": True},
            }
        },
    )


def threshold_rule() -> Any:
    return make_rule(
        id="ADG-9003",
        tier="behavior",
        telemetry=["tool.call"],
        logic={"threshold": {"match": {"event_types": ["tool.call"]}, "op": "gte", "value": 2}},
    )


def test_scan_emits_sorted_records_for_every_primitive() -> None:
    trace_b = make_trace(
        [
            make_event("r1", "retrieval", {"adg.source.trust": "untrusted"}, trace_id="t-b"),
            make_event(
                "c1",
                "tool.call",
                {"gen_ai.tool.name": "send_email", "adg.content.ref": ["r1"]},
                trace_id="t-b",
                seconds=5,
            ),
            make_event("c2", "tool.call", {"gen_ai.tool.name": "x"}, trace_id="t-b", seconds=9),
        ],
        trace_id="t-b",
    )
    trace_a = make_trace(
        [make_event("c1", "tool.call", {"gen_ai.tool.name": "y"}, trace_id="t-a")],
        trace_id="t-a",
    )
    rules = [threshold_rule(), make_rule(), match_rule()]
    records = scan(rules, [trace_b, trace_a])
    summary = [(r.trace_id, r.rule_id, r.matched_span_ids, r.tier.value) for r in records]
    assert summary == [
        ("t-a", "ADG-9002", ["c1"], "content"),
        ("t-b", "ADG-9001", ["r1", "c1"], "sequence"),
        ("t-b", "ADG-9002", ["c1"], "content"),
        ("t-b", "ADG-9002", ["c2"], "content"),
        ("t-b", "ADG-9003", ["c1", "c2"], "behavior"),
    ]
    sequence_hit = records[1]
    assert sequence_hit.first_timestamp < sequence_hit.last_timestamp
    assert sequence_hit.severity.value == "high"
    assert scan(rules, [trace_a, trace_b]) == records


def test_scan_rejects_duplicate_rule_ids() -> None:
    with pytest.raises(ValueError, match="duplicate rule ids"):
        scan([make_rule(), make_rule()], [])


def test_distinct_treats_whole_floats_as_integers() -> None:
    events = [
        make_event("c0", "tool.call", {"x.n": 1}),
        make_event("c1", "tool.call", {"x.n": 1.0}, seconds=1),
        make_event("c2", "tool.call", {"x.n": {"k": [2.0]}}, seconds=2),
        make_event("c3", "tool.call", {"x.n": {"k": [2]}}, seconds=3),
        make_event("c4", "tool.call", {"x.n": 1.5}, seconds=4),
    ]
    assert run(threshold(distinct="attributes.x.n", op="eq", value=3), events) == [(0, 1, 2, 3, 4)]
