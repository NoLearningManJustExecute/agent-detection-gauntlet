from __future__ import annotations

import json
from typing import Any

from agent_detection_gauntlet.engine.primitives import TraceContext, run_sequence
from agent_detection_gauntlet.rules.model import SequenceSpec
from agent_detection_gauntlet.schema.trace import TraceEvent
from tests.conftest import make_event, make_trace, taint_trace_events


def spec(steps: list[dict[str, Any]], **options: Any) -> SequenceSpec:
    return SequenceSpec.model_validate_json(json.dumps({"steps": steps, **options}))


def step(name: str, event_type: str, where: dict[str, Any] | None = None, **extra: Any) -> dict:
    match: dict[str, Any] = {"event_types": [event_type]}
    if where is not None:
        match["where"] = where
    return {"name": name, "match": match, **extra}


UNTRUSTED = {"field": "attributes.adg.source.trust", "op": "equals", "value": "untrusted"}
SEND = {"field": "attributes.gen_ai.tool.name", "op": "equals", "value": "send_email"}

TAINT = spec(
    [
        step("fetch", "retrieval", UNTRUSTED, bind={"src": "span_id"}),
        step("send", "tool.call", SEND, require=[{"op": "derives_from", "bound": "src"}]),
    ]
)


def hits(sequence: SequenceSpec, events: list[TraceEvent]) -> list[tuple[int, ...]]:
    return run_sequence(sequence, TraceContext(make_trace(events)))


def events_from(dicts: list[dict[str, Any]]) -> list[TraceEvent]:
    return [TraceEvent.model_validate_json(json.dumps(d)) for d in dicts]


def test_bind_positive_through_transitive_chain() -> None:
    assert hits(TAINT, events_from(taint_trace_events("t"))) == [(1, 4)]


def test_bind_broken_taint_chain() -> None:
    assert hits(TAINT, events_from(taint_trace_events("t", linked=False))) == []


def test_bind_trusted_source_does_not_start_sequence() -> None:
    assert hits(TAINT, events_from(taint_trace_events("t", trust="trusted"))) == []


def test_bind_wrong_order() -> None:
    events = [
        make_event("a1", "tool.call", {"gen_ai.tool.name": "send_email"}),
        make_event("a2", "retrieval", {"adg.source.trust": "untrusted"}, seconds=1),
    ]
    assert hits(TAINT, events) == []
    plain = spec([step("fetch", "retrieval", UNTRUSTED), step("send", "tool.call", SEND)])
    assert hits(plain, events) == []


def test_derives_from_requires_a_link_to_the_bound_span() -> None:
    events = [
        make_event("r1", "retrieval", {"adg.source.trust": "untrusted"}),
        make_event("r2", "retrieval", {"adg.source.trust": "untrusted"}, seconds=1),
        make_event(
            "c1",
            "tool.call",
            {"gen_ai.tool.name": "send_email", "adg.content.ref": ["r2"]},
            seconds=2,
        ),
    ]
    # r1 matches the first step but has no link; the search backtracks to r2.
    assert hits(TAINT, events) == [(1, 2)]


def test_one_hit_per_final_event_with_earliest_assignment() -> None:
    events = [
        make_event("r1", "retrieval", {"adg.source.trust": "untrusted"}),
        make_event("c1", "tool.call", {"gen_ai.tool.name": "send_email"}, seconds=1),
        make_event("c2", "tool.call", {"gen_ai.tool.name": "send_email"}, seconds=2),
    ]
    plain = spec([step("fetch", "retrieval", UNTRUSTED), step("send", "tool.call", SEND)])
    assert hits(plain, events) == [(0, 1), (0, 2)]


def test_within_events_limit() -> None:
    events = [
        make_event("e1", "retrieval", {"adg.source.trust": "untrusted"}),
        make_event("e2", "llm.request", seconds=1),
        make_event("e3", "llm.response", seconds=2),
        make_event("e4", "tool.call", {"gen_ai.tool.name": "send_email"}, seconds=3),
    ]
    steps = [step("fetch", "retrieval", UNTRUSTED), step("send", "tool.call", SEND)]
    assert hits(spec(steps, within_events=4), events) == [(0, 3)]
    assert hits(spec(steps, within_events=3), events) == []


def test_within_seconds_limit_is_inclusive() -> None:
    events = [
        make_event("e1", "retrieval", {"adg.source.trust": "untrusted"}),
        make_event("e2", "tool.call", {"gen_ai.tool.name": "send_email"}, seconds=30),
    ]
    steps = [step("fetch", "retrieval", UNTRUSTED), step("send", "tool.call", SEND)]
    assert hits(spec(steps, within_seconds=30), events) == [(0, 1)]
    assert hits(spec(steps, within_seconds=29.5), events) == []


def test_window_prefers_later_start_when_earlier_is_outside() -> None:
    events = [
        make_event("e1", "retrieval", {"adg.source.trust": "untrusted"}),
        make_event("e2", "retrieval", {"adg.source.trust": "untrusted"}, seconds=50),
        make_event("e3", "tool.call", {"gen_ai.tool.name": "send_email"}, seconds=55),
    ]
    steps = [step("fetch", "retrieval", UNTRUSTED), step("send", "tool.call", SEND)]
    assert hits(spec(steps, within_seconds=10), events) == [(1, 2)]


def test_equals_and_contains_requirements() -> None:
    events = [
        make_event("c1", "tool.call", {"gen_ai.tool.call.id": "call-7", "x.tags": ["a", "b"]}),
        make_event(
            "c2",
            "tool.result",
            {"gen_ai.tool.call.id": "call-7", "adg.content.text": "result of b here"},
            seconds=1,
        ),
    ]
    by_id = spec(
        [
            step("call", "tool.call", bind={"cid": "attributes.gen_ai.tool.call.id"}),
            step(
                "result",
                "tool.result",
                require=[
                    {"op": "equals", "field": "attributes.gen_ai.tool.call.id", "bound": "cid"}
                ],
            ),
        ]
    )
    assert hits(by_id, events) == [(0, 1)]

    by_text = spec(
        [
            step("call", "tool.call", bind={"tag": "attributes.x.tags"}),
            step(
                "result",
                "tool.result",
                require=[
                    {"op": "contains", "field": "attributes.adg.content.text", "bound": "tag"}
                ],
            ),
        ]
    )
    # The bound value is a list, so substring containment on text does not hold.
    assert hits(by_text, events) == []


def test_contains_requirement_on_list_and_scalar() -> None:
    events = [
        make_event("r1", "retrieval", {"adg.source.trust": "untrusted"}),
        make_event("c1", "tool.call", {"adg.content.ref": ["r1"], "x.count": 1}, seconds=1),
    ]
    on_list = spec(
        [
            step("fetch", "retrieval", bind={"src": "span_id"}),
            step(
                "send",
                "tool.call",
                require=[{"op": "contains", "field": "attributes.adg.content.ref", "bound": "src"}],
            ),
        ]
    )
    assert hits(on_list, events) == [(0, 1)]
    on_scalar = spec(
        [
            step("fetch", "retrieval", bind={"src": "span_id"}),
            step(
                "send",
                "tool.call",
                require=[{"op": "contains", "field": "attributes.x.count", "bound": "src"}],
            ),
        ]
    )
    assert hits(on_scalar, events) == []
    missing = spec(
        [
            step("fetch", "retrieval", bind={"src": "span_id"}),
            step(
                "send",
                "tool.call",
                require=[{"op": "equals", "field": "attributes.absent", "bound": "src"}],
            ),
        ]
    )
    assert hits(missing, events) == []


def test_bind_on_missing_field_means_step_does_not_hold() -> None:
    events = [
        make_event("r1", "retrieval", {"adg.source.trust": "untrusted"}),
        make_event("c1", "tool.call", {"adg.content.ref": ["r1"]}, seconds=1),
    ]
    sequence = spec(
        [
            step("fetch", "retrieval", bind={"src": "attributes.gen_ai.data_source.id"}),
            step("send", "tool.call"),
        ]
    )
    assert hits(sequence, events) == []


def test_derives_from_with_non_string_bound_value() -> None:
    events = [
        make_event("r1", "retrieval", {"adg.source.trust": "untrusted", "x.n": 1}),
        make_event("c1", "tool.call", {"adg.content.ref": ["r1"]}, seconds=1),
    ]
    sequence = spec(
        [
            step("fetch", "retrieval", bind={"n": "attributes.x.n"}),
            step("send", "tool.call", require=[{"op": "derives_from", "bound": "n"}]),
        ]
    )
    assert hits(sequence, events) == []


def test_three_step_sequence_with_backtracking() -> None:
    events = [
        make_event("p1", "user.prompt", {"x.k": "a"}),
        make_event("p2", "user.prompt", {"x.k": "b"}, seconds=1),
        make_event("l1", "llm.response", {"x.k": "b"}, seconds=2),
        make_event("c1", "tool.call", {"x.k": "b"}, seconds=3),
    ]
    sequence = spec(
        [
            step("first", "user.prompt", bind={"k": "attributes.x.k"}),
            step(
                "middle",
                "llm.response",
                require=[{"op": "equals", "field": "attributes.x.k", "bound": "k"}],
            ),
            step(
                "last",
                "tool.call",
                require=[{"op": "equals", "field": "attributes.x.k", "bound": "k"}],
            ),
        ]
    )
    assert hits(sequence, events) == [(1, 2, 3)]


def test_final_step_requirement_failure() -> None:
    events = [
        make_event("p1", "user.prompt", {"x.k": "a"}),
        make_event("c1", "tool.call", {"x.k": "b"}, seconds=1),
    ]
    sequence = spec(
        [
            step("first", "user.prompt", bind={"k": "attributes.x.k"}),
            step(
                "last",
                "tool.call",
                require=[{"op": "equals", "field": "attributes.x.k", "bound": "k"}],
            ),
        ]
    )
    assert hits(sequence, events) == []


def test_ancestors_are_transitive_and_exclude_self() -> None:
    trace = make_trace(events_from(taint_trace_events("t")))
    context = TraceContext(trace)
    assert context.ancestors("s5") == frozenset({"s1", "s2", "s3", "s4"})
    assert context.ancestors("s2") == frozenset()
    assert context.ancestors("unknown") == frozenset()
