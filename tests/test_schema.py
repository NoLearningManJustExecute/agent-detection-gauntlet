from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from agent_detection_gauntlet.schema.common import (
    format_utc_timestamp,
    parse_utc_timestamp,
    unique_items,
)
from agent_detection_gauntlet.schema.detection import Detection
from agent_detection_gauntlet.schema.labels import LabelRecord
from agent_detection_gauntlet.schema.trace import TraceEvent, integrity_problems
from tests.conftest import event_dict, make_event


def validate(data: dict[str, Any]) -> TraceEvent:
    return TraceEvent.model_validate_json(json.dumps(data))


def test_valid_event_round_trips() -> None:
    event = make_event(
        "s1",
        "retrieval",
        {"adg.source.trust": "untrusted", "adg.data.labels": ["public"], "x.custom": {"a": 1}},
    )
    dumped = event.model_dump(mode="json")
    assert dumped["timestamp"] == "2026-01-15T09:00:00Z"
    assert validate(dumped) == event


@pytest.mark.parametrize(
    "stamp",
    [
        "2026-01-15T09:00:00",  # no offset
        "2026-01-15T09:00:00+02:00",  # not UTC
        "2026-01-15 09:00:00Z",  # space separator
        "2026-13-15T09:00:00Z",  # bad month
        "2026-01-15T09:00:00.1234567Z",  # too many fractional digits
    ],
)
def test_timestamp_must_be_rfc3339_utc(stamp: str) -> None:
    data = event_dict("s1", "session.start")
    data["timestamp"] = stamp
    with pytest.raises(ValidationError, match="timestamp"):
        validate(data)


def test_timestamp_rejects_numbers() -> None:
    data = event_dict("s1", "session.start")
    data["timestamp"] = 1768467600
    with pytest.raises(ValidationError):
        validate(data)


def test_timestamp_helpers() -> None:
    parsed = parse_utc_timestamp("2026-01-15T09:00:00.5+00:00")
    assert format_utc_timestamp(parsed) == "2026-01-15T09:00:00.500000Z"
    aware = datetime(2026, 1, 1, tzinfo=UTC)
    assert parse_utc_timestamp(aware) == aware
    with pytest.raises(ValueError, match="UTC"):
        parse_utc_timestamp(datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="UTC"):
        parse_utc_timestamp(datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=1))))


def test_unknown_event_type_rejected() -> None:
    with pytest.raises(ValidationError, match="event_type"):
        validate(event_dict("s1", "tool.invoke"))


def test_unknown_top_level_field_rejected() -> None:
    data = event_dict("s1", "session.start")
    data["label"] = "malicious"
    with pytest.raises(ValidationError, match="label"):
        validate(data)


def test_parent_span_id_is_required_but_nullable() -> None:
    data = event_dict("s1", "session.start")
    del data["parent_span_id"]
    with pytest.raises(ValidationError, match="parent_span_id"):
        validate(data)


@pytest.mark.parametrize(
    ("event_type", "attributes", "message"),
    [
        ("retrieval", {}, "must carry adg.source.trust"),
        ("retrieval", {"adg.source.trust": "maybe"}, "adg.source.trust must be one of"),
        ("user.prompt", {"adg.data.labels": []}, "non-empty list"),
        ("user.prompt", {"adg.data.labels": ["top-secret"]}, "drawn from"),
        ("user.prompt", {"adg.data.labels": ["pii", "pii"]}, "must not repeat"),
        ("user.prompt", {"adg.content.ref": "s0"}, "non-empty list of span ids"),
        ("user.prompt", {"adg.content.ref": ["bad id"]}, "entries must be span ids"),
        ("user.prompt", {"adg.content.ref": ["s0", "s0"]}, "must not repeat"),
        ("user.prompt", {"adg.content.ref": ["s1"]}, "must not reference the event itself"),
        ("user.prompt", {"adg.content.text": 5}, "must be a string"),
        ("user.prompt", {"adg.unknown": 1}, "unknown adg attribute"),
        ("user.prompt", {"": 1}, "non-empty"),
        ("tool.call", {"gen_ai.tool.name": 7}, "gen_ai.tool.name must be a string"),
        ("session.start", {"adg.source.trust": "trusted"}, "content-bearing"),
        ("guardrail.action", {"adg.guardrail.decision": "maybe"}, "must be one of"),
        ("tool.call", {"adg.guardrail.decision": "block"}, "only allowed on guardrail.action"),
        ("tool.call", {"adg.guardrail.name": "egress"}, "only allowed on guardrail.action"),
        ("guardrail.action", {"adg.guardrail.name": "bad name"}, "must be an identifier"),
        ("guardrail.action", {"adg.guardrail.stage": "elsewhere"}, "must be one of"),
    ],
)
def test_attribute_validation(event_type: str, attributes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        validate(event_dict("s1", event_type, attributes))


def test_parent_cannot_be_self() -> None:
    with pytest.raises(ValidationError, match="parent_span_id must not equal"):
        validate(event_dict("s1", "session.start", parent="s1"))


def test_guardrail_decision_accepted() -> None:
    event = make_event("s1", "guardrail.action", {"adg.guardrail.decision": "block"})
    assert event.content_refs() == ()


def test_integrity_problems() -> None:
    events = [
        make_event("s1", "user.prompt", {"adg.content.ref": ["s2"]}),
        make_event("s2", "llm.request", seconds=1, parent="ghost"),
        make_event("s2", "llm.response", {"adg.content.ref": ["nope"]}, seconds=2),
        make_event("s3", "session.end", trace_id="other", seconds=3),
    ]
    messages = [message for _, message in integrity_problems(events)]
    assert any("several traces" in m for m in messages)
    assert any("duplicate span_id" in m for m in messages)
    assert any("parent_span_id 'ghost'" in m for m in messages)
    assert any("earlier event" in m for m in messages)
    assert any("'nope' is not a span" in m for m in messages)


def test_unique_items() -> None:
    assert unique_items([1, 2]) == [1, 2]
    with pytest.raises(ValueError, match="duplicate"):
        unique_items([1, 1])


LABEL = {
    "schema_version": "0.1",
    "trace_id": "t-1",
    "label": "malicious",
    "attack_class": "indirect_prompt_injection",
    "attack_succeeded": True,
    "mutation": None,
    "guardrails": "off",
    "split": "heldout",
    "source": "synthetic",
}


def test_label_valid() -> None:
    assert LabelRecord.model_validate_json(json.dumps(LABEL)).attack_succeeded is True


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"attack_class": None}, "need an attack_class"),
        ({"attack_succeeded": None}, "need attack_succeeded"),
        ({"attack_succeeded": "yes"}, "attack_succeeded"),
        ({"label": "benign"}, "benign labels must have null"),
        (
            {"label": "benign", "attack_class": None, "attack_succeeded": None, "mutation": "b64"},
            "null mutation",
        ),
        ({"split": "test"}, "split"),
        ({"source": "elsewhere"}, "source"),
        ({"guardrails": True}, "guardrails"),
    ],
)
def test_label_rules(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        LabelRecord.model_validate_json(json.dumps({**LABEL, **overrides}))


def test_detection_order_check() -> None:
    data = {
        "schema_version": "0.1",
        "rule_id": "ADG-0001",
        "rule_version": "0.1.0",
        "trace_id": "t-1",
        "tier": "sequence",
        "severity": "high",
        "matched_span_ids": ["s1"],
        "first_timestamp": "2026-01-15T09:00:05Z",
        "last_timestamp": "2026-01-15T09:00:00Z",
    }
    with pytest.raises(ValidationError, match="must not be before"):
        Detection.model_validate_json(json.dumps(data))


def test_parent_cycle_is_reported() -> None:
    events = [
        make_event("a", "llm.request", parent="b"),
        make_event("b", "llm.response", seconds=1, parent="a"),
    ]
    messages = [message for _, message in integrity_problems(events)]
    assert any("loops" in m for m in messages)


def test_guardrail_name_and_stage_need_0_2() -> None:
    attributes = {
        "adg.guardrail.decision": "block",
        "adg.guardrail.name": "tool_permissions",
        "adg.guardrail.stage": "tool_call",
    }
    data = event_dict("s1", "guardrail.action", attributes)
    data["schema_version"] = "0.2"
    assert validate(data).attributes["adg.guardrail.stage"] == "tool_call"
    data["schema_version"] = "0.1"
    with pytest.raises(ValidationError, match=r"need schema_version 0.2"):
        validate(data)


def test_event_versions_accepted() -> None:
    for version in ("0.1", "0.2", "0.3"):
        data = event_dict("s1", "session.start")
        data["schema_version"] = version
        assert validate(data).schema_version == version
    data["schema_version"] = "0.9"
    with pytest.raises(ValidationError, match="schema_version"):
        validate(data)


LABEL_0_2 = {
    **LABEL,
    "schema_version": "0.2",
    "scenario_id": "AC01",
    "condition": "baseline",
    "source_run_id": "phase4-baseline:attack:AC01:0",
}


def test_label_0_2_optional_fields() -> None:
    record = LabelRecord.model_validate_json(json.dumps(LABEL_0_2))
    assert record.scenario_id == "AC01"
    assert record.task_id is None
    unassigned = LabelRecord.model_validate_json(json.dumps({**LABEL_0_2, "split": None}))
    assert unassigned.split is None
    benign = {
        **LABEL_0_2,
        "label": "benign",
        "attack_class": None,
        "attack_succeeded": None,
        "scenario_id": None,
        "task_id": "BT-001",
    }
    assert LabelRecord.model_validate_json(json.dumps(benign)).task_id == "BT-001"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"schema_version": "0.1"}, "need schema_version 0.2"),
        ({"task_id": "BT-001"}, "must not carry a task_id"),
        ({"scenario_id": ""}, "scenario_id"),
        (
            {"label": "benign", "attack_class": None, "attack_succeeded": None},
            "must not carry a scenario_id",
        ),
    ],
)
def test_label_0_2_rules(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        LabelRecord.model_validate_json(json.dumps({**LABEL_0_2, **overrides}))


LABEL_0_3 = {
    **LABEL_0_2,
    "schema_version": "0.3",
    "scenario_id": "AC01-S03",
    "variant_group": "AC01-S03",
    "derived_from": "AC01",
}


def test_label_0_3_group_fields() -> None:
    record = LabelRecord.model_validate_json(json.dumps(LABEL_0_3))
    assert (record.variant_group, record.derived_from) == ("AC01-S03", "AC01")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"schema_version": "0.2"}, r"need schema_version 0\.3"),
        ({"schema_version": "0.2", "derived_from": None}, r"need schema_version 0\.3"),
        ({"variant_group": ""}, "variant_group"),
        (
            {
                "label": "benign",
                "attack_class": None,
                "attack_succeeded": None,
                "scenario_id": None,
                "task_id": "BT-001",
            },
            "must not carry derived_from",
        ),
    ],
)
def test_label_0_3_rules(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        LabelRecord.model_validate_json(json.dumps({**LABEL_0_3, **overrides}))


def test_label_0_1_needs_a_split() -> None:
    with pytest.raises(ValidationError, match="split must be dev or heldout"):
        LabelRecord.model_validate_json(json.dumps({**LABEL, "split": None}))


@pytest.mark.parametrize("key", ["scenario_id", "task_id", "condition", "source_run_id"])
def test_label_0_1_rejects_0_2_keys_even_when_null(key: str) -> None:
    with pytest.raises(ValidationError, match=r"need schema_version 0\.2"):
        LabelRecord.model_validate_json(json.dumps({**LABEL, key: None}))


def test_label_0_2_benign_rejects_scenario_id() -> None:
    benign = {**LABEL_0_2, "label": "benign", "attack_class": None, "attack_succeeded": None}
    with pytest.raises(ValidationError, match="must not carry a scenario_id"):
        LabelRecord.model_validate_json(json.dumps(benign))


def test_0_1_event_rejects_guardrail_stage_alone() -> None:
    data = event_dict("s1", "guardrail.action", {"adg.guardrail.stage": "tool_call"})
    with pytest.raises(ValidationError, match=r"need schema_version 0\.2"):
        validate(data)


def test_trace_must_not_mix_versions() -> None:
    newer = event_dict("s2", "session.end")
    newer["schema_version"] = "0.2"
    newer["timestamp"] = "2026-01-15T09:00:01Z"
    events = [make_event("s1", "session.start"), validate(newer)]
    assert any("mixes schema versions" in m for _, m in integrity_problems(events))


def test_0_1_detection_still_reads() -> None:
    data = {
        "schema_version": "0.1",
        "rule_id": "ADG-0001",
        "rule_version": "0.1.0",
        "trace_id": "t-1",
        "tier": "sequence",
        "severity": "high",
        "matched_span_ids": ["s1"],
        "first_timestamp": "2026-01-15T09:00:00Z",
        "last_timestamp": "2026-01-15T09:00:00Z",
    }
    assert Detection.model_validate_json(json.dumps(data)).schema_version == "0.1"
