from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agent_detection_gauntlet.errors import InputError
from agent_detection_gauntlet.rules.loader import load_rule_file, load_yaml_document, rule_files
from agent_detection_gauntlet.rules.model import Rule, SequenceLogic, logic_event_types
from tests.conftest import RULES_DIR, make_rule, rule_data


def validate(data: dict[str, Any]) -> Rule:
    return Rule.model_validate_json(json.dumps(data))


def where(**condition: Any) -> dict[str, Any]:
    return {"match": {"event_types": ["tool.call"], "where": condition}}


def test_sample_rule_loads() -> None:
    rule = load_rule_file(RULES_DIR / "ADG-0001.yaml")
    assert rule.id == "ADG-0001"
    assert isinstance(rule.logic, SequenceLogic)
    assert {t.value for t in logic_event_types(rule.logic)} == {"retrieval", "tool.call"}


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"id": "ADG-1"}, "id"),
        ({"version": "1.0"}, "version"),
        ({"status": "draft"}, "status"),
        ({"tier": "keyword"}, "tier"),
        ({"severity": "urgent"}, "severity"),
        ({"title": "   "}, "whitespace"),
        ({"limitations": []}, "limitations"),
        ({"limitations": [""]}, "limitations"),
        ({"telemetry": []}, "telemetry"),
        ({"telemetry": ["retrieval", "retrieval"]}, "duplicate"),
        ({"telemetry": ["retrieval"]}, "not listed in telemetry"),
        ({"fixtures": {"tp": [], "fp": ["a"]}}, "tp"),
        ({"fixtures": {"tp": ["a"], "fp": []}}, "fp"),
        ({"fixtures": {"tp": ["a"], "fp": ["a"]}}, "both tp and fp"),
        (
            {"mappings": {"atlas": ["T0051"], "owasp_llm": [], "owasp_agentic": [], "attack": []}},
            "atlas",
        ),
        (
            {"mappings": {"atlas": [], "owasp_llm": ["LLM1"], "owasp_agentic": [], "attack": []}},
            "owasp_llm",
        ),
        (
            {"mappings": {"atlas": [], "owasp_llm": [], "owasp_agentic": ["AS01"], "attack": []}},
            "owasp_agentic",
        ),
        (
            {"mappings": {"atlas": [], "owasp_llm": [], "owasp_agentic": [], "attack": ["T12"]}},
            "attack",
        ),
        ({"mappings": {"atlas": [], "owasp_llm": [], "owasp_agentic": []}}, "attack"),
        ({"logic": {}}, "exactly one of"),
        ({"logic": {"match": {"event_types": ["tool.call"]}, "threshold": {}}}, "exactly one of"),
        ({"logic": where(field="timestamp", op="equals", value=1)}, "field must be"),
        ({"logic": where(field="attributes.", op="equals", value=1)}, "field must be"),
        ({"logic": where(field="span_id", op="exists", value="yes")}, "true or false"),
        (
            {"logic": where(field="span_id", op="exists", value=True, normalize=["nfkc"])},
            "does not take normalize",
        ),
        ({"logic": where(field="span_id", op="in", value=[])}, "non-empty list"),
        ({"logic": where(field="span_id", op="regex", value="(")}, "invalid regex"),
        ({"logic": where(field="span_id", op="regex", value="")}, "non-empty pattern"),
        ({"logic": where(field="span_id", op="startswith", value=1)}, "non-empty string"),
        ({"logic": where(field="span_id", op="contains", value="")}, "non-empty string"),
        ({"logic": where(field="span_id", op="contains", value=[1])}, "non-empty string"),
        (
            {"logic": where(field="span_id", op="equals", value=1, normalize=["casefold"] * 2)},
            "duplicate",
        ),
        ({"logic": where(field="span_id", op="like", value=1)}, "op"),
        ({"logic": {"match": {"event_types": ["tool.call"], "where": {"all": []}}}}, "all"),
        ({"logic": {"match": {"event_types": ["tool.call"], "where": 5}}}, "a condition must be"),
    ],
)
def test_rule_model_rejects(overrides: dict[str, Any], message: str) -> None:
    data = rule_data(**overrides)
    if "logic" in overrides and "telemetry" not in overrides:
        data["telemetry"] = ["retrieval", "tool.call"]
    with pytest.raises(ValidationError, match=message):
        validate(data)


def sequence(steps: list[dict[str, Any]], **options: Any) -> dict[str, Any]:
    return {"sequence": {"steps": steps, **options}}


STEP_A = {"name": "a", "match": {"event_types": ["retrieval"]}, "bind": {"x": "span_id"}}
STEP_B = {"name": "b", "match": {"event_types": ["tool.call"]}}


@pytest.mark.parametrize(
    ("logic", "message"),
    [
        (sequence([STEP_A]), "at least 2"),
        (sequence([STEP_A, {**STEP_B, "name": "a"}]), "step names must be unique"),
        (sequence([STEP_A, STEP_B], within_events=1), "greater than or equal to 2"),
        (
            sequence([STEP_A, STEP_B, STEP_B | {"name": "c"}], within_events=2),
            "at least the number of steps",
        ),
        (sequence([STEP_A, STEP_B], within_seconds=0), "greater than 0"),
        (
            sequence([STEP_A, {**STEP_B, "require": [{"op": "derives_from", "bound": "y"}]}]),
            "which no earlier step binds",
        ),
        (sequence([STEP_A, {**STEP_B, "bind": {"x": "span_id"}}]), "bound twice"),
        (
            sequence(
                [
                    STEP_A,
                    {
                        **STEP_B,
                        "require": [{"op": "derives_from", "bound": "x", "field": "span_id"}],
                    },
                ]
            ),
            "takes no field",
        ),
        (
            sequence([STEP_A, {**STEP_B, "require": [{"op": "equals", "bound": "x"}]}]),
            "needs a field",
        ),
        (sequence([{**STEP_A, "name": "Bad"}, STEP_B]), "name"),
        (
            sequence(
                [
                    {**STEP_A, "require": [{"op": "equals", "bound": "x", "field": "span_id"}]},
                    STEP_B,
                ]
            ),
            "which no earlier step binds",
        ),
        ({"threshold": {"match": {"event_types": ["tool.call"]}, "op": "lt", "value": 1}}, "op"),
        (
            {"threshold": {"match": {"event_types": ["tool.call"]}, "op": "gte", "value": 0}},
            "greater than or equal to 1",
        ),
    ],
)
def test_logic_rejects(logic: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        validate(rule_data(logic=logic))


def test_alternative_logic_kinds_validate() -> None:
    threshold = make_rule(
        telemetry=["tool.call"],
        logic={
            "threshold": {
                "match": {"event_types": ["tool.call"]},
                "distinct": "attributes.gen_ai.tool.name",
                "op": "gt",
                "value": 3,
            }
        },
    )
    assert {t.value for t in logic_event_types(threshold.logic)} == {"tool.call"}
    match = make_rule(telemetry=["tool.call"], logic={"match": {"event_types": ["tool.call"]}})
    assert {t.value for t in logic_event_types(match.logic)} == {"tool.call"}
    # Validated models can be passed back in, which exercises the discriminators on objects.
    assert Rule.model_validate(match.model_dump(by_alias=True)) == match


def test_condition_tree_round_trip() -> None:
    logic = where(
        all=[
            {"any": [{"field": "span_id", "op": "equals", "value": "a"}]},
            {"not": {"field": "span_id", "op": "equals", "value": "b"}},
        ]
    )
    rule = make_rule(telemetry=["tool.call"], logic=logic)
    again = Rule.model_validate(rule)
    assert again == rule
    assert Rule.model_validate_json(rule.model_dump_json(by_alias=True)) == rule


def test_yaml_document_rules() -> None:
    assert json.loads(load_yaml_document("a: 1\n", "x")) == {"a": 1}
    with pytest.raises(ValueError, match="duplicate key 'a'"):
        load_yaml_document("a: 1\na: 2\n", "x")
    with pytest.raises(ValueError, match="must be a mapping"):
        load_yaml_document("- a\n", "x")
    with pytest.raises(ValueError, match="invalid YAML"):
        load_yaml_document("a: [\n", "x")
    with pytest.raises(ValueError, match="not plain JSON data"):
        load_yaml_document("a: 2026-01-01\n", "x")
    with pytest.raises(ValueError, match="invalid YAML"):
        load_yaml_document("a: !!python/object:os.system {}\n", "x")


def test_yaml_number_for_version_fails_closed(tmp_path: Path) -> None:
    text = (RULES_DIR / "ADG-0001.yaml").read_text(encoding="utf-8")
    path = tmp_path / "ADG-0001.yaml"
    path.write_text(text.replace("version: 0.1.0", "version: 1.5"), encoding="utf-8")
    with pytest.raises(InputError, match="version"):
        load_rule_file(path)


def test_rule_files_and_unreadable(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="does not exist"):
        rule_files(tmp_path / "missing")
    with pytest.raises(InputError, match="no rule files"):
        rule_files(tmp_path)
    bad = tmp_path / "ADG-0002.yaml"
    bad.write_bytes(b"\xff\xfe")
    with pytest.raises(InputError, match="cannot read rule file"):
        load_rule_file(bad)
