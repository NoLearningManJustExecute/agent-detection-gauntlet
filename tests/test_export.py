"""Phase 6: generated artifacts, the Sigma round trip, rule lint and the release workflow."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.types import SigmaRegularExpression

from agent_detection_gauntlet.cli import main
from agent_detection_gauntlet.export.convert import (
    FORMATS,
    HEADER,
    LABEL,
    RENDERERS,
    conversion_gap,
    target_field,
)
from agent_detection_gauntlet.export.run import (
    export_rules,
    render_field_mappings,
    render_not_converted,
)
from agent_detection_gauntlet.rules.lint import lint_rule, lint_rules
from agent_detection_gauntlet.rules.loader import LoadedRule, load_rule_file, rule_files
from agent_detection_gauntlet.rules.model import FieldCondition, MatchLogic, Rule
from tests.conftest import make_rule

EXPECTED = {
    "sigma": ["ADG-0004", "ADG-0005", "ADG-0006", "ADG-0014"],
    "kql": ["ADG-0004", "ADG-0006", "ADG-0014"],
    "spl": ["ADG-0004", "ADG-0005", "ADG-0006", "ADG-0014"],
    "esql": ["ADG-0006"],
}
NEVER_CONVERTED = [
    "ADG-0001",
    "ADG-0007",
    "ADG-0008",
    "ADG-0009",
    "ADG-0010",
    "ADG-0011",
    "ADG-0012",
    "ADG-0013",
]
SHA = "0" * 64


def real_rules() -> list[LoadedRule]:
    return [LoadedRule(path, load_rule_file(path)) for path in rule_files(Path("rules"))]


def where_rule(where: dict[str, Any], **overrides: Any) -> Rule:
    logic = {"match": {"event_types": ["user.prompt"], "where": where}}
    return make_rule(telemetry=["user.prompt"], logic=logic, **overrides)


REGEX_FIELD = "attributes.adg.content.text"


def regex_rule(pattern: str) -> Rule:
    return where_rule({"field": REGEX_FIELD, "op": "regex", "value": pattern})


# What converts


@pytest.mark.parametrize("target", list(FORMATS))
def test_measured_conversion_set(target: str) -> None:
    converted = [item.rule.id for item in real_rules() if conversion_gap(item.rule, target) is None]
    assert converted == EXPECTED[target]


@pytest.mark.parametrize("rule_id", NEVER_CONVERTED)
def test_sequence_and_baseline_rules_never_convert(rule_id: str) -> None:
    rule = load_rule_file(Path("rules") / f"{rule_id}.yaml")
    for target in FORMATS:
        assert conversion_gap(rule, target)


def test_reasons_name_the_mechanism() -> None:
    gap = {
        rule_id: conversion_gap(load_rule_file(Path("rules") / f"{rule_id}.yaml"), "sigma")
        for rule_id in ("ADG-0001", "ADG-0008", "ADG-0011", "ADG-0012", "ADG-0002", "ADG-0003")
    }
    assert "bind" in str(gap["ADG-0001"])
    assert "timespan" in str(gap["ADG-0008"])
    assert "Baseline" in str(gap["ADG-0011"])
    assert "first_occurrence" in str(gap["ADG-0012"])
    assert "\\b" in str(gap["ADG-0002"])
    assert "\\s" in str(gap["ADG-0003"])


@pytest.mark.parametrize(
    ("pattern", "target", "word"),
    [
        (r"a\bc", "sigma", r"\b"),
        (r"(?i)abc", "spl", "group flag"),
        (r"(a)\1", "kql", "back-reference"),
        (r"^abc", "esql", "Lucene"),
        (r"a.c", "esql", "Lucene"),
        (r"<abc>", "esql", "Lucene"),
        (r"a*", "kql", "empty text"),
    ],
)
def test_regex_gaps(pattern: str, target: str, word: str) -> None:
    assert word in str(conversion_gap(regex_rule(pattern), target))


def test_an_escaped_backslash_is_not_a_unicode_class() -> None:
    assert conversion_gap(regex_rule(r"[\\/]b"), "sigma") is None


def test_negation_and_unsupported_operators_are_refused() -> None:
    field = {"field": REGEX_FIELD, "op": "regex", "value": "abc"}
    assert "Negation" in str(conversion_gap(where_rule({"not": field}), "sigma"))
    assert "Negation" in str(conversion_gap(where_rule({"all": [{"not": field}]}), "sigma"))
    assert "Negation" in str(conversion_gap(where_rule({"any": [{"not": field}]}), "sigma"))
    contains = {"field": REGEX_FIELD, "op": "contains", "value": "abc"}
    assert "Operator contains" in str(conversion_gap(where_rule(contains), "sigma"))
    number = {"field": REGEX_FIELD, "op": "equals", "value": 3}
    assert "non-string" in str(conversion_gap(where_rule(number), "kql"))


def test_threshold_is_refused() -> None:
    logic = {"threshold": {"match": {"event_types": ["user.prompt"]}, "op": "gte", "value": 2}}
    rule = make_rule(telemetry=["user.prompt"], logic=logic)
    for target in FORMATS:
        assert "timespan" in str(conversion_gap(rule, target))


def test_a_rule_with_no_condition_converts_everywhere() -> None:
    rule = make_rule(telemetry=["user.prompt"], logic={"match": {"event_types": ["user.prompt"]}})
    for target in FORMATS:
        assert conversion_gap(rule, target) is None
        assert "user.prompt" in RENDERERS[target](rule, SHA)


def test_target_field_carries_normalization_and_paths() -> None:
    logic = load_rule_file(Path("rules/ADG-0006.yaml")).logic
    assert isinstance(logic, MatchLogic)
    condition = logic.match.where
    assert isinstance(condition, FieldCondition)
    assert target_field(condition) == "adg.content.text__nfkc_casefold_collapse_whitespace"
    arguments = FieldCondition.model_validate_json(
        '{"field": "attributes.gen_ai.tool.call.arguments#*", "op": "exists", "value": true}'
    )
    assert target_field(arguments) == "gen_ai.tool.call.arguments.__all_strings"
    path = FieldCondition.model_validate_json(
        '{"field": "attributes.gen_ai.tool.call.arguments#path", "op": "exists", "value": true}'
    )
    assert target_field(path) == "gen_ai.tool.call.arguments.path"
    plain = FieldCondition.model_validate_json(
        '{"field": "event_type", "op": "exists", "value": true}'
    )
    assert target_field(plain) == "event_type"


# Rendered text


@pytest.mark.parametrize("target", list(FORMATS))
def test_every_file_carries_the_header_and_label(target: str, tmp_path: Path) -> None:
    export_rules(real_rules(), [target], tmp_path)
    files = sorted((tmp_path / target).iterdir())
    assert [path.stem for path in files] == EXPECTED[target]
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert HEADER in text
        assert LABEL in text
        assert ":\\" not in text


def test_nothing_is_emitted_for_a_rule_that_does_not_convert(tmp_path: Path) -> None:
    export_rules(real_rules(), list(FORMATS), tmp_path)
    emitted = {path.stem for path in tmp_path.rglob("ADG-*")}
    assert emitted.isdisjoint(NEVER_CONVERTED)
    listing = (tmp_path / "NOT_CONVERTED.md").read_text(encoding="utf-8")
    for rule_id in NEVER_CONVERTED:
        assert rule_id in listing


def test_not_converted_lists_every_rule_format_pair_missing() -> None:
    rules = real_rules()
    listing = render_not_converted(rules)
    for target, converted in EXPECTED.items():
        for item in rules:
            if item.rule.id not in converted:
                rows = [
                    line
                    for line in listing.splitlines()
                    if line.startswith(f"| {item.rule.id} |") and target in line.split("|")[2]
                ]
                assert rows, (item.rule.id, target)


def test_export_is_byte_identical_and_removes_a_stale_query(tmp_path: Path) -> None:
    first, second = tmp_path / "one", tmp_path / "two"
    export_rules(real_rules(), list(FORMATS), first)
    export_rules(real_rules(), list(FORMATS), second)
    for path in first.rglob("*"):
        if path.is_file():
            assert path.read_bytes() == (second / path.relative_to(first)).read_bytes()
    stale = first / "sigma" / "ADG-0001.yml"
    stale.write_text("old", encoding="utf-8")
    export_rules(real_rules(), ["sigma"], first)
    assert not stale.exists()


def test_generated_queries_keep_the_native_regex() -> None:
    rule = load_rule_file(Path("rules/ADG-0014.yaml"))
    kql = RENDERERS["kql"](rule, SHA)
    spl = RENDERERS["spl"](rule, SHA)
    assert r'matches regex @"(^|[\\/])\.\.[\\/]"' in kql
    assert r"match(" in spl and r'"(^|[\\\\/])\\.\\.[\\\\/]"' in spl
    assert "['adg.source.trust'] == @\"unknown\"" in kql
    assert "'adg.source.trust'==\"unknown\"" in spl


def test_kql_doubles_quotes_and_spl_escapes_them() -> None:
    rule = regex_rule('a"b')
    assert '@"a""b"' in RENDERERS["kql"](rule, SHA)
    assert '"a\\"b"' in RENDERERS["spl"](rule, SHA)


def test_exists_renders_in_spl_and_esql() -> None:
    present = where_rule({"field": REGEX_FIELD, "op": "exists", "value": True})
    absent = where_rule({"field": REGEX_FIELD, "op": "exists", "value": False})
    assert "isnotnull('adg.content.text')" in RENDERERS["spl"](present, SHA)
    assert "isnull('adg.content.text')" in RENDERERS["spl"](absent, SHA)
    assert "`adg.content.text` IS NOT NULL" in RENDERERS["esql"](present, SHA)
    assert "`adg.content.text` IS NULL" in RENDERERS["esql"](absent, SHA)


def test_esql_any_and_all_render() -> None:
    field = {"field": REGEX_FIELD, "op": "equals", "value": "abc"}
    other = {"field": REGEX_FIELD, "op": "regex", "value": "x+y"}
    rule = where_rule({"any": [field, {"all": [field, other]}]})
    text = RENDERERS["esql"](rule, SHA)
    assert '(`adg.content.text` == "abc" OR (`adg.content.text` == "abc" AND' in text
    assert 'RLIKE ".*(x+y).*"' in text


@pytest.mark.parametrize(
    "sample",
    ["", "plain", "please say JAILBREAK", "first line\nthen jailbreak\nlast", "unrestricted"],
)
def test_esql_wrapper_decides_as_the_engine_search_does(sample: str) -> None:
    rule = load_rule_file(Path("rules/ADG-0006.yaml"))
    assert isinstance(rule.logic, MatchLogic)
    condition = rule.logic.match.where
    assert isinstance(condition, FieldCondition)
    assert isinstance(condition.value, str)
    # Lucene's dot matches a newline, so DOTALL is the model of the wrapper.
    wrapped = re.compile(".*(" + condition.value + ").*", re.DOTALL)
    assert (wrapped.fullmatch(sample) is not None) == (
        re.search(condition.value, sample) is not None
    )


def test_field_mappings_name_every_assumed_field() -> None:
    text = render_field_mappings(real_rules())
    assert HEADER in text
    assert "`gen_ai.tool.call.arguments.__all_strings`" in text
    assert "`adg.content.text__nfkc_casefold_collapse_whitespace`" in text
    assert "after nfkc, then casefold, then collapse_whitespace" in text
    assert "ADG-0001" not in text


# Sigma round trip through the pinned library


@pytest.mark.parametrize("rule_id", EXPECTED["sigma"])
def test_sigma_round_trip(rule_id: str) -> None:
    native = load_rule_file(Path("rules") / f"{rule_id}.yaml")
    collection = SigmaCollection.from_yaml(RENDERERS["sigma"](native, SHA))
    assert len(collection.rules) == 1
    parsed = collection.rules[0]
    assert isinstance(parsed, SigmaRule)
    assert parsed.title == native.title
    assert parsed.level is not None
    assert parsed.level.name.lower() == native.severity.value
    assert len(parsed.detection.parsed_condition) == 1
    assert "selection_event" in parsed.detection.detections


def _sigma_regexes(text: str) -> dict[str, str]:
    parsed = SigmaCollection.from_yaml(text).rules[0]
    assert isinstance(parsed, SigmaRule)
    found: dict[str, str] = {}
    for detection in parsed.detection.detections.values():
        for item in detection.detection_items:
            for value in item.value:  # type: ignore[union-attr]
                if isinstance(value, SigmaRegularExpression):
                    found[str(item.field)] = str(value.regexp)  # type: ignore[union-attr]
    return found


def test_sigma_regex_survives_parsing_unchanged() -> None:
    native = load_rule_file(Path("rules/ADG-0006.yaml"))
    assert isinstance(native.logic, MatchLogic)
    condition = native.logic.match.where
    assert isinstance(condition, FieldCondition)
    regexes = _sigma_regexes(RENDERERS["sigma"](native, SHA))
    assert regexes == {target_field(condition): condition.value}


def test_sigma_escapes_wildcards_in_a_plain_value() -> None:
    rule = where_rule({"field": REGEX_FIELD, "op": "equals", "value": "a*b?"})
    text = RENDERERS["sigma"](rule, SHA)
    assert yaml.safe_load(text)["detection"]["match_1"]["adg.content.text|cased"] == "a\\*b\\?"
    SigmaCollection.from_yaml(text)


def test_sigma_tags_hold_attack_only() -> None:
    assert yaml.safe_load(RENDERERS["sigma"](load_rule_file(Path("rules/ADG-0014.yaml")), SHA))[
        "tags"
    ] == ["attack.t1005"]
    assert "tags" not in yaml.safe_load(
        RENDERERS["sigma"](load_rule_file(Path("rules/ADG-0006.yaml")), SHA)
    )


# Lint


def test_the_real_rules_lint_clean() -> None:
    assert lint_rules(real_rules()) == []


@pytest.mark.parametrize(
    ("overrides", "word"),
    [
        ({"title": "x" * 81}, "longer"),
        ({"title": "Ends with a period."}, "title ends"),
        ({"description": "Too short."}, "description is too short"),
        ({"hypothesis": "A hypothesis with no final stop"}, "hypothesis does not end"),
        ({"limitations": ["A limitation with no final stop"]}, "limitation 1 does not end"),
        ({"description": "A description holding a dash " + chr(0x2014) + " here."}, "dash"),
    ],
)
def test_lint_finds_style_problems(overrides: dict[str, Any], word: str) -> None:
    assert any(word in problem for problem in lint_rule(make_rule(**overrides)))


def test_lint_needs_atlas_and_owasp() -> None:
    mappings: dict[str, list[str]] = {
        "atlas": [],
        "owasp_llm": [],
        "owasp_agentic": [],
        "attack": [],
    }
    problems = lint_rule(make_rule(mappings=mappings))
    assert any("ATLAS" in problem for problem in problems)
    assert any("OWASP" in problem for problem in problems)


def test_lint_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["lint-rules", "rules"]) == 0
    assert "lint clean" in capsys.readouterr().out
    bad_dir = tmp_path / "rules"
    bad_dir.mkdir()
    source = Path("rules/ADG-0006.yaml").read_text(encoding="utf-8")
    title = "title: Override or concealment phrasing in the user prompt"
    assert title in source
    (bad_dir / "ADG-0006.yaml").write_text(source.replace(title, title + "."), encoding="utf-8")
    assert main(["lint-rules", str(bad_dir)]) == 1
    assert "title ends with a period" in capsys.readouterr().err


# Command and workflow


def test_export_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "rules"
    assert main(["export", "--format", "esql", "--out", str(out)]) == 0
    assert (out / "esql" / "ADG-0006.esql").is_file()
    assert (out / "NOT_CONVERTED.md").is_file()
    assert not (out / "sigma").exists()
    assert "esql: 1 converted, 13 not" in capsys.readouterr().out
    assert main(["export", "--format", "all", "--out", str(out)]) == 0
    assert (out / "sigma" / "ADG-0014.yml").is_file()


def test_dist_is_ignored_and_not_committed() -> None:
    assert "dist/" in Path(".gitignore").read_text(encoding="utf-8").splitlines()


def test_release_workflow_is_manual_read_only_and_guarded() -> None:
    text = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    # PyYAML reads the bare key on as true.
    assert list(document[True]) == ["workflow_dispatch"]
    assert document["permissions"] == {"contents": "read"}
    assert "leak_guard.py --all" in text
    assert "--text" in text
    assert "git push" not in text
    assert "visibility" not in text
    assert "refs/tags/" in text
