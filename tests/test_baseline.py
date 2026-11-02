"""Rule format 1.1: value paths, first_occurrence, baseline logic, fitting and the doc."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from agent_detection_gauntlet.catalog import load_catalog
from agent_detection_gauntlet.cli import main
from agent_detection_gauntlet.engine.conditions import evaluate_field
from agent_detection_gauntlet.engine.executor import rule_hits
from agent_detection_gauntlet.engine.fields import MISSING, resolve
from agent_detection_gauntlet.engine.primitives import TraceContext, run_sequence
from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.fit import fit_baselines, nearest_rank
from agent_detection_gauntlet.paths import set_repo_root
from agent_detection_gauntlet.rules.docgen import render
from agent_detection_gauntlet.rules.model import FieldCondition, Rule, SequenceSpec
from agent_detection_gauntlet.rules.validator import validate_rules
from tests.conftest import event_dict, make_event, make_rule, make_trace, rule_data, write_lines

ARGS = "attributes.gen_ai.tool.call.arguments"


def call(span: str, tool: str, seconds: float = 0, **arguments: Any) -> dict[str, Any]:
    attributes = {"gen_ai.tool.name": tool, "gen_ai.tool.call.arguments": arguments}
    return event_dict(span, "tool.call", attributes, seconds=seconds)


def trace_of(*names: str, trace_id: str = "t-1") -> list[dict[str, Any]]:
    return [
        {**call(f"s{i}", name, seconds=i), "trace_id": trace_id} for i, name in enumerate(names, 1)
    ]


def as_trace(records: list[dict[str, Any]]) -> Any:
    from agent_detection_gauntlet.schema.trace import TraceEvent

    events = [TraceEvent.model_validate_json(json.dumps(record)) for record in records]
    return make_trace(events, records[0]["trace_id"])


def baseline_rule(fitted: dict[str, Any] | None = None, **spec: Any) -> dict[str, Any]:
    data = rule_data(
        format_version="1.1",
        tier="behavior",
        telemetry=["tool.call"],
        logic={"baseline": {"match": {"event_types": ["tool.call"]}, **spec}},
    )
    if fitted is not None:
        data["fitted"] = fitted
    return data


CHAIN: dict[str, Any] = {"statistic": "chain_length", "percentile": 95}
RARE: dict[str, Any] = {
    "statistic": "rare_transition",
    "max_rate": 0.1,
    "key": "attributes.gen_ai.tool.name",
}
FIT = {"command": "gauntlet fit-baselines", "population": "dev benign", "traces": 2}


# Value paths


def test_value_path_reads_a_key_inside_arguments() -> None:
    event = make_event(**_call_kwargs(to="alex@example.test", nested={"deep": ["a", "b"]}))
    assert resolve(event, f"{ARGS}#to") == "alex@example.test"
    assert resolve(event, f"{ARGS}#nested.deep.1") == "b"


@pytest.mark.parametrize("path", ["absent", "to.below", "nested.deep.9", "nested.deep.x"])
def test_value_path_that_reaches_nothing_is_missing(path: str) -> None:
    event = make_event(**_call_kwargs(to="alex@example.test", nested={"deep": ["a"]}))
    assert resolve(event, f"{ARGS}#{path}") is MISSING


def test_star_joins_every_string_in_sorted_key_order() -> None:
    event = make_event(**_call_kwargs(b="two", a=["one", {"z": "three"}], n=7))
    assert resolve(event, f"{ARGS}#*") == "one\nthree\ntwo"


def test_star_with_no_strings_is_missing_and_a_string_value_is_itself() -> None:
    assert resolve(make_event(**_call_kwargs(n=7)), f"{ARGS}#*") is MISSING
    event = make_event("s1", "tool.result", {"gen_ai.tool.call.result": "plain"})
    assert resolve(event, "attributes.gen_ai.tool.call.result#*") == "plain"


def test_a_condition_can_read_through_a_path() -> None:
    condition = FieldCondition.model_validate_json(
        json.dumps({"field": f"{ARGS}#*", "op": "regex", "value": "canary-[0-9]+"})
    )
    assert evaluate_field(condition, make_event(**_call_kwargs(body="x canary-42 y")))
    assert not evaluate_field(condition, make_event(**_call_kwargs(body="nothing")))


@pytest.mark.parametrize("bad", ["attributes.x#", "attributes.x#a..b", "attributes.x#a b", "x#y"])
def test_malformed_paths_are_rejected(bad: str) -> None:
    with pytest.raises(ValidationError, match="field must be one of"):
        FieldCondition.model_validate_json(
            json.dumps({"field": bad, "op": "exists", "value": True})
        )


def _call_kwargs(**arguments: Any) -> dict[str, Any]:
    return {
        "span_id": "s1",
        "event_type": "tool.call",
        "attributes": {"gen_ai.tool.call.arguments": arguments},
    }


# Format version


@pytest.mark.parametrize(
    "logic",
    [
        {"match": {"event_types": ["tool.call"], "where": {
            "field": f"{ARGS}#to", "op": "exists", "value": True}}},
        {"threshold": {"match": {"event_types": ["tool.call"]}, "distinct": f"{ARGS}#to",
                       "op": "gte", "value": 1}},
        {"sequence": {"steps": [
            {"name": "a", "match": {"event_types": ["tool.call"]}, "bind": {"v": f"{ARGS}#to"}},
            {"name": "b", "match": {"event_types": ["tool.call"]}},
        ]}},
        {"sequence": {"steps": [
            {"name": "a", "match": {"event_types": ["tool.call"]}},
            {"name": "b", "match": {"event_types": ["tool.call"]},
             "first_occurrence": "attributes.gen_ai.tool.name"},
        ]}},
        {"baseline": {"match": {"event_types": ["tool.call"]}, **CHAIN}},
    ],
)  # fmt: skip
def test_new_features_need_format_1_1(logic: dict[str, Any]) -> None:
    fields = {"telemetry": ["tool.call"], "logic": logic}
    with pytest.raises(ValidationError, match=r"need format_version 1\.1"):
        make_rule(**fields)
    assert make_rule(format_version="1.1", **fields).format_version == "1.1"


def test_rules_without_a_format_version_still_load() -> None:
    assert make_rule().format_version == "1.0"


def test_a_hash_in_a_compared_value_is_not_a_path() -> None:
    where = {"field": "attributes.a", "op": "equals", "value": "x#y"}
    make_rule(
        telemetry=["tool.call"], logic={"match": {"event_types": ["tool.call"], "where": where}}
    )


# first_occurrence


def _first_use_spec() -> SequenceSpec:
    return SequenceSpec.model_validate_json(
        json.dumps(
            {
                "steps": [
                    {
                        "name": "src",
                        "match": {
                            "event_types": ["retrieval"],
                        },
                    },
                    {
                        "name": "use",
                        "match": {"event_types": ["tool.call"]},
                        "first_occurrence": "attributes.gen_ai.tool.name",
                    },
                ]
            }
        )
    )


def test_first_occurrence_fires_on_the_first_use_after_the_source() -> None:
    records = [
        event_dict("s1", "retrieval", {"adg.source.trust": "untrusted"}),
        call("s2", "send", seconds=1),
        call("s3", "send", seconds=2),
        call("s4", "post", seconds=3),
    ]
    assert run_sequence(_first_use_spec(), TraceContext(as_trace(records))) == [(0, 1), (0, 3)]


def test_first_occurrence_stays_silent_when_the_tool_was_used_before_the_source() -> None:
    records = [
        call("s1", "send"),
        event_dict("s2", "retrieval", {"adg.source.trust": "untrusted"}, seconds=1),
        call("s3", "send", seconds=2),
    ]
    assert run_sequence(_first_use_spec(), TraceContext(as_trace(records))) == []


def test_first_occurrence_skips_events_without_the_field() -> None:
    records = [
        event_dict("s1", "retrieval", {"adg.source.trust": "untrusted"}),
        event_dict("s2", "tool.call", {}, seconds=1),
        call("s3", "send", seconds=2),
    ]
    assert run_sequence(_first_use_spec(), TraceContext(as_trace(records))) == [(0, 2)]


# Baseline logic


@pytest.mark.parametrize(
    "spec",
    [
        {"statistic": "chain_length"},
        {"statistic": "chain_length", "percentile": 95, "max_rate": 0.1},
        {"statistic": "chain_length", "percentile": 95, "key": "attributes.a"},
        {"statistic": "chain_length", "percentile": 0},
        {"statistic": "rare_transition", "max_rate": 0.1},
        {"statistic": "rare_transition", "key": "attributes.a"},
        {"statistic": "rare_transition", "key": "attributes.a", "max_rate": 0.1, "percentile": 9},
        {"statistic": "rare_transition", "key": "attributes.a", "max_rate": 0.0},
    ],
)
def test_baseline_parameters_are_checked(spec: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate_json(json.dumps(baseline_rule(**spec)))


@pytest.mark.parametrize(
    "fitted",
    [
        dict(FIT),
        {**FIT, "threshold": 1, "transitions": {"a -> b": 1}},
        {**FIT, "transitions": {"a -> b": 1}},
        {**FIT, "threshold": 1, "population": "everything"},
        {**FIT, "threshold": 1, "traces": 0},
    ],
)
def test_fitted_shape_is_checked(fitted: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Rule.model_validate_json(json.dumps(baseline_rule(fitted, **CHAIN)))


def test_fitted_belongs_to_baseline_logic_only() -> None:
    with pytest.raises(ValidationError, match="fitted belongs to baseline logic only"):
        make_rule(fitted={**FIT, "threshold": 1})


def _baseline(fitted: dict[str, Any], **spec: Any) -> Rule:
    return Rule.model_validate_json(json.dumps(baseline_rule(fitted, **spec)))


def test_chain_length_fires_above_the_threshold_and_cites_every_call() -> None:
    rule = _baseline({**FIT, "threshold": 2}, **CHAIN)
    assert rule_hits(rule, TraceContext(as_trace(trace_of("a", "b")))) == []
    assert rule_hits(rule, TraceContext(as_trace(trace_of("a", "b", "c")))) == [(0, 1, 2)]


def test_chain_length_threshold_zero_stays_silent_on_a_trace_with_no_calls() -> None:
    rule = _baseline({**FIT, "threshold": 0}, **CHAIN)
    empty = as_trace([event_dict("s1", "user.prompt", {})])
    assert rule_hits(rule, TraceContext(empty)) == []


def test_rare_transition_fires_per_rare_pair_and_cites_both_calls() -> None:
    counts = {"<start> -> a": 45, "a -> b": 45, "b -> c": 5, "z -> z": 5}
    rule = _baseline({**FIT, "transitions": counts}, **RARE)
    # 100 transitions at max_rate 0.1: b -> c (5) is rare, a -> b is not, and b -> a is unseen.
    hits = rule_hits(rule, TraceContext(as_trace(trace_of("a", "b", "c", "b", "a"))))
    assert hits == [(1, 2), (2, 3), (3, 4)]


def test_rare_transition_covers_the_first_call_with_one_span() -> None:
    rule = _baseline({**FIT, "transitions": {"<start> -> a": 9}}, **RARE)
    assert rule_hits(rule, TraceContext(as_trace(trace_of("new")))) == [(0,)]


def test_rare_transition_skips_events_without_the_key() -> None:
    rule = _baseline({**FIT, "transitions": {"<start> -> a": 9, "a -> b": 9}}, **RARE)
    records = [*trace_of("a"), event_dict("s9", "tool.call", {}, seconds=2), call("s8", "b", 3)]
    assert rule_hits(rule, TraceContext(as_trace(records))) == []


def test_an_unfitted_baseline_rule_cannot_run() -> None:
    rule = Rule.model_validate_json(json.dumps(baseline_rule(**CHAIN)))
    with pytest.raises(ValueError, match="no fitted baseline"):
        rule_hits(rule, TraceContext(as_trace(trace_of("a"))))


# Fitting


@pytest.mark.parametrize(
    ("values", "percentile", "expected"),
    [
        ([1], 95, 1),
        ([1, 2, 3, 4], 50, 2),
        ([1, 2, 3, 4], 51, 3),
        ([4, 3, 2, 1], 100, 4),
        ([1, 2, 3, 4], 1, 1),
        (list(range(1, 101)), 95, 95),
    ],
)
def test_nearest_rank(values: list[int], percentile: int, expected: int) -> None:
    assert nearest_rank(values, percentile) == expected


def _label(trace_id: str, *, split: str = "dev", label: str = "benign") -> dict[str, Any]:
    malicious = label == "malicious"
    return {
        "attack_class": "x" if malicious else None,
        "attack_succeeded": True if malicious else None,
        "guardrails": "off",
        "label": label,
        "mutation": None,
        "schema_version": "0.1",
        "source": "synthetic",
        "split": split,
        "trace_id": trace_id,
    }


@pytest.fixture
def fit_repo(tmp_path: Path) -> Path:
    (tmp_path / ".git").mkdir()
    set_repo_root(tmp_path)
    rules = tmp_path / "rules"
    rules.mkdir()
    for rule_id, spec in (("ADG-9101", CHAIN), ("ADG-9102", RARE)):
        data = baseline_rule(**spec)
        data["id"] = rule_id
        (rules / f"{rule_id}.yaml").write_text(
            "# kept comment\n" + yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
        )
    data = rule_data(id="ADG-9103")
    (rules / "ADG-9103.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    write_lines(tmp_path / "t" / "a.jsonl", trace_of("x", "y", trace_id="a"))
    write_lines(tmp_path / "t" / "b.jsonl", trace_of("x", trace_id="b"))
    write_lines(tmp_path / "t" / "m.jsonl", trace_of("x", "y", "z", "w", "v", trace_id="m"))
    write_lines(
        tmp_path / "labels.jsonl",
        [_label("a"), _label("b"), _label("m", label="malicious"), _label("h", split="heldout")],
    )
    return tmp_path


def test_fit_counts_benign_dev_traces_only_and_keeps_the_rest_of_the_file(fit_repo: Path) -> None:
    rules = fit_repo / "rules"
    untouched = (rules / "ADG-9103.yaml").read_bytes()
    outcome = fit_baselines(rules, [fit_repo / "t"], fit_repo / "labels.jsonl")
    assert outcome.fitted == 2
    assert len(outcome.written) == 2
    chain = yaml.safe_load((rules / "ADG-9101.yaml").read_text(encoding="utf-8"))
    assert chain["fitted"] == {
        "command": "gauntlet fit-baselines --rules rules --traces t --labels labels.jsonl",
        "population": "dev benign",
        "threshold": 2,
        "traces": 2,
    }
    rare = yaml.safe_load((rules / "ADG-9102.yaml").read_text(encoding="utf-8"))
    assert rare["fitted"]["transitions"] == {"<start> -> x": 2, "x -> y": 1}
    assert (rules / "ADG-9101.yaml").read_text(encoding="utf-8").startswith("# kept comment\n")
    assert (rules / "ADG-9103.yaml").read_bytes() == untouched


def test_fit_is_deterministic_and_idempotent(fit_repo: Path) -> None:
    rules, labels = fit_repo / "rules", fit_repo / "labels.jsonl"
    fit_baselines(rules, [fit_repo / "t"], labels)
    first = (rules / "ADG-9102.yaml").read_bytes()
    assert fit_baselines(rules, [fit_repo / "t"], labels).written == []
    assert (rules / "ADG-9102.yaml").read_bytes() == first


def test_fit_check_reports_stale_rules_and_writes_nothing(fit_repo: Path) -> None:
    rules, labels = fit_repo / "rules", fit_repo / "labels.jsonl"
    before = (rules / "ADG-9101.yaml").read_bytes()
    outcome = fit_baselines(rules, [fit_repo / "t"], labels, check=True)
    assert len(outcome.stale) == 2
    assert outcome.written == []
    assert (rules / "ADG-9101.yaml").read_bytes() == before


def test_fit_refuses_traces_that_are_not_dev(fit_repo: Path) -> None:
    write_lines(fit_repo / "t" / "h.jsonl", trace_of("x", trace_id="h"))
    with pytest.raises(GauntletError, match="dev traces only; 1 supplied are not"):
        fit_baselines(fit_repo / "rules", [fit_repo / "t"], fit_repo / "labels.jsonl")


def test_fit_refuses_unlabeled_traces(fit_repo: Path) -> None:
    write_lines(fit_repo / "t" / "u.jsonl", trace_of("x", trace_id="u"))
    with pytest.raises(GauntletError, match="dev traces only"):
        fit_baselines(fit_repo / "rules", [fit_repo / "t"], fit_repo / "labels.jsonl")


def test_fit_refuses_heldout_paths_whatever_the_environment(
    fit_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GAUNTLET_SCORING_HELDOUT", "1")
    held = write_lines(
        fit_repo / "datasets" / "corpus" / "heldout" / "x.jsonl", trace_of("x", trace_id="a")
    )
    with pytest.raises(GauntletError, match="baseline fitting must not read held-out data"):
        fit_baselines(fit_repo / "rules", [held], fit_repo / "labels.jsonl")


def test_fit_needs_a_benign_population(fit_repo: Path) -> None:
    write_lines(fit_repo / "only.jsonl", [_label("m", label="malicious")])
    only = write_lines(fit_repo / "m" / "m.jsonl", trace_of("x", trace_id="m"))
    with pytest.raises(GauntletError, match="no dev benign traces"):
        fit_baselines(fit_repo / "rules", [only], fit_repo / "only.jsonl")


def test_fit_needs_inputs_inside_the_repository(fit_repo: Path, tmp_path_factory: Any) -> None:
    outside = tmp_path_factory.mktemp("outside") / "labels.jsonl"
    with pytest.raises(GauntletError, match="must be inside the repository"):
        fit_baselines(fit_repo / "rules", [fit_repo / "t"], outside)


def test_cli_fit_baselines_then_check(fit_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    args = [
        "--root",
        str(fit_repo),
        "fit-baselines",
        "--rules",
        str(fit_repo / "rules"),
        "--traces",
        str(fit_repo / "t"),
        "--labels",
        str(fit_repo / "labels.jsonl"),
    ]
    assert main([*args, "--check"]) == 1
    assert "rules/ADG-9101.yaml is out of date" in capsys.readouterr().err
    assert main(args) == 0
    assert "2 baseline rule(s), 2 rewritten" in capsys.readouterr().out
    assert main([*args, "--check"]) == 0


# Validator and the catalog doc


def test_validator_reports_an_unfitted_baseline_rule(fit_repo: Path) -> None:
    report = validate_rules(fit_repo / "rules", [fit_repo / "t"], load_catalog())
    assert any("not fitted" in issue.message for issue in report.errors)
    assert {loaded.rule.id for loaded in report.rules} == {"ADG-9103"}


def test_rules_doc_writes_then_checks(fit_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fit_baselines(fit_repo / "rules", [fit_repo / "t"], fit_repo / "labels.jsonl")
    out = fit_repo / "docs" / "detections.md"
    args = ["--root", str(fit_repo), "rules-doc", "--rules", str(fit_repo / "rules")]
    args += ["--out", str(out)]
    assert main([*args, "--check"]) == 1
    assert main(args) == 0
    assert main([*args, "--check"]) == 0
    capsys.readouterr()
    text = render(fit_repo / "rules")
    assert out.read_text(encoding="utf-8") == text
    assert "percentile 95 of matching events per trace = 2, on 2 dev benign traces" in text
    assert "2 transitions, 3 observed; rare below rate 0.1" in text
    assert "`gauntlet fit-baselines --rules rules --traces t --labels labels.jsonl`" in text
    assert "ATT&CK none" in text


def test_rules_doc_describes_threshold_and_match_logic(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    threshold = rule_data(
        id="ADG-9201",
        tier="behavior",
        telemetry=["tool.call"],
        logic={"threshold": {"match": {"event_types": ["tool.call"]}, "op": "gte", "value": 1}},
    )
    match = rule_data(
        id="ADG-9202",
        tier="content",
        telemetry=["tool.call"],
        logic={"match": {"event_types": ["tool.call"]}},
    )
    for data in (threshold, match):
        path = rules / f"{data['id']}.yaml"
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    text = render(rules)
    assert "**Logic:** threshold" in text
    assert "**Logic:** match" in text
