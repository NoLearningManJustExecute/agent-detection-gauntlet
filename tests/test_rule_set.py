"""The shipped rule set against the Phase 2 gate. Reads dev traces and dev labels only."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from agent_detection_gauntlet.cli import main
from agent_detection_gauntlet.engine.executor import rule_hits
from agent_detection_gauntlet.engine.primitives import TraceContext
from agent_detection_gauntlet.io.labels import load_labels
from agent_detection_gauntlet.io.traces import load_traces
from agent_detection_gauntlet.rules.docgen import render
from agent_detection_gauntlet.rules.loader import load_rule_file, rule_files
from agent_detection_gauntlet.rules.model import Rule
from agent_detection_gauntlet.schema.labels import LabelRecord, Split, Verdict
from agent_detection_gauntlet.schema.trace import Trace
from tests.conftest import (
    DEV_TRACES,
    REPO_ROOT,
    RULE_FIXTURES,
    RULES_DIR,
    make_event,
    make_trace,
)

CORPUS_LABELS = REPO_ROOT / "datasets" / "corpus" / "labels.jsonl"
INEFFECTIVE = {"AC03", "AC09", "AC10"}


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    return [load_rule_file(path) for path in rule_files(RULES_DIR)]


@pytest.fixture(scope="module")
def dev_labels() -> dict[str, LabelRecord]:
    labels = load_labels([CORPUS_LABELS])
    return {key: label for key, label in labels.items() if label.split is Split.DEV}


@pytest.fixture(scope="module")
def dev_traces() -> dict[str, Trace]:
    return {trace.trace_id: trace for trace in load_traces([DEV_TRACES]).traces}


def _fixture_args() -> list[str]:
    return ["--fixtures", *(str(path) for path in RULE_FIXTURES)]


def test_the_shipped_rules_pass_validation() -> None:
    assert main(["validate-rules", str(RULES_DIR), *_fixture_args()]) == 0


def test_rule_count_and_tier_balance(rules: list[Rule]) -> None:
    assert 12 <= len(rules) <= 15
    tiers = Counter(rule.tier.value for rule in rules)
    assert set(tiers) == {"content", "sequence", "behavior"}
    assert all(4 <= count <= 5 for count in tiers.values())


def test_every_rule_states_a_hypothesis_and_two_limitations(rules: list[Rule]) -> None:
    for rule in rules:
        assert rule.hypothesis
        assert len(rule.limitations) >= 2, rule.id


def test_fixtures_are_dev_or_synthetic_never_heldout(
    rules: list[Rule], dev_labels: dict[str, LabelRecord]
) -> None:
    for rule in rules:
        for trace_id in (*rule.fixtures.tp, *rule.fixtures.fp):
            assert trace_id in dev_labels or trace_id.startswith("syn-"), (rule.id, trace_id)


def test_fixtures_are_true_to_their_labels(
    rules: list[Rule], dev_labels: dict[str, LabelRecord]
) -> None:
    for rule in rules:
        for trace_id in rule.fixtures.tp:
            if trace_id in dev_labels:
                assert dev_labels[trace_id].attack_succeeded is True, (rule.id, trace_id)
                assert dev_labels[trace_id].attack_class not in INEFFECTIVE, (rule.id, trace_id)
        for trace_id in rule.fixtures.fp:
            if trace_id in dev_labels:
                label = dev_labels[trace_id]
                assert label.label is Verdict.BENIGN or label.attack_class in INEFFECTIVE


def test_every_rule_names_a_real_tp_where_the_dev_split_has_one(
    rules: list[Rule], dev_labels: dict[str, LabelRecord], dev_traces: dict[str, Trace]
) -> None:
    """Only a rule that fires on no successful dev attack may lean on a synthetic tp alone."""
    for rule in rules:
        real = [trace_id for trace_id in rule.fixtures.tp if trace_id in dev_labels]
        if real:
            continue
        fired = [
            trace_id
            for trace_id, trace in dev_traces.items()
            if dev_labels[trace_id].attack_succeeded is True
            and rule_hits(rule, TraceContext(trace))
        ]
        assert fired == [], rule.id


def test_every_rule_has_a_hard_negative_fp(
    rules: list[Rule], dev_traces: dict[str, Trace], dev_labels: dict[str, LabelRecord]
) -> None:
    """A benign fp fixture that reads a secret, sends, chains, or takes in untrusted content."""

    def is_hard(trace: Trace) -> bool:
        calls = [e for e in trace.events if e.event_type.value == "tool.call"]
        names = [str(e.attributes.get("gen_ai.tool.name", "")) for e in calls]
        reads_secret = any(
            e.event_type.value == "tool.result"
            and "secret" in (e.attributes.get("adg.data.labels") or [])  # type: ignore[operator]
            for e in trace.events
        )
        untrusted = any(e.attributes.get("adg.source.trust") == "untrusted" for e in trace.events)
        sends = any(name.startswith("send") for name in names)
        return reads_secret or untrusted or sends or len(calls) >= 3

    for rule in rules:
        assert any(
            trace_id in dev_traces
            and dev_labels[trace_id].label is Verdict.BENIGN
            and is_hard(dev_traces[trace_id])
            for trace_id in rule.fixtures.fp
        ), rule.id


def test_the_override_phrase_list_reaches_its_last_alternative(rules: list[Rule]) -> None:
    rule = next(item for item in rules if item.id == "ADG-0002")
    trace = make_trace(
        [make_event("s1", "tool.result", {"adg.content.text": "Please ALWAYS  Use this path."})]
    )
    assert rule_hits(rule, TraceContext(trace))


def test_no_rule_keys_on_the_lab_attack_domain() -> None:
    for path in rule_files(RULES_DIR):
        text = path.read_text(encoding="utf-8").casefold()
        assert "exfil" not in text.replace("exfiltration", ""), path.name
        assert ".example" not in text, path.name


def test_baselines_are_fitted_and_current() -> None:
    assert main(["fit-baselines", "--check"]) == 0


def test_the_detection_catalog_is_current() -> None:
    assert render(RULES_DIR) == (REPO_ROOT / "docs" / "detections.md").read_text(encoding="utf-8")


def test_the_heldout_log_holds_only_registered_scoring_runs() -> None:
    log: Path = REPO_ROOT / "docs" / "heldout-log.md"
    rows = [
        [cell.strip() for cell in line.split("|")[1:-1]]
        for line in log.read_text(encoding="utf-8").splitlines()
        if line.startswith("| 20")
    ]
    assert rows
    assert rows[0][2] == "validation score"
    assert {row[2] for row in rows} <= {
        "validation score",
        "validation score --check",
        "evasion mutate",
        "evasion score",
        "evasion score --check",
    }
