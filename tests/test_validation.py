"""Phase 3 scoring on a small hand-made corpus. No test reads the real held-out split.

The stand-in corpus has hand-countable results, so the expected numbers below are worked out by
hand from the table in `_corpus`, not by running the code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_detection_gauntlet.cli import main
from agent_detection_gauntlet.errors import GauntletError, MetricsInputError
from agent_detection_gauntlet.firewall import HELDOUT_ENV
from agent_detection_gauntlet.io.jsonl import write_text
from agent_detection_gauntlet.metrics.compute import sha256_file
from agent_detection_gauntlet.metrics.report import Rate
from agent_detection_gauntlet.paths import set_repo_root
from agent_detection_gauntlet.rules.loader import LoadedRule, load_rule_file
from agent_detection_gauntlet.schema.common import Tier
from agent_detection_gauntlet.schema.labels import Split
from agent_detection_gauntlet.validation.model import BaselineResults, Preregistration
from agent_detection_gauntlet.validation.prereg import (
    build_preregistration,
    dump_preregistration,
    read_preregistration,
    read_results,
    render_preregistration,
    rule_hash_drift,
    verify,
)
from agent_detection_gauntlet.validation.report import render_results
from agent_detection_gauntlet.validation.score import group_interval, score_split
from tests.conftest import event_dict, rule_data, write_lines, write_rule


def _match_rule(rule_id: str, tier: str, needle: str) -> dict[str, Any]:
    """Fires on a tool call whose name equals ``needle``. tp and fp are stand-in fixtures."""
    return rule_data(
        id=rule_id,
        tier=tier,
        title=f"Stand-in {rule_id}",
        telemetry=["tool.call"],
        logic={
            "match": {
                "event_types": ["tool.call"],
                "where": {"field": "attributes.gen_ai.tool.name", "op": "equals", "value": needle},
            }
        },
        fixtures={"tp": [f"fx-{needle}"], "fp": ["fx-none"]},
    )


def _trace(trace_id: str, tools: list[str]) -> list[dict[str, Any]]:
    events = [event_dict("s0", "user.prompt", {}, trace_id=trace_id)]
    for index, tool in enumerate(tools, start=1):
        events.append(
            event_dict(
                f"s{index}",
                "tool.call",
                {"gen_ai.tool.name": tool},
                trace_id=trace_id,
                seconds=index,
            )
        )
    return events


def _label(
    trace_id: str,
    group: str,
    *,
    split: str = "heldout",
    attack_class: str | None = "AC01",
    succeeded: bool | None = True,
    guardrails: str = "off",
    scenario: str | None = None,
    derived_from: str | None = None,
) -> dict[str, Any]:
    benign = attack_class is None
    return {
        "schema_version": "0.3",
        "trace_id": trace_id,
        "label": "benign" if benign else "malicious",
        "attack_class": attack_class,
        "attack_succeeded": None if benign else succeeded,
        "mutation": None,
        "guardrails": guardrails,
        "split": split,
        "source": "agent-risk-framework",
        "scenario_id": None if benign else (scenario or group),
        "task_id": group if benign else None,
        "condition": "baseline" if guardrails == "off" else "combined",
        "source_run_id": f"run:{trace_id}",
        "variant_group": group,
        "derived_from": derived_from,
    }


# Tools: c fires content, s fires sequence, b fires behavior. Sensitive K only changes "s" -> "x".
#
# trace   group   class  outcome    arm  tools
# m1      A1      AC01   succeeded  off  c
# m2      A1      AC01   succeeded  on   c s
# m3      A2      AC01   succeeded  off  s
# m4      A3      AC02   succeeded  off  b
# m5      A3-OBF  AC02   succeeded  off  (none)   scenario ends in -OBF
# f1      A4      AC02   failed     on   c
# f2      A4      AC02   failed     off  (none)
# b1      B1      -      benign     off  c
# b2      B1      -      benign     on   (none)
# b3      B2      -      benign     off  s b
# b4      B3      -      benign     off  (none)
CORPUS: list[tuple[str, list[str]]] = [
    ("m1", ["c"]),
    ("m2", ["c", "s"]),
    ("m3", ["s"]),
    ("m4", ["b"]),
    ("m5", ["n"]),
    ("f1", ["c"]),
    ("f2", ["n"]),
    ("b1", ["c"]),
    ("b2", ["n"]),
    ("b3", ["s", "b"]),
    ("b4", ["n"]),
]


def _write_split(corpus: Path, split: str, entries: list[tuple[str, list[str]]], k: int) -> None:
    events = []
    for trace_id, tools in entries:
        # At k=48 the sequence signal is lost on every trace, as a coarse provenance stand-in.
        events += _trace(trace_id, ["x" if tool == "s" and k == 48 else tool for tool in tools])
    write_lines(corpus / split / f"k{k}" / "traces.jsonl", events)


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / ".git").mkdir()
    monkeypatch.chdir(tmp_path)
    set_repo_root(tmp_path)
    corpus = tmp_path / "datasets" / "corpus"
    for k in (16, 24, 48):
        _write_split(corpus, "heldout", CORPUS, k)
        _write_split(corpus, "dev", [("d1", ["c"])], k)
    labels = [
        _label("m1", "A1", derived_from="P1"),
        _label("m2", "A1", guardrails="on", derived_from="P1"),
        _label("m3", "A2", derived_from="P2"),
        _label("m4", "A3", attack_class="AC02"),
        _label("m5", "A3", attack_class="AC02", scenario="A3-OBF"),
        _label("f1", "A4", attack_class="AC02", succeeded=False, guardrails="on"),
        _label("f2", "A4", attack_class="AC02", succeeded=False),
        _label("b1", "B1", attack_class=None),
        _label("b2", "B1", attack_class=None, guardrails="on"),
        _label("b3", "B2", attack_class=None),
        _label("b4", "B3", attack_class=None),
        # Dev side: P1 is the parent of A1 and sits across the split; P2 stays with its child.
        _label("d1", "P1", split="dev", attack_class="AC01"),
        _label("d2", "P2", split="heldout", attack_class="AC01", succeeded=False),
    ]
    write_lines(corpus / "labels.jsonl", labels)
    # d2 keeps P2 in the held-out split; it is a failed trace with no tool call.
    for k in (16, 24, 48):
        path = corpus / "heldout" / f"k{k}" / "traces.jsonl"
        with path.open("ab") as handle:
            for event in _trace("d2", ["n"]):
                handle.write((json.dumps(event) + "\n").encode())
    manifest = {
        "files": {},
        "ineffective_classes": ["AC03"],
        "below_floor_classes": ["AC02"],
    }
    write_text(corpus / "SPLIT_MANIFEST.json", json.dumps(manifest))
    rules = tmp_path / "rules"
    write_rule(rules, _match_rule("ADG-0101", "content", "c"))
    write_rule(rules, _match_rule("ADG-0102", "sequence", "s"))
    write_rule(rules, _match_rule("ADG-0103", "behavior", "b"))
    fixtures = tmp_path / "fx"
    for needle in ("c", "s", "b"):
        write_lines(fixtures / f"{needle}.jsonl", _trace(f"fx-{needle}", [needle]))
    write_lines(fixtures / "none.jsonl", _trace("fx-none", ["n"]))
    return tmp_path


def _loaded(project: Path) -> list[LoadedRule]:
    return [
        LoadedRule(path=path, rule=load_rule_file(path))
        for path in sorted((project / "rules").glob("*.yaml"))
    ]


def _plan(project: Path) -> Preregistration:
    return build_preregistration(_loaded(project), project / "datasets" / "corpus", "a" * 40)


def _register(project: Path) -> Preregistration:
    plan = _plan(project)
    write_text(project / "docs" / "preregistration.json", dump_preregistration(plan))
    write_text(project / "docs" / "preregistration.md", render_preregistration(plan))
    return plan


def _score(project: Path) -> BaselineResults:
    plan = _register(project)
    path = project / "docs" / "preregistration.json"
    corpus = project / "datasets" / "corpus"
    return score_split(plan, sha256_file(path), _loaded(project), corpus, Split.HELDOUT).results


def _value(rate: Rate) -> tuple[int, int]:
    return rate.numerator, rate.denominator


def _tier(results: BaselineResults, tier: Tier) -> Any:
    return next(item for item in results.pooled.per_tier if item.tier is tier)


def test_pooled_counts_match_the_table_by_hand(project: Path) -> None:
    results = _score(project)
    population = results.population
    assert (population.malicious_succeeded, population.benign, population.attack_failed) == (
        5,
        4,
        3,
    )
    assert population.malicious_succeeded_groups == 3
    assert population.benign_groups == 3
    assert population.attack_failed_groups == 2

    content = _tier(results, Tier.CONTENT)
    assert (content.confusion.tp, content.confusion.fn) == (2, 3)
    assert (content.confusion.fp, content.confusion.tn) == (1, 3)
    assert (content.attack_failed.count, content.attack_failed.detected) == (3, 1)
    assert _value(content.rates.recall) == (2, 5)
    assert _value(content.rates.fpr) == (1, 4)
    assert _value(content.rates.precision) == (2, 3)
    assert content.rates.recall.ci95 is not None
    assert content.rates.f1.ci95 is None

    sequence = _tier(results, Tier.SEQUENCE)
    assert _value(sequence.rates.recall) == (2, 5)
    assert _value(sequence.rates.fpr) == (1, 4)

    behavior = _tier(results, Tier.BEHAVIOR)
    assert _value(behavior.rates.recall) == (1, 5)
    assert _value(behavior.rates.fpr) == (1, 4)


def test_all_tiers_is_the_union_of_the_rules(project: Path) -> None:
    results = _score(project)
    combined = results.pooled.all_tiers
    assert _value(combined.rates.recall) == (4, 5)  # m1 m2 m3 m4
    assert _value(combined.rates.fpr) == (2, 4)  # b1 b3
    assert combined.attack_failed.detected == 1  # f1


def test_guardrails_sections_split_both_buckets(project: Path) -> None:
    results = _score(project)
    off, on = results.by_guardrails
    assert (off.guardrails.value, on.guardrails.value) == ("off", "on")
    assert (off.population.malicious_succeeded, on.population.malicious_succeeded) == (4, 1)
    assert (off.population.benign, on.population.benign) == (3, 1)
    assert _value(on.section.all_tiers.rates.recall) == (1, 1)
    assert _value(on.section.all_tiers.rates.fpr) == (0, 1)
    assert _value(off.section.all_tiers.rates.recall) == (3, 4)
    assert _value(off.section.all_tiers.rates.fpr) == (2, 3)


def test_per_class_has_sizes_and_flags(project: Path) -> None:
    results = _score(project)
    ac01, ac02 = results.per_class
    assert (ac01.attack_class, ac01.succeeded_traces, ac01.succeeded_groups) == ("AC01", 3, 2)
    assert (ac02.attack_class, ac02.succeeded_traces, ac02.succeeded_groups) == ("AC02", 2, 1)
    assert ac01.small_n
    assert not ac01.below_floor
    assert ac02.below_floor
    assert _value(ac01.table.all_tiers.recall) == (3, 3)
    assert _value(ac02.table.all_tiers.recall) == (1, 2)
    assert (ac02.table.all_tiers.attack_failed.count, ac02.attack_failed_traces) == (2, 2)


def test_benign_traces_do_not_enter_any_class_cell(project: Path) -> None:
    results = _score(project)
    assert all(
        item.table.all_tiers.recall.denominator <= item.succeeded_traces
        for item in results.per_class
    )


def test_attack_failed_counts_per_class_and_arm(project: Path) -> None:
    results = _score(project)
    assert results.attack_failed.total == 3
    rows = {row.attack_class: row for row in results.attack_failed.by_class}
    assert (rows["AC02"].guardrails_off, rows["AC02"].guardrails_on, rows["AC02"].groups) == (
        1,
        1,
        1,
    )
    assert (rows["AC01"].total, rows["AC01"].groups) == (1, 1)


def test_provenance_uses_each_export_and_only_the_sequence_tier(project: Path) -> None:
    results = _score(project)
    by_k = {run.k: run for run in results.provenance_sensitivity}
    assert sorted(by_k) == [16, 24, 48]
    assert all(run.tier.tier is Tier.SEQUENCE for run in by_k.values())
    assert [rule.rule_id for rule in by_k[24].per_rule] == ["ADG-0102"]
    assert _value(by_k[16].tier.rates.recall) == (2, 5)
    assert _value(by_k[24].tier.rates.recall) == _value(_tier(results, Tier.SEQUENCE).rates.recall)
    assert _value(by_k[48].tier.rates.recall) == (0, 5)
    assert _value(by_k[48].tier.rates.fpr) == (0, 4)


def test_set_asides_remove_only_what_they_name(project: Path) -> None:
    results = _score(project)
    items = {item.name: item for item in results.set_asides}
    # A1 has its parent P1 in dev. A2's parent P2 is held-out, so A2 stays.
    seeded = items["seeded_group_parent_in_other_split"]
    assert (seeded.set_aside_traces, seeded.set_aside_groups, seeded.remaining_groups) == (2, 1, 2)
    assert _value(seeded.table.all_tiers.recall) == (2, 3)  # m3 m4 out of m3 m4 m5
    obf = items["authored_obfuscated_twin"]
    assert (obf.set_aside_traces, obf.set_aside_groups) == (1, 1)
    assert _value(obf.table.all_tiers.recall) == (4, 4)


def test_family_set_aside_takes_a_child_whose_parent_is_across_the_split(project: Path) -> None:
    results = _score(project)
    item = next(x for x in results.set_asides if x.name == "family_member_in_other_split")
    assert (item.set_aside_traces, item.set_aside_groups) == (2, 1)


def _add_labels(project: Path, *extra: dict[str, Any]) -> None:
    corpus = project / "datasets" / "corpus"
    labels = (corpus / "labels.jsonl").read_text(encoding="utf-8").splitlines()
    lines = [*labels, *(json.dumps(item) for item in extra)]
    write_text(corpus / "labels.jsonl", "\n".join(lines) + "\n")


def _row(results: BaselineResults, name: str) -> Any:
    return next(item for item in results.set_asides if item.name == name)


def test_family_set_aside_leaves_a_parent_whose_child_is_across_the_split(project: Path) -> None:
    _add_labels(project, _label("d3", "C3", split="dev", attack_class="AC02", derived_from="A3"))
    results = _score(project)
    # A3 is authored, so the registered wording keeps it. Only the unregistered row removes it.
    family = _row(results, "family_member_in_other_split")
    assert (family.set_aside_traces, family.set_aside_groups) == (2, 1)
    assert family.registered
    broad = _row(results, "any_relative_in_other_split")
    assert (broad.set_aside_traces, broad.set_aside_groups) == (4, 2)
    assert not broad.registered


def test_family_set_aside_takes_a_child_whose_sibling_is_across_the_split(project: Path) -> None:
    # A2's parent P2 is held-out, but its sibling C2 is in dev.
    results = _score(project)
    assert _row(results, "family_member_in_other_split").set_aside_traces == 2
    _add_labels(project, _label("d3", "C2", split="dev", attack_class="AC01", derived_from="P2"))
    results = _score(project)
    family = _row(results, "family_member_in_other_split")
    assert (family.set_aside_traces, family.set_aside_groups) == (3, 2)
    # The card's narrower definition looks only at the parent, so A2 stays there.
    seeded = _row(results, "seeded_group_parent_in_other_split")
    assert (seeded.set_aside_traces, seeded.set_aside_groups) == (2, 1)


def test_ineffective_class_is_kept_out_and_reported(project: Path) -> None:
    corpus = project / "datasets" / "corpus"
    labels = (corpus / "labels.jsonl").read_text(encoding="utf-8").splitlines()
    extra = _label("i1", "I1", attack_class="AC03", succeeded=False)
    write_text(corpus / "labels.jsonl", "\n".join([*labels, json.dumps(extra)]) + "\n")
    for k in (16, 24, 48):
        with (corpus / "heldout" / f"k{k}" / "traces.jsonl").open("ab") as handle:
            for event in _trace("i1", ["c"]):
                handle.write((json.dumps(event) + "\n").encode())
    results = _score(project)
    assert results.population.attack_failed == 3  # i1 is not in the pooled bucket
    assert [item.attack_class for item in results.per_class] == ["AC01", "AC02"]
    assert results.ineffective.traces == 1
    assert _value(results.ineffective.all_tiers.fired) == (1, 1)
    assert _value(next(c for c in results.ineffective.per_tier if c.name == "sequence").fired) == (
        0,
        1,
    )
    assert _value(_tier(results, Tier.CONTENT).rates.fpr) == (1, 4)  # no change to false positives


def test_a_success_in_an_ineffective_class_fails_closed(project: Path) -> None:
    corpus = project / "datasets" / "corpus"
    labels = (corpus / "labels.jsonl").read_text(encoding="utf-8").splitlines()
    extra = _label("i1", "I1", attack_class="AC03", succeeded=True)
    write_text(corpus / "labels.jsonl", "\n".join([*labels, json.dumps(extra)]) + "\n")
    for k in (16, 24, 48):
        with (corpus / "heldout" / f"k{k}" / "traces.jsonl").open("ab") as handle:
            for event in _trace("i1", ["c"]):
                handle.write((json.dumps(event) + "\n").encode())
    with pytest.raises(MetricsInputError, match="registered ineffective"):
        _score(project)


def test_an_empty_ineffective_population_gives_nulls_not_zeros(project: Path) -> None:
    results = _score(project)
    fired = results.ineffective.all_tiers.fired
    assert results.ineffective.traces == 0
    assert (fired.value, fired.ci95, fired.denominator) == (None, None, 0)


def test_exports_with_different_traces_fail_closed(project: Path) -> None:
    corpus = project / "datasets" / "corpus"
    path = corpus / "heldout" / "k48" / "traces.jsonl"
    keep = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["trace_id"] != "b4"
    ]
    write_text(path, "\n".join(keep) + "\n")
    with pytest.raises(MetricsInputError):
        _score(project)


def test_paired_counts_and_difference(project: Path) -> None:
    results = _score(project)
    item = next(c for c in results.tier_comparison if (c.a, c.b) == (Tier.CONTENT, Tier.BEHAVIOR))
    assert (item.recall.a_only, item.recall.b_only, item.recall.both, item.recall.neither) == (
        2,
        1,
        0,
        2,
    )
    assert item.recall.difference == pytest.approx(0.2)
    assert item.recall.groups == 3
    assert (item.fpr.a_only, item.fpr.b_only, item.fpr.both, item.fpr.neither) == (1, 1, 0, 2)
    assert item.fpr.difference == 0.0
    assert item.fpr.groups == 3
    assert item.recall.ci95 is not None
    assert item.recall.ci95.lower <= 0.2 <= item.recall.ci95.upper


def test_results_are_identical_across_runs(project: Path) -> None:
    assert _score(project).model_dump() == _score(project).model_dump()


def test_interval_resamples_groups_not_traces() -> None:
    """Two groups: one where a always wins, one where b always wins. Sizes make it visible."""
    groups = [(9, 9, 0), (1, 0, 1)]
    lower, upper = group_interval(groups, seed=7, resamples=2000)  # type: ignore[misc]
    # Drawn as groups, the only resamples are (A, A) = +1, (B, B) = -1, and (A, B) = +0.8.
    assert lower == -1.0
    assert upper == 1.0


def test_interval_is_deterministic_for_a_seed_and_moves_with_it() -> None:
    groups = [(2, 2, 0), (1, 0, 1), (3, 1, 1), (1, 1, 0), (2, 0, 0)]
    first = group_interval(groups, seed=1337, resamples=500)
    assert first == group_interval(groups, seed=1337, resamples=500)
    assert len({group_interval(groups, seed=seed, resamples=20) for seed in range(10)}) > 1


def test_interval_with_no_groups_is_null() -> None:
    assert group_interval([], seed=1, resamples=10) is None


def test_interval_with_no_discordance_is_zero_width() -> None:
    assert group_interval([(3, 2, 2), (2, 0, 0)], seed=1, resamples=50) == (0.0, 0.0)


def test_cannot_score_without_a_registration_and_nothing_is_logged(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(HELDOUT_ENV, "1")
    args = ["validation", "score", "--out", "out/m.json", "--fixtures", "fx"]
    assert main(args) == 1
    assert "no pre-registration" in capsys.readouterr().err
    assert not (project / "docs" / "heldout-log.md").exists()


def test_scoring_needs_the_declaration(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _register(project)
    assert main(["validation", "score", "--out", "out/m.json", "--fixtures", "fx"]) == 1
    assert "refuses held-out input" in capsys.readouterr().err
    assert not (project / "out" / "m.json").exists()


def test_a_changed_rule_blocks_scoring_before_any_read(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _register(project)
    monkeypatch.setenv(HELDOUT_ENV, "1")
    rule = project / "rules" / "ADG-0101.yaml"
    rule.write_text(
        rule.read_text(encoding="utf-8").replace("Stand-in", "Edited"), encoding="utf-8"
    )
    assert main(["validation", "score", "--out", "out/m.json", "--fixtures", "fx"]) == 1
    assert "differ from the pre-registration" in capsys.readouterr().err
    assert not (project / "docs" / "heldout-log.md").exists()


def test_cli_score_logs_once_writes_and_check_passes_and_catches_edits(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _register(project)
    monkeypatch.setenv(HELDOUT_ENV, "1")
    out = "results/baseline/metrics.json"
    assert main(["validation", "score", "--out", out, "--fixtures", "fx"]) == 0
    log = (project / "docs" / "heldout-log.md").read_text(encoding="utf-8")
    assert log.count("| validation score |") == 1
    assert "datasets/corpus/heldout/k16" in log
    assert str(project) not in log
    golden = project / out
    assert str(project) not in golden.read_text(encoding="utf-8")

    assert main(["validation", "score", "--check", "--fixtures", "fx"]) == 0
    assert "byte-identical" in capsys.readouterr().out
    log = (project / "docs" / "heldout-log.md").read_text(encoding="utf-8")
    assert log.count("| validation score --check |") == 1

    golden.write_text(
        golden.read_text(encoding="utf-8").replace('"tp": 2', '"tp": 3'), encoding="utf-8"
    )
    assert main(["validation", "score", "--check", "--fixtures", "fx"]) == 1
    assert "differs from a fresh score" in capsys.readouterr().err


def test_check_is_skipped_when_rule_hashes_moved_on(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _register(project)
    monkeypatch.setenv(HELDOUT_ENV, "1")
    assert (
        main(["validation", "score", "--out", "results/baseline/metrics.json", "--fixtures", "fx"])
        == 0
    )
    rule = project / "rules" / "ADG-0101.yaml"
    rule.write_text(rule.read_text(encoding="utf-8").replace("1.0.0", "1.0.1"), encoding="utf-8")
    assert main(["validation", "score", "--check", "--fixtures", "fx"]) == 0
    assert "skipped" in capsys.readouterr().out


def test_score_may_not_write_over_the_log(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _register(project)
    monkeypatch.setenv(HELDOUT_ENV, "1")
    assert main(["validation", "score", "--out", "docs/heldout-log.md", "--fixtures", "fx"]) == 1
    assert "firewall-protected" in capsys.readouterr().err


def test_score_needs_an_output_or_check(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validation", "score", "--fixtures", "fx"]) == 1
    assert "needs --out or --check" in capsys.readouterr().err


def test_registration_refuses_to_overwrite(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _register(project)
    assert main(["validation", "prereg", "--fixtures", "fx"]) == 1
    assert "already exists" in capsys.readouterr().err


def test_registration_refuses_a_dirty_checkout(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("agent_detection_gauntlet.cli.git_provenance", lambda: ("a" * 40, True))
    assert main(["validation", "prereg", "--fixtures", "fx"]) == 1
    assert "clean git checkout" in capsys.readouterr().err
    assert not (project / "docs" / "preregistration.json").exists()


def test_cli_prereg_writes_both_files_from_a_clean_checkout(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agent_detection_gauntlet.cli.git_provenance", lambda: ("b" * 40, False))
    assert main(["validation", "prereg", "--fixtures", "fx"]) == 0
    plan = read_preregistration(project / "docs" / "preregistration.json")
    assert plan.tooling_commit == "b" * 40
    assert plan.ineffective_classes == ["AC03"]
    assert plan.rules[0].path == "rules/ADG-0101.yaml"
    assert main(["validation", "verify", "--fixtures", "fx"]) == 0


def test_registered_values_are_the_stated_ones(project: Path) -> None:
    plan = _plan(project)
    assert (plan.coverage.min_heldout_recall, plan.coverage.max_fpr) == (0.5, 0.05)
    assert plan.tier_comparison.resamples == 10000
    assert plan.tier_comparison.seed == 1337
    assert plan.content_ref_ks == [16, 24, 48]
    assert plan.baseline_sidecars == []


def test_drift_names_each_kind_of_change(project: Path) -> None:
    plan = _plan(project)
    assert rule_hash_drift(plan, _loaded(project)) == []
    rule = project / "rules" / "ADG-0101.yaml"
    rule.write_text(
        rule.read_text(encoding="utf-8").replace("Stand-in", "Edited"), encoding="utf-8"
    )
    (project / "rules" / "ADG-0102.yaml").unlink()
    write_rule(project / "rules", _match_rule("ADG-0104", "behavior", "b"))
    assert rule_hash_drift(plan, _loaded(project)) == [
        "ADG-0101 differs from the registered version or hash",
        "ADG-0102 is registered but missing",
        "ADG-0104 is not registered",
    ]


def _verify(
    project: Path,
    frozen: bytes | None = None,
    frozen_doc: bytes | None = None,
    base_results: bytes | None = None,
) -> list[str]:
    docs = project / "docs"
    return verify(
        docs / "preregistration.json",
        docs / "preregistration.md",
        project / "results",
        _loaded(project),
        frozen,
        frozen_doc,
        base_results,
    )


def _write_results(project: Path, results: BaselineResults) -> Path:
    path = project / "results" / "baseline" / "metrics.json"
    write_text(path, json.dumps(results.model_dump(mode="json"), sort_keys=True))
    return path


def test_verify_passes_with_nothing_registered(project: Path) -> None:
    assert _verify(project) == []


def test_verify_fails_on_results_without_a_registration(project: Path) -> None:
    results = _score(project)
    _write_results(project, results)
    (project / "docs" / "preregistration.json").unlink()
    assert "has no pre-registration" in _verify(project)[0]


def test_verify_passes_and_allows_an_appended_doc(project: Path) -> None:
    results = _score(project)
    _write_results(project, results)
    assert _verify(project) == []
    doc = project / "docs" / "preregistration.md"
    doc.write_bytes(doc.read_bytes() + b"\n## Phase 4\n\nAppended later.\n")
    assert _verify(project) == []


def test_verify_fails_on_an_edited_doc(project: Path) -> None:
    _register(project)
    doc = project / "docs" / "preregistration.md"
    doc.write_text(doc.read_text(encoding="utf-8").replace("0.05", "0.5"), encoding="utf-8")
    assert "does not start with" in _verify(project)[0]


def test_verify_fails_when_the_registration_moved_from_its_first_commit(project: Path) -> None:
    _register(project)
    frozen = (project / "docs" / "preregistration.json").read_bytes()
    assert _verify(project, frozen) == []
    assert "changed after" in _verify(project, frozen + b" ")[0]


def test_verify_compares_the_doc_with_its_first_commit_and_allows_appending(project: Path) -> None:
    _register(project)
    doc = project / "docs" / "preregistration.md"
    frozen_doc = doc.read_bytes()
    doc.write_bytes(frozen_doc + b"\n## Errata\n")
    assert _verify(project, frozen_doc=frozen_doc) == []
    assert "changed text" in _verify(project, frozen_doc=frozen_doc + b"x")[0]


def test_verify_holds_the_golden_file_still_once_rules_moved_on(project: Path) -> None:
    results = _score(project)
    path = _write_results(project, results)
    base = path.read_bytes()
    assert _verify(project, base_results=base) == []
    # Rules unchanged: a re-score guards the golden file, so a change here is left to it.
    path.write_bytes(base + b" ")
    assert _verify(project, base_results=base) == []
    rule = project / "rules" / "ADG-0101.yaml"
    rule.write_text(rule.read_text(encoding="utf-8").replace("1.0.0", "1.0.1"), encoding="utf-8")
    assert "changed while the rules differ" in _verify(project, base_results=base)[0]
    path.write_bytes(base)
    assert _verify(project, base_results=base) == []
    path.unlink()
    assert "changed while the rules differ" in _verify(project, base_results=base)[0]


def test_cli_verify_reads_the_frozen_inputs(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    results = _score(project)
    path = _write_results(project, results)
    args = ["validation", "verify", "--fixtures", "fx"]
    args += ["--frozen-prereg", "docs/preregistration.json"]
    args += ["--frozen-doc", "docs/preregistration.md", "--base-results", str(path)]
    assert main(args) == 0
    assert "agree" in capsys.readouterr().out


def test_verify_fails_on_a_rule_edit_without_a_bump_and_allows_a_bump(project: Path) -> None:
    _register(project)
    rule = project / "rules" / "ADG-0101.yaml"
    original = rule.read_text(encoding="utf-8")
    rule.write_text(original.replace("Stand-in", "Edited"), encoding="utf-8")
    assert _verify(project) == ["ADG-0101 changed without a version bump"]
    rule.write_text(original.replace("1.0.0", "1.0.1"), encoding="utf-8")
    assert _verify(project) == []


def test_verify_fails_on_results_naming_other_hashes(project: Path) -> None:
    results = _score(project)
    first = results.rules[0].model_copy(update={"sha256": "0" * 64})
    edited = results.model_copy(update={"rules": [first, *results.rules[1:]]})
    _write_results(project, edited)
    assert any("does not reference the registered rule hashes" in p for p in _verify(project))


def test_verify_fails_on_results_from_another_registration_or_split(project: Path) -> None:
    results = _score(project)
    edited = results.model_copy(update={"preregistration_sha256": "0" * 64, "split": Split.DEV})
    _write_results(project, edited)
    problems = _verify(project)
    assert any("different pre-registration" in p for p in problems)
    assert any("not from the held-out split" in p for p in problems)


def test_report_is_generated_from_the_json_and_clean(project: Path) -> None:
    results = _score(project)
    plan = read_preregistration(project / "docs" / "preregistration.json")
    text = render_results(results, plan)
    assert "2/5 = 0.400" in text
    assert "null (0/0)" in text
    assert "seeded_group_parent_in_other_split" in text
    assert "any_relative_in_other_split (not registered)" in text
    assert "1 of 3 succeeded groups have a parent, sibling or seeded child" in text
    assert "small-N" in text
    assert "underpowered" in text
    for forbidden in (chr(0x2013), chr(0x2014), str(project)):
        assert forbidden not in text
        assert forbidden not in render_preregistration(plan)


def test_cli_report_writes_and_checks(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    results = _score(project)
    path = _write_results(project, results)
    assert read_results(path) == results
    assert main(["validation", "report", "--check"]) == 1
    assert main(["validation", "report"]) == 0
    assert main(["validation", "report", "--check"]) == 0
    capsys.readouterr()


def test_reading_a_corrupt_file_is_an_error(project: Path) -> None:
    path = project / "docs" / "preregistration.json"
    write_text(path, "{}")
    with pytest.raises(GauntletError, match=r"docs/preregistration\.json"):
        read_preregistration(path)
    write_text(path, "not json")
    with pytest.raises(GauntletError, match="not valid JSON"):
        read_preregistration(path)
    with pytest.raises(GauntletError, match="no results"):
        read_results(project / "absent.json")


def test_cli_verify_reports_problems(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validation", "verify", "--fixtures", "fx"]) == 0
    assert "no pre-registration yet" in capsys.readouterr().out
    _register(project)
    doc = project / "docs" / "preregistration.md"
    doc.write_text("edited\n", encoding="utf-8")
    assert main(["validation", "verify", "--fixtures", "fx"]) == 1
    assert "does not start with" in capsys.readouterr().err
