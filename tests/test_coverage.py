"""Phase 5 coverage. Verdict logic on hand-made populations, then the frozen golden files.

No test reads a held-out trace: coverage reads rule files and golden results only.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from agent_detection_gauntlet.catalog import load_catalog
from agent_detection_gauntlet.cli import main
from agent_detection_gauntlet.coverage.claims import docs_to_scan, find_claims, unsupported_claims
from agent_detection_gauntlet.coverage.compute import (
    COVERAGE_JSON,
    Inputs,
    _best,
    _verdict,
    build_coverage,
    load_class_map,
    parse_class_map,
)
from agent_detection_gauntlet.coverage.model import (
    CoverageReport,
    Population,
    Reason,
    RuleEvidence,
)
from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.evasion.model import EvasionResults
from agent_detection_gauntlet.metrics.compute import make_rate, sha256_file
from agent_detection_gauntlet.rules.loader import LoadedRule, load_rule_file, rule_files
from agent_detection_gauntlet.schema.common import Tier
from agent_detection_gauntlet.validation.prereg import (
    BASELINE_RESULTS,
    PREREG_JSON,
    read_preregistration,
    read_results,
)

EVASION_RESULTS = Path("results/evasion/evasion.json")


def evidence(rule_id: str, hits: int, total: int, false_alarms: int = 0) -> RuleEvidence:
    recall = make_rate(hits, total)
    fpr = make_rate(false_alarms, 38)
    return RuleEvidence(
        rule_id=rule_id,
        tier=Tier.CONTENT,
        recall=recall,
        fpr=fpr,
        meets_recall=recall.value is not None and recall.value >= 0.5,
        meets_fpr=fpr.value is not None and fpr.value <= 0.05,
    )


def population(*rules: RuleEvidence, by_class: dict[str, int] | None = None) -> Population:
    return Population(
        name="clean_heldout",
        source="made by hand",
        succeeded_traces=10,
        succeeded_groups=5,
        succeeded_by_class=by_class if by_class is not None else {"AC01": 10},
        rules=list(rules),
    )


# The bar


def test_exactly_at_both_thresholds_is_covered() -> None:
    verdict = _verdict(population(evidence("ADG-0001", 5, 10, 1)), ["ADG-0001"], ["AC01"], False)
    assert verdict.covered
    assert verdict.covering_rules == ["ADG-0001"]
    assert verdict.reason is None


def test_recall_just_under_is_not_covered() -> None:
    verdict = _verdict(population(evidence("ADG-0001", 49, 100)), ["ADG-0001"], ["AC01"], False)
    assert not verdict.covered
    assert verdict.reason is Reason.RECALL_TOO_LOW


def test_recall_met_but_fpr_over_reads_fpr_too_high() -> None:
    verdict = _verdict(population(evidence("ADG-0001", 9, 10, 3)), ["ADG-0001"], ["AC01"], False)
    assert not verdict.covered
    assert verdict.reason is Reason.FPR_TOO_HIGH


def test_only_mapped_rules_count() -> None:
    table = population(evidence("ADG-0001", 1, 10), evidence("ADG-0002", 9, 10))
    assert not _verdict(table, ["ADG-0001"], ["AC01"], False).covered
    assert _verdict(table, ["ADG-0001", "ADG-0002"], ["AC01"], False).covering_rules == ["ADG-0002"]


def test_null_recall_never_passes() -> None:
    verdict = _verdict(population(evidence("ADG-0001", 0, 0)), ["ADG-0001"], [], False)
    assert not verdict.covered
    assert verdict.reason is Reason.RECALL_TOO_LOW
    assert verdict.best_rule.recall.value is None


# The class map removes verdicts and never grants one


def test_ineffective_only_is_never_covered_even_if_a_rule_passes() -> None:
    verdict = _verdict(population(evidence("ADG-0001", 9, 10)), ["ADG-0001"], ["AC09"], True)
    assert not verdict.covered
    assert verdict.covering_rules == []
    assert verdict.reason is Reason.NO_SUCCESSFUL_ATTACKS


def test_no_own_successes_here_is_not_covered() -> None:
    table = population(evidence("ADG-0001", 9, 10), by_class={"AC01": 10, "AC05": 0})
    verdict = _verdict(table, ["ADG-0001"], ["AC05"], False)
    assert not verdict.covered
    assert verdict.own_succeeded_traces == 0
    assert verdict.reason is Reason.NO_SUCCESSFUL_ATTACKS


def test_no_class_tie_is_judged_on_the_pooled_rows() -> None:
    verdict = _verdict(population(evidence("ADG-0001", 9, 10)), ["ADG-0001"], [], False)
    assert verdict.covered
    assert verdict.own_succeeded_traces is None


def test_low_own_share_does_not_grant_or_remove() -> None:
    table = population(evidence("ADG-0001", 2, 10), by_class={"AC01": 8, "AC05": 2})
    verdict = _verdict(table, ["ADG-0001"], ["AC05"], False)
    assert not verdict.covered
    assert verdict.reason is Reason.RECALL_TOO_LOW


def test_best_rule_is_highest_recall_then_lowest_fpr_then_id() -> None:
    assert _best([evidence("ADG-0002", 3, 10), evidence("ADG-0001", 2, 10)]).rule_id == "ADG-0002"
    tied = [evidence("ADG-0001", 3, 10, 1), evidence("ADG-0002", 3, 10)]
    assert _best(tied).rule_id == "ADG-0002"
    assert _best([evidence("ADG-0002", 3, 10), evidence("ADG-0001", 3, 10)]).rule_id == "ADG-0001"


# Class map


def _map_text(**overrides: Any) -> str:
    entry: dict[str, list[str]] = {
        "atlas": [],
        "owasp_llm": [],
        "owasp_agentic": [],
        "attack": [],
        "not_in_catalog": [],
    }
    entry.update(overrides)
    return json.dumps({"source_commit": "abc", "classes": {"AC01": entry}})


def test_class_map_refuses_an_id_the_catalog_lacks() -> None:
    with pytest.raises(GauntletError, match=r"AML\.T9999 not in atlas"):
        parse_class_map(_map_text(atlas=["AML.T9999"]), load_catalog())


def test_class_map_refuses_a_catalog_id_marked_outside() -> None:
    with pytest.raises(GauntletError, match=r"AML\.T0053 is in the catalog"):
        parse_class_map(_map_text(not_in_catalog=["AML.T0053"]), load_catalog())


def test_class_map_refuses_unknown_keys_and_bad_yaml() -> None:
    with pytest.raises(GauntletError, match="attack_classes"):
        parse_class_map('{"source_commit": "abc", "classes": {}, "extra": 1}', load_catalog())
    with pytest.raises(GauntletError, match="attack_classes"):
        parse_class_map("- not\n- a mapping\n", load_catalog())


# Claims


@pytest.mark.parametrize(
    "text",
    [
        "AML.T0053 is covered by this rule.",
        "We have coverage of LLM06 now.",
        "Coverage: ASI02",
        "AML.T0051.001\nis covered",
    ],
)
def test_a_claim_next_to_an_id_is_found(text: str) -> None:
    assert list(find_claims(text))


@pytest.mark.parametrize(
    "text",
    [
        "AML.T0053 is not covered here.",
        "There is no coverage for LLM06.",
        "ASI02 is mapped. Elsewhere, far away, " + "x" * 100 + " the word coverage appears.",
        "Test coverage is 99 percent.",
        "The word covered with no technique.",
        "XAML.T0053 is covered, and Tool1005 is covered.",
    ],
)
def test_no_claim_is_found(text: str) -> None:
    assert not list(find_claims(text))


def _report(covered: bool) -> CoverageReport:
    data = json.loads(COVERAGE_JSON.read_text(encoding="utf-8"))
    for technique in data["techniques"]:
        for verdict in technique["verdicts"]:
            verdict["covered"] = covered and technique["id"] == "LLM06"
    return CoverageReport.model_validate_json(json.dumps(data))


def test_unsupported_claim_fails_and_a_supported_one_passes(tmp_path: Path) -> None:
    doc = tmp_path / "claim.md"
    doc.write_text("LLM06 is covered.\n", encoding="utf-8")
    problems = unsupported_claims([doc], _report(False))
    assert [(item.line, item.technique) for item in problems] == [(1, "LLM06")]
    assert unsupported_claims([doc], _report(True)) == []
    doc.write_text("\nLLM99 is covered.\n", encoding="utf-8")
    assert [item.technique for item in unsupported_claims([doc], _report(True))] == ["LLM99"]


def test_scan_takes_top_level_and_docs_but_not_the_generated_doc(tmp_path: Path) -> None:
    (tmp_path / "docs" / "deep").mkdir(parents=True)
    (tmp_path / "README.md").write_text("x", encoding="utf-8")
    (tmp_path / "docs" / "a.md").write_text("x", encoding="utf-8")
    (tmp_path / "docs" / "deep" / "b.md").write_text("x", encoding="utf-8")
    generated = tmp_path / "docs" / "coverage.md"
    generated.write_text("x", encoding="utf-8")
    names = [path.name for path in docs_to_scan(tmp_path, generated)]
    assert names == ["README.md", "a.md", "b.md"]
    assert docs_to_scan(tmp_path / "missing", generated) == []


def test_claims_command_fails_on_an_unsupported_claim(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("AML.T0051.001 is covered.\n", encoding="utf-8")
    argv = ["coverage", "claims", "--root-dir", str(tmp_path)]
    assert main(argv) == 1
    assert main(["coverage", "claims", "--results", str(tmp_path / "none.json")]) == 1


# The frozen results


def real_inputs() -> Inputs:
    catalog = load_catalog()
    return Inputs(
        plan=read_preregistration(PREREG_JSON),
        plan_sha256=sha256_file(PREREG_JSON),
        baseline=read_results(BASELINE_RESULTS),
        baseline_sha256=sha256_file(BASELINE_RESULTS),
        evasion=EvasionResults.model_validate_json(EVASION_RESULTS.read_text(encoding="utf-8")),
        rules=[LoadedRule(path, load_rule_file(path)) for path in rule_files(Path("rules"))],
        catalog=catalog,
        class_map=load_class_map(catalog),
        input_refs=[],
    )


def _verdicts(report: CoverageReport, name: str) -> dict[str, Any]:
    return {
        item.id: next(verdict for verdict in item.verdicts if verdict.population == name)
        for item in report.techniques
    }


def test_thresholds_come_from_the_registration() -> None:
    report = build_coverage(real_inputs())
    assert report.thresholds.min_heldout_recall == 0.5
    assert report.thresholds.max_fpr == 0.05


def test_every_mapped_technique_has_a_row_and_three_verdicts() -> None:
    report = build_coverage(real_inputs())
    expected = {
        mapping_id
        for path in rule_files(Path("rules"))
        for family in ("atlas", "owasp_llm", "owasp_agentic", "attack")
        for mapping_id in getattr(load_rule_file(path).mappings, family)
    }
    assert {item.id for item in report.techniques} == expected
    assert all(len(item.verdicts) == 3 for item in report.techniques)


def test_measured_verdicts_on_the_golden_files() -> None:
    report = build_coverage(real_inputs())
    clean = _verdicts(report, "clean_heldout")
    payload = _verdicts(report, "payload_mutations")
    variants = _verdicts(report, "attack_variants")
    assert not any(verdict.covered for verdict in clean.values())
    assert not any(verdict.covered for verdict in payload.values())
    assert {name for name, verdict in variants.items() if verdict.covered} == {
        "AML.T0053",
        "AML.T0057",
        "ASI02",
        "ASI03",
        "LLM06",
        "T1005",
    }
    assert clean["AML.T0053"].best_rule.rule_id == "ADG-0012"
    assert clean["AML.T0053"].best_rule.recall.numerator == 7
    assert clean["AML.T0053"].best_rule.recall.denominator == 28
    assert clean["AML.T0053"].reason is Reason.RECALL_TOO_LOW


def test_ineffective_only_techniques_on_the_golden_files() -> None:
    report = build_coverage(real_inputs())
    assert {item.id for item in report.techniques if item.ineffective_only} == {
        "AML.T0051.001",
        "LLM02",
    }
    for item in report.techniques:
        if item.ineffective_only:
            assert not any(verdict.covered for verdict in item.verdicts)
            assert all(verdict.reason is Reason.NO_SUCCESSFUL_ATTACKS for verdict in item.verdicts)
            assert item.clean_technique_counts == []


def test_technique_counts_add_over_own_classes() -> None:
    report = build_coverage(real_inputs())
    asi04 = next(item for item in report.techniques if item.id == "ASI04")
    assert asi04.classes == ["AC11", "AC12A", "AC12B"]
    count = asi04.clean_technique_counts[0]
    assert (count.rule_id, count.recall.numerator, count.recall.denominator) == ("ADG-0005", 6, 9)
    # Own counts passing the line must not make it covered: the registered bar is pooled.
    assert not next(v for v in asi04.verdicts if v.population == "clean_heldout").covered


def test_populations_agree_with_the_golden_totals() -> None:
    report = build_coverage(real_inputs())
    totals = {item.name: item for item in report.populations}
    assert totals["clean_heldout"].succeeded_traces == 28
    assert sum(totals["clean_heldout"].succeeded_by_class.values()) == 28
    assert totals["payload_mutations"].succeeded_traces == 57
    assert sum(totals["payload_mutations"].succeeded_by_class.values()) == 57
    assert totals["attack_variants"].succeeded_traces == 5
    assert sum(totals["attack_variants"].succeeded_by_class.values()) == 5


def test_attacked_without_rule_lists_ids_outside_the_catalog() -> None:
    report = build_coverage(real_inputs())
    rows = {item.id: item for item in report.attacked_without_rule}
    assert rows["AML.T0056"].classes == ["AC04"]
    assert rows["AML.T0056"].clean_succeeded_traces == 4
    assert rows["AML.T0086"].clean_succeeded_traces == 0


def test_refuses_results_that_do_not_belong_together() -> None:
    inputs = real_inputs()
    with pytest.raises(GauntletError, match="different registration"):
        build_coverage(replace(inputs, plan_sha256="0" * 64))
    with pytest.raises(GauntletError, match="different baseline"):
        build_coverage(replace(inputs, baseline_sha256="0" * 64))
    with pytest.raises(GauntletError, match="rule files differ"):
        build_coverage(replace(inputs, rules=list(inputs.rules)[:-1]))
    short = inputs.class_map.model_copy(update={"classes": {}})
    with pytest.raises(GauntletError, match="no entry for"):
        build_coverage(replace(inputs, class_map=short))


def test_committed_outputs_match_a_fresh_build(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["coverage", "build", "--check"]) == 0
    assert "match" in capsys.readouterr().out


def test_check_fails_on_a_stale_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    stale = tmp_path / "coverage.json"
    stale.write_text("{}\n", encoding="utf-8")
    doc = tmp_path / "coverage.md"
    argv = ["coverage", "build", "--out", str(stale), "--doc", str(doc)]
    assert main([*argv, "--check"]) == 1
    assert "out of date" in capsys.readouterr().err
    assert main(argv) == 0
    assert stale.read_bytes() == COVERAGE_JSON.read_bytes()
    assert doc.read_bytes() == Path("docs/coverage.md").read_bytes()
    assert main([*argv, "--check"]) == 0


def test_build_refuses_an_input_outside_the_repository(tmp_path: Path) -> None:
    outside = tmp_path / "preregistration.json"
    outside.write_bytes(PREREG_JSON.read_bytes())
    assert main(["coverage", "build", "--check", "--prereg", str(outside)]) == 1


def test_outputs_hold_no_timestamp_or_local_path() -> None:
    text = COVERAGE_JSON.read_text(encoding="utf-8")
    assert "timestamp" not in text
    assert ":\\" not in text
    assert not any(ref["path"].startswith("/") for ref in json.loads(text)["inputs"])
