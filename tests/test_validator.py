"""Each validator error class has a failing fixture here."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent_detection_gauntlet.catalog import (
    Catalog,
    CatalogEntry,
    load_catalog,
    parse_catalog_file,
)
from agent_detection_gauntlet.errors import CatalogError
from agent_detection_gauntlet.rules.validator import IssueLevel, ValidationReport, validate_rules
from tests.conftest import RULE_FIXTURES, RULES_DIR, rule_data, write_rule


def entry(mapping_id: str, verified: bool = True) -> CatalogEntry:
    return CatalogEntry(
        id=mapping_id, name="n", url="https://example.org", version="1", verified=verified
    )


VERIFIED = Catalog(
    families={
        "atlas": {"AML.T0051.001": entry("AML.T0051.001")},
        "owasp_llm": {"LLM01": entry("LLM01")},
        "owasp_agentic": {"ASI01": entry("ASI01")},
        "attack": {},
    }
)


def run(
    tmp_path: Path, fixture_dir: Path, *rules: dict[str, Any], catalog: Catalog = VERIFIED
) -> ValidationReport:
    rules_dir = tmp_path / "rules"
    for data in rules:
        write_rule(rules_dir, data)
    return validate_rules(rules_dir, [fixture_dir], catalog)


def messages(report: Any) -> list[str]:
    return [issue.message for issue in report.errors]


def test_valid_rule_passes(tmp_path: Path, fixture_dir: Path) -> None:
    report = run(tmp_path, fixture_dir, rule_data())
    assert report.ok, report.issues
    assert report.warnings == []
    assert len(report.rules) == 1


def test_repository_rules_validate_against_repository_fixtures() -> None:
    report = validate_rules(RULES_DIR, RULE_FIXTURES, load_catalog())
    assert report.ok, [issue.render() for issue in report.errors]
    # Catalog entries ship unverified until Phase 7 checks them, so each mapping warns.
    mappings = [loaded.rule.mappings.by_family() for loaded in report.rules]
    assert len(report.warnings) == sum(len(ids) for family in mappings for ids in family.values())


def test_schema_error(tmp_path: Path, fixture_dir: Path) -> None:
    report = run(tmp_path, fixture_dir, rule_data(severity="urgent"))
    assert report.rules == []
    assert any("severity" in m for m in messages(report))


def test_file_name_must_match_id(tmp_path: Path, fixture_dir: Path) -> None:
    write_rule(tmp_path / "rules", rule_data(), name="other.yaml")
    report = validate_rules(tmp_path / "rules", [fixture_dir], VERIFIED)
    assert messages(report) == ["file name must be ADG-9001.yaml to match the rule id"]


def test_duplicate_ids(tmp_path: Path, fixture_dir: Path) -> None:
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, rule_data())
    write_rule(rules_dir, rule_data(), name="ADG-9001.yml")
    report = validate_rules(rules_dir, [fixture_dir], VERIFIED)
    assert any("duplicate rule id ADG-9001" in m for m in messages(report))


def test_bad_mapping_format(tmp_path: Path, fixture_dir: Path) -> None:
    mappings = {"atlas": ["AML.T51"], "owasp_llm": [], "owasp_agentic": [], "attack": []}
    report = run(tmp_path, fixture_dir, rule_data(mappings=mappings))
    assert any("mappings.atlas" in m for m in messages(report))


def test_unknown_mapping_id(tmp_path: Path, fixture_dir: Path) -> None:
    mappings = {"atlas": [], "owasp_llm": ["LLM09"], "owasp_agentic": [], "attack": ["T1059"]}
    report = run(tmp_path, fixture_dir, rule_data(mappings=mappings))
    assert messages(report) == [
        "owasp_llm id LLM09 is not in the catalog",
        "attack id T1059 is not in the catalog",
    ]


def test_unverified_mapping_warns(tmp_path: Path, fixture_dir: Path) -> None:
    catalog = Catalog(
        families={**VERIFIED.families, "owasp_llm": {"LLM01": entry("LLM01", verified=False)}}
    )
    report = run(tmp_path, fixture_dir, rule_data(), catalog=catalog)
    assert report.ok
    assert [issue.level for issue in report.warnings] == [IssueLevel.WARNING]
    assert "LLM01" in report.warnings[0].render()


def test_missing_fixture_trace(tmp_path: Path, fixture_dir: Path) -> None:
    report = run(tmp_path, fixture_dir, rule_data(fixtures={"tp": ["t-tp"], "fp": ["ghost"]}))
    assert messages(report) == ["fp fixture trace 'ghost' does not exist"]


def test_missing_tp_or_fp_fixtures(tmp_path: Path, fixture_dir: Path) -> None:
    report = run(tmp_path, fixture_dir, rule_data(fixtures={"tp": ["t-tp"]}))
    assert any("fixtures.fp" in m for m in messages(report))


def test_empty_limitations(tmp_path: Path, fixture_dir: Path) -> None:
    report = run(tmp_path, fixture_dir, rule_data(limitations=[]))
    assert any("limitations" in m for m in messages(report))


def test_rule_must_fire_on_tp_and_not_on_fp(tmp_path: Path, fixture_dir: Path) -> None:
    report = run(tmp_path, fixture_dir, rule_data(fixtures={"tp": ["t-fp"], "fp": ["t-tp"]}))
    assert messages(report) == [
        "rule does not fire on tp fixture 't-fp'",
        "rule fires on fp fixture 't-tp'",
    ]


def test_unloadable_fixtures(tmp_path: Path) -> None:
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "x.jsonl").write_text("{oops\n", encoding="utf-8")
    report = run(tmp_path, broken, rule_data())
    assert any("cannot load fixture traces" in m for m in messages(report))


def test_catalog_loads_with_expected_entries() -> None:
    catalog = load_catalog()
    assert catalog.lookup("atlas", "AML.T0051.001") is not None
    assert catalog.lookup("owasp_agentic", "ASI01") is not None
    assert catalog.lookup("attack", "T1059") is None
    assert all(
        not item.verified for family in catalog.families.values() for item in family.values()
    )


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("entries: [{id: LLM1, name: n, url: 'https://x', version: '1'}]", "not a valid"),
        (
            "entries: [{id: LLM01, name: n, url: 'https://x', version: '1'},"
            " {id: LLM01, name: n, url: 'https://x', version: '1'}]",
            "duplicate entry",
        ),
        ("entries: [{id: LLM01, name: n, url: 'http://x', version: '1'}]", "url"),
        ("entries: [{id: LLM01, name: n, url: 'https://x', version: 1}]", "version"),
        ("- nope", "must be a mapping"),
    ],
)
def test_catalog_errors(text: str, message: str) -> None:
    with pytest.raises(CatalogError, match=message):
        parse_catalog_file("owasp_llm", text, "catalog/test.yaml")
