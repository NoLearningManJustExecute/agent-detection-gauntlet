"""Phase 7 public documents. Reads golden results and catalogs, never a trace."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from agent_detection_gauntlet.catalog import Catalog, CatalogEntry, load_catalog
from agent_detection_gauntlet.cli import main
from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.publish.build import DASHBOARD, MAPPINGS, is_current, outputs
from agent_detection_gauntlet.publish.dashboard import change, rate, short_rate
from agent_detection_gauntlet.publish.diagram import (
    DIAGRAM_SOURCE,
    DIAGRAM_SVG,
    load_diagram,
    render_diagram,
)
from agent_detection_gauntlet.publish.mappings import render_mappings
from agent_detection_gauntlet.publish.numbers import (
    PUBLISHED_FILES,
    RESULT_FILES,
    Traceable,
    check_published,
    load_results,
    traceable,
    untraced_tokens,
)

ROOT = Path(__file__).resolve().parent.parent


def _known() -> Any:
    return traceable(load_results(ROOT / path) for path in RESULT_FILES)


def test_generated_documents_are_current() -> None:
    for path, text in outputs(ROOT):
        assert is_current(path, text), path


def test_every_published_rate_is_in_a_results_json() -> None:
    scanned, problems = check_published(ROOT)
    assert [problem.render() for problem in problems] == []
    assert {ROOT / path for path in PUBLISHED_FILES} == set(scanned)


@pytest.mark.parametrize("token", ["7/57", "25/48", "20/28", "1/38", "0/66", "23/46"])
def test_real_fractions_are_traceable(token: str) -> None:
    assert list(untraced_tokens(f"recall {token} here", _known())) == []


@pytest.mark.parametrize(
    ("text", "token"),
    [
        ("recall 99/100 here", "99/100"),
        ("recall 7/58 here", "7/58"),
        ("a value of 0.999 here", "0.999"),
    ],
)
def test_invented_numbers_are_caught(text: str, token: str) -> None:
    assert list(untraced_tokens(text, _known())) == [(1, token)]


def test_percent_with_no_rate_behind_it_is_caught() -> None:
    known = Traceable(frozenset(), frozenset(), frozenset({71}))
    assert list(untraced_tokens("71 percent and 93 points", known)) == [(1, "93 points")]


def test_real_decimals_and_percents_are_traceable() -> None:
    assert list(untraced_tokens("change -0.398 and +0.047, 71 percent", _known())) == []


def test_styles_scripts_links_and_versions_are_not_read_as_claims() -> None:
    text = (
        "<style>a { width: 0.999px; }</style>\n"
        "<script>const x = 99/100;</script>\n"
        "https://example.org/99/100 and python 3.12 and docs/99/100\n"
    )
    assert list(untraced_tokens(text, _known())) == []


def test_line_numbers_survive_blanked_blocks() -> None:
    text = "<style>\nb {}\n</style>\nrecall 99/100\n"
    assert list(untraced_tokens(text, _known())) == [(4, "99/100")]


def test_numbers_command_reports_an_invented_rate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for path in RESULT_FILES:
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_bytes((ROOT / path).read_bytes())
    (tmp_path / "README.md").write_text("recall 99/100\n", encoding="utf-8")
    assert main(["publish", "numbers", "--root-dir", str(tmp_path)]) == 1
    assert "99/100 is in no results JSON" in capsys.readouterr().err
    (tmp_path / "README.md").write_text("recall 20/28\n", encoding="utf-8")
    assert main(["publish", "numbers", "--root-dir", str(tmp_path)]) == 0


def test_nothing_to_scan_fails_closed(tmp_path: Path) -> None:
    for path in RESULT_FILES:
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_bytes((ROOT / path).read_bytes())
    with pytest.raises(GauntletError, match="no published document"):
        check_published(tmp_path)


def test_missing_results_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(GauntletError, match="no results at"):
        load_results(tmp_path / "metrics.json")


def test_build_command_writes_then_passes_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for path in [*RESULT_FILES, DIAGRAM_SOURCE]:
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_bytes((ROOT / path).read_bytes())
    assert main(["publish", "build", "--root-dir", str(tmp_path), "--check"]) == 1
    assert "out of date" in capsys.readouterr().err
    assert main(["publish", "build", "--root-dir", str(tmp_path)]) == 0
    assert main(["publish", "build", "--root-dir", str(tmp_path), "--check"]) == 0
    for path in (DASHBOARD, MAPPINGS, DIAGRAM_SVG):
        assert (tmp_path / path).read_bytes() == (ROOT / path).read_bytes()


def test_dashboard_is_self_contained_and_holds_the_headline() -> None:
    html = (ROOT / DASHBOARD).read_text(encoding="utf-8")
    assert "<script" not in html
    assert not re.search(r"""src\s*=|@import|url\(|https?://""", html)
    assert re.findall(r"""href\s*=\s*['"]([^'"]*)""", html) == ["index.html"]
    for token in ("7/57", "25/48", "-0.398", "20/28 = 0.714", "1/38 = 0.026", "0/66"):
        assert token in html, token
    assert not re.search(r"[A-Za-z]:\\|/home/|/Users/", html)


def test_dashboard_does_not_headline_per_technique_verdicts() -> None:
    html = (ROOT / DASHBOARD).read_text(encoding="utf-8")
    assert html.index("Recall change under payload mutation") < html.index("Clean held-out attacks")
    assert html.index("Clean held-out attacks") < html.index("Per-technique detail")


@pytest.mark.parametrize(
    ("cell", "expected"),
    [
        ({"numerator": 0, "denominator": 0, "value": None, "ci95": None}, "null (0/0)"),
        ({"numerator": 1, "denominator": 2, "value": 0.5, "ci95": None}, "1/2 = 0.500"),
    ],
)
def test_rates_never_turn_null_into_zero(cell: dict[str, Any], expected: str) -> None:
    assert rate(cell) == expected
    assert short_rate(cell) == expected


def test_rate_edges() -> None:
    assert rate(None) == "null"
    cell = {
        "numerator": 1,
        "denominator": 2,
        "value": 0.5,
        "ci95": {"lower": 0.1, "upper": 0.9},
    }
    assert rate(cell) == "1/2 = 0.500 [0.100, 0.900]"
    assert change({"delta": None, "ci95": None}) == "null"
    assert change({"delta": -0.5, "ci95": {"lower": -0.75, "upper": 0.25}}) == (
        "-0.500 [-0.750, +0.250]"
    )


def test_mappings_table_lists_every_entry_and_names_the_unverified() -> None:
    text = render_mappings(load_catalog())
    catalog = load_catalog()
    for family in catalog.families.values():
        for entry in family.values():
            assert f"| {entry.id} | {entry.name} |" in text
            assert entry.checked
    assert "Unverified: AML.T0057." in text


def test_mappings_with_nothing_unverified_say_so() -> None:
    entry = CatalogEntry(
        id="LLM01", name="n", url="https://example.org", version="1", verified=True
    )
    catalog = Catalog(
        families={"atlas": {}, "owasp_llm": {"LLM01": entry}, "owasp_agentic": {}, "attack": {}}
    )
    text = render_mappings(catalog)
    assert "Unverified: none." in text
    assert "| never |" in text


def test_catalog_results_agree_on_what_is_verified() -> None:
    coverage = json.loads((ROOT / RESULT_FILES[2]).read_text(encoding="utf-8"))
    flags = {item["id"]: item["verified"] for item in coverage["techniques"]}
    assert [name for name, verified in flags.items() if not verified] == ["AML.T0057"]


@pytest.mark.parametrize("name", ["docs/assets/demo-banner.svg", "docs/assets/architecture.svg"])
def test_images_carry_no_provenance_or_embedded_data(name: str) -> None:
    text = (ROOT / name).read_text(encoding="utf-8").lower()
    for bad in ("c2pa", "claude", "anthropic", "<metadata", "base64", "<image"):
        assert bad not in text


def test_landing_page_external_references_are_only_fonts_and_own_repos() -> None:
    text = (ROOT / "docs/index.html").read_text(encoding="utf-8")
    assert text.index("<style>") < text.index("@import")
    assert text[text.index("<style>") + len("<style>") :].lstrip().startswith("@import")
    urls = set(re.findall(r"https?://[^\s\"')]+", text))
    own = "https://github.com/NoLearningManJustExecute/"
    fonts = "https://fonts.googleapis.com/"
    assert urls
    assert all(url.startswith((own, fonts)) for url in urls), urls


def test_landing_page_has_both_themes_and_a_motion_fallback() -> None:
    text = (ROOT / "docs/index.html").read_text(encoding="utf-8")
    for token in (
        "prefers-color-scheme: dark",
        ':root[data-theme="dark"]',
        "prefers-reduced-motion: reduce",
    ):
        assert token in text


def test_percent_inside_a_count_up_tag_is_read() -> None:
    known = Traceable(frozenset(), frozenset(), frozenset({71}))
    text = '<b><span data-count="93">93</span> percent</b>\n<b><span>71</span> percent</b>'
    assert list(untraced_tokens(text, known)) == [(1, "93 percent")]


def _evasion_cell(name: str, tier: str) -> dict[str, Any]:
    evasion = load_results(ROOT / RESULT_FILES[1])
    section = next(item for item in evasion["sections"] if item["name"] == name)
    arm = next(item for item in section["arms"] if item["guardrails"] == "off")
    if tier == "all_tiers":
        return dict(arm["table"]["all_tiers"]["paired"])
    return dict(next(c for c in arm["table"]["per_tier"] if c["name"] == tier)["paired"])


def _cell_text(cell: dict[str, Any]) -> str:
    return f"{cell['numerator']}/{cell['denominator']} = {cell['value']:.3f}"


def test_landing_figures_are_pinned_to_their_cells() -> None:
    page = (ROOT / "docs/index.html").read_text(encoding="utf-8")
    banner = (ROOT / "docs/assets/demo-banner.svg").read_text(encoding="utf-8")
    baseline = load_results(ROOT / RESULT_FILES[0])
    recall = baseline["pooled"]["all_tiers"]["rates"]["recall"]
    assert f'data-count="{round(recall["value"] * 100)}"' in page
    assert f'data-count="{len(baseline["rules"])}"' in page
    content = _evasion_cell("all_payload_mutations", "content")
    assert f'data-count="{round(abs(content["delta"]) * 100)}"' in page
    for tier in ("content", "sequence", "behavior", "all_tiers"):
        delta = _evasion_cell("all_payload_mutations", tier)["delta"]
        assert f"--w:{abs(delta) * 100:.1f}%" in page, tier
    mutated_content = _evasion_cell("homoglyph", "content")["mutated"]
    mutated_behavior = _evasion_cell("homoglyph", "behavior")["mutated"]
    all_tiers = _evasion_cell("homoglyph", "all_tiers")
    for text in (page, banner):
        assert f"x mutated: {_cell_text(mutated_content)}" in text
        assert f"+ mutated: {_cell_text(mutated_behavior)}" in text
    missed = all_tiers["mutated"]["denominator"] - all_tiers["mutated"]["numerator"]
    assert f"{missed} of {all_tiers['mutated']['denominator']} successful attacks" in page
    assert f"{all_tiers['delta']:+.3f}" in page


def test_readme_opens_with_the_banner_and_one_live_demo_line() -> None:
    lines = (ROOT / "README.md").read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("![") and lines[0].endswith("(docs/assets/demo-banner.svg)")
    assert lines[1] == ""
    assert sum(line.startswith("Live demo:") for line in lines) == 1


def test_landing_relative_links_exist() -> None:
    page = (ROOT / "docs/index.html").read_text(encoding="utf-8")
    links = re.findall(r'href="([^"#]+)"', page)
    relative = [link for link in links if not link.startswith("https://")]
    assert relative
    assert all((ROOT / "docs" / link).is_file() for link in relative)


def test_ci_gives_the_private_list_only_to_the_job_that_runs_no_change_code() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    holders = [
        (name, step)
        for name, job in workflow["jobs"].items()
        for step in job["steps"]
        if "secrets." in str(step.get("env", {}))
    ]
    assert holders
    for name, step in holders:
        assert name == "leak-guard"
        assert "$LEAK_GUARD" in step["run"]
        assert "tools/leak_guard.py" not in step["run"]
    assert "env" not in workflow
    assert all("env" not in job for job in workflow["jobs"].values())


def test_diagram_renders_every_stage_and_no_embedded_data() -> None:
    svg = render_diagram(load_diagram(ROOT / DIAGRAM_SOURCE))
    for stage in ("Lab", "Telemetry", "Detection", "Evaluation"):
        assert f">{stage}</text>" in svg
    for bad in ("<metadata", "base64", "<image", "href"):
        assert bad not in svg


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("title: t\nstages: []\nfooter: f\n", "stages"),
        ("- not\n- a mapping\n", "architecture.yaml"),
        ("title: [\n", "architecture.yaml"),
    ],
)
def test_bad_diagram_source_fails(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "architecture.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(GauntletError, match=message):
        load_diagram(path)


def test_missing_diagram_source_fails(tmp_path: Path) -> None:
    with pytest.raises(GauntletError, match="no diagram source"):
        load_diagram(tmp_path / "absent.yaml")
