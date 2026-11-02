"""The held-out firewall. Every path here is a stand-in under tmp_path; no test reads real data."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agent_detection_gauntlet.cli import main
from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.firewall import (
    HELDOUT_ENV,
    LOG_HEADER,
    heldout_inputs,
    refuse_heldout,
    require_clearance,
)
from agent_detection_gauntlet.paths import set_repo_root
from tests.conftest import taint_trace_events, write_lines


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A stand-in repository with a held-out file, a dev file and a manifest pinning the first."""
    monkeypatch.delenv(HELDOUT_ENV, raising=False)
    (tmp_path / ".git").mkdir()
    corpus = tmp_path / "datasets" / "corpus"
    held = write_lines(corpus / "heldout" / "k24" / "traces.jsonl", taint_trace_events("t-held"))
    write_lines(corpus / "dev" / "k24" / "traces.jsonl", taint_trace_events("t-dev"))
    pinned = hashlib.sha256(held.read_bytes()).hexdigest()
    manifest = {"files": {"heldout/k24/traces.jsonl": pinned, "labels.jsonl": "0" * 64}}
    (corpus / "SPLIT_MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    set_repo_root(tmp_path)
    return tmp_path


def test_heldout_paths_are_flagged_and_dev_paths_are_not(repo: Path) -> None:
    corpus = repo / "datasets" / "corpus"
    assert heldout_inputs([corpus / "dev" / "k24"]) == []
    for path in (
        corpus / "heldout",
        corpus / "heldout" / "k24",
        corpus / "heldout" / "k24" / "traces.jsonl",
    ):
        assert heldout_inputs([path]) == [path]


@pytest.mark.parametrize("parent", ["", "datasets", "datasets/corpus"])
def test_a_parent_directory_counts_because_it_expands_to_heldout(repo: Path, parent: str) -> None:
    path = repo / parent
    assert heldout_inputs([path]) == [path]


def test_a_copy_elsewhere_is_recognized_by_its_pinned_hash(repo: Path, tmp_path: Path) -> None:
    source = repo / "datasets" / "corpus" / "heldout" / "k24" / "traces.jsonl"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    copy = elsewhere / "innocent.jsonl"
    copy.write_bytes(source.read_bytes())
    assert heldout_inputs([copy]) == [copy]
    assert heldout_inputs([elsewhere]) == [elsewhere]


def test_no_manifest_means_paths_only(tmp_path: Path) -> None:
    set_repo_root(tmp_path)
    other = write_lines(tmp_path / "other" / "x.jsonl", taint_trace_events("t-1"))
    assert heldout_inputs([other]) == []


def test_refusal_names_the_input_and_writes_no_log(repo: Path) -> None:
    path = repo / "datasets" / "corpus" / "heldout"
    with pytest.raises(GauntletError, match=r"scan refuses held-out input \(datasets/corpus/held"):
        require_clearance("scan", [path])
    assert not (repo / "docs" / "heldout-log.md").exists()


def test_clearance_logs_every_read_with_relative_paths(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(HELDOUT_ENV, "1")
    path = repo / "datasets" / "corpus" / "heldout" / "k24"
    require_clearance("scan", [path])
    require_clearance("metrics", [], scoring_split=True)
    text = (repo / "docs" / "heldout-log.md").read_text(encoding="utf-8")
    assert text.startswith(LOG_HEADER)
    rows = text[len(LOG_HEADER) :].splitlines()
    assert len(rows) == 2
    assert "| scan | datasets/corpus/heldout/k24 |" in rows[0]
    assert "| metrics | split heldout of the corpus labels |" in rows[1]
    assert str(repo) not in text


def test_only_the_exact_value_clears(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(HELDOUT_ENV, "true")
    with pytest.raises(GauntletError):
        require_clearance("scan", [repo / "datasets" / "corpus" / "heldout"])


def test_clean_inputs_need_no_clearance_and_are_not_logged(repo: Path) -> None:
    require_clearance("scan", [repo / "datasets" / "corpus" / "dev"])
    assert not (repo / "docs" / "heldout-log.md").exists()


def test_refuse_heldout_ignores_the_environment(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(HELDOUT_ENV, "1")
    with pytest.raises(GauntletError, match="rule fixtures must not read held-out data"):
        refuse_heldout([repo / "datasets" / "corpus" / "heldout"], "rule fixtures")


def test_cli_scan_refuses_heldout_before_doing_anything(
    repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    held = repo / "datasets" / "corpus" / "heldout" / "k24"
    out = tmp_path / "d.jsonl"
    args = ["scan", "--rules", "missing", "--traces", str(held), "--out", str(out)]
    assert main(["--root", str(repo), *args]) == 1
    assert "refuses held-out input" in capsys.readouterr().err
    assert not out.exists()


def test_cli_validate_rules_refuses_heldout_fixtures(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    held = repo / "datasets" / "corpus" / "heldout"
    args = ["validate-rules", "missing", "--fixtures", str(held)]
    assert main(["--root", str(repo), *args]) == 1
    assert "rule fixtures must not read held-out data" in capsys.readouterr().err


def _corpus_label(trace_id: str, split: str) -> dict[str, object]:
    return {
        "attack_class": None,
        "attack_succeeded": None,
        "guardrails": "off",
        "label": "benign",
        "mutation": None,
        "schema_version": "0.1",
        "source": "agent-risk-framework",
        "split": split,
        "trace_id": trace_id,
    }


def test_cli_metrics_refuses_corpus_labels_on_the_default_split(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    labels = write_lines(repo / "labels.jsonl", [_corpus_label("t-held", "heldout")])
    dev = repo / "datasets" / "corpus" / "dev" / "k24"
    args = [
        "metrics",
        "--rules",
        "missing",
        "--traces",
        str(dev),
        "--detections",
        "missing",
        "--labels",
        str(labels),
        "--out",
        str(repo / "m.json"),
    ]
    assert main(["--root", str(repo), *args]) == 1
    assert "split heldout of the corpus labels" in capsys.readouterr().err
    # The dev split of the same labels is not a held-out read.
    assert main(["--root", str(repo), *args, "--split", "dev"]) == 1
    assert "refuses held-out" not in capsys.readouterr().err
