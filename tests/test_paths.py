"""Paths in reports and logs: repository-relative, never absolute, independent of the cwd."""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agent_detection_gauntlet.cli import main
from agent_detection_gauntlet.paths import (
    find_repo_root,
    repo_relative,
    set_repo_root,
    shown_path,
)
from tests.conftest import FIXTURE_LABELS, FIXTURE_TRACES, REPO_ROOT, RULES_DIR
from tools.leak_guard import GENERIC_RULES

PATH_RULES = frozenset(
    {
        "windows-path",
        "unc-path",
        "macos-home-path",
        "linux-home-path",
        "userprofile-variable",
        "home-tilde-path",
    }
)


def absolute_path_hits(text: str) -> list[str]:
    return [
        match.group()
        for rule in GENERIC_RULES
        if rule.name in PATH_RULES
        for match in rule.pattern.finditer(text)
    ]


def strings_in(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from strings_in(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings_in(item)


def assert_no_absolute_paths(text: str) -> None:
    assert absolute_path_hits(text) == []
    for value in strings_in(json.loads(text)):
        assert absolute_path_hits(value) == [], value


def scan_and_score(
    rules: str, traces: str, labels: str, out: Path, *extra: str
) -> tuple[bytes, bytes]:
    detections = out / "detections.jsonl"
    metrics = out / "metrics.json"
    fixtures = ["--fixtures", traces]
    external = ["--external-basename"] if "--external-basename" in extra else []
    common = [arg for arg in extra if arg != "--external-basename"]
    scan = ["scan", "--rules", rules, "--traces", traces, "--out", str(detections), *fixtures]
    assert main([*common, *scan]) == 0
    score = [
        "metrics",
        "--rules",
        rules,
        "--traces",
        traces,
        "--detections",
        str(detections),
        "--labels",
        labels,
        "--out",
        str(metrics),
        *fixtures,
        *external,
    ]
    assert main([*common, *score]) == 0
    return detections.read_bytes(), metrics.read_bytes()


def test_find_repo_root_walks_up_to_git(tmp_path: Path) -> None:
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    deep = project / "a" / "b"
    deep.mkdir(parents=True)
    assert find_repo_root(deep) == project.resolve()
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")
    assert find_repo_root(worktree) == worktree.resolve()


def test_find_repo_root_falls_back_to_start(tmp_path: Path) -> None:
    start = tmp_path / "plain"
    start.mkdir()
    root = find_repo_root(start)
    assert root == start.resolve() or (root / ".git").exists()


def test_repo_relative_and_shown_path(tmp_path: Path) -> None:
    set_repo_root(tmp_path)
    assert repo_relative(tmp_path) == "."
    assert repo_relative(tmp_path / "a" / "b.txt") == "a/b.txt"
    assert repo_relative(tmp_path.parent / "x.txt") is None
    assert shown_path(tmp_path / "a" / "b.txt") == "a/b.txt"
    assert shown_path(tmp_path.parent / "x.txt") == "<outside repo>/x.txt"
    set_repo_root(None)
    assert repo_relative(RULES_DIR) == "rules"


def test_reports_are_identical_from_root_and_subdirectory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(REPO_ROOT)
    first_out = tmp_path / "first"
    first = scan_and_score(
        "rules",
        "datasets/fixtures/traces",
        "datasets/fixtures/labels.jsonl",
        first_out,
        "--external-basename",
    )
    monkeypatch.chdir(REPO_ROOT / "docs")
    second_out = tmp_path / "second"
    second = scan_and_score(
        "../rules",
        "../datasets/fixtures/traces",
        "../datasets/fixtures/labels.jsonl",
        second_out,
        "--external-basename",
    )
    assert first == second
    report = json.loads(first[1])
    paths = {(item["role"], item["path"], item["external"]) for item in report["inputs"]}
    assert ("detections", "detections.jsonl", True) in paths
    assert ("labels", "datasets/fixtures/labels.jsonl", False) in paths
    assert ("rule", "rules/ADG-0001.yaml", False) in paths
    assert_no_absolute_paths(first[1].decode("utf-8"))
    printed = capsys.readouterr()
    assert "<outside repo>/metrics.json" in printed.out
    assert tmp_path.as_posix() not in printed.out + printed.err
    assert str(tmp_path) not in printed.out + printed.err


def copy_inputs(target: Path) -> tuple[str, str, str]:
    shutil.copytree(RULES_DIR, target / "rules")
    shutil.copytree(FIXTURE_TRACES, target / "data" / "traces")
    shutil.copy(FIXTURE_LABELS, target / "data" / "labels.jsonl")
    return "rules", "data/traces", "data/labels.jsonl"


def test_no_absolute_path_in_reports_from_a_directory_outside_the_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    rules, traces, labels = copy_inputs(work)
    monkeypatch.chdir(work)
    detections, metrics = scan_and_score(rules, traces, labels, work / "out", "--root", str(work))
    assert_no_absolute_paths(metrics.decode("utf-8"))
    for line in detections.decode("utf-8").splitlines():
        assert_no_absolute_paths(line)
    report = json.loads(metrics)
    assert all(not item["external"] for item in report["inputs"])
    assert {item["path"] for item in report["inputs"]} >= {
        "out/detections.jsonl",
        "rules/ADG-0001.yaml",
    }


def test_external_inputs_fail_closed_or_record_the_file_name_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    rules, traces, labels = (str(data / part) for part in copy_inputs(data))
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.chdir(root)
    out = tmp_path / "out"
    detections = out / "detections.jsonl"
    common = ["--root", str(root)]
    scan = ["scan", "--rules", rules, "--traces", traces, "--out", str(detections)]
    assert main([*common, *scan, "--fixtures", traces]) == 0
    score = [
        "metrics",
        "--rules",
        rules,
        "--traces",
        traces,
        "--detections",
        str(detections),
        "--labels",
        labels,
        "--out",
        str(out / "metrics.json"),
        "--fixtures",
        traces,
    ]
    capsys.readouterr()
    assert main([*common, *score]) == 1
    err = capsys.readouterr().err
    assert "outside the repository root" in err
    assert tmp_path.as_posix() not in err
    assert str(tmp_path) not in err
    assert not (out / "metrics.json").exists()

    assert main([*common, *score, "--external-basename"]) == 0
    text = (out / "metrics.json").read_text(encoding="utf-8")
    assert_no_absolute_paths(text)
    report = json.loads(text)
    assert all(item["external"] for item in report["inputs"])
    assert all("/" not in item["path"] for item in report["inputs"])


def test_os_error_names_only_a_safe_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    code = main(
        [
            "scan",
            "--rules",
            str(RULES_DIR),
            "--traces",
            str(FIXTURE_TRACES),
            "--out",
            str(blocker / "d.jsonl"),
            "--fixtures",
            str(FIXTURE_TRACES),
        ]
    )
    assert code == 1
    err = capsys.readouterr().err
    assert err.splitlines()[-1].startswith("error: <outside repo>/file: ")
    assert tmp_path.as_posix() not in err
    assert str(tmp_path) not in err
