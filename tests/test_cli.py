from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from agent_detection_gauntlet.cli import main
from agent_detection_gauntlet.schema.export import export_schemas, schema_drift
from tests.conftest import FIXTURE_LABELS, FIXTURE_TRACES, PLUMBING_RULES, REPO_ROOT

SCHEMAS_DIR = REPO_ROOT / "schemas"


def run_pipeline(out: Path) -> tuple[bytes, bytes]:
    """validate, scan and score the repository fixtures into ``out``."""
    detections = out / "detections.jsonl"
    metrics = out / "metrics.json"
    fixtures = ["--fixtures", str(FIXTURE_TRACES)]
    assert main(["validate-traces", str(FIXTURE_TRACES)]) == 0
    assert main(["validate-rules", str(PLUMBING_RULES), *fixtures]) == 0
    assert (
        main(
            [
                "scan",
                "--rules",
                str(PLUMBING_RULES),
                "--traces",
                str(FIXTURE_TRACES),
                "--out",
                str(detections),
                *fixtures,
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "metrics",
                "--rules",
                str(PLUMBING_RULES),
                "--traces",
                str(FIXTURE_TRACES),
                "--detections",
                str(detections),
                "--labels",
                str(FIXTURE_LABELS),
                "--out",
                str(metrics),
                "--external-basename",
                *fixtures,
            ]
        )
        == 0
    )
    return detections.read_bytes(), metrics.read_bytes()


def test_full_path_from_traces_to_metrics(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    detections, metrics = run_pipeline(tmp_path)
    lines = detections.decode().splitlines()
    assert len(lines) >= 1
    assert {json.loads(line)["rule_id"] for line in lines} == {"ADG-0001"}
    report = json.loads(metrics)
    assert report["split"] == "heldout"
    assert report["schema_version"] == "0.3"
    assert [rule["id"] for rule in report["rules"]] == ["ADG-0001"]
    roles = {item["role"] for item in report["inputs"]}
    assert roles == {"rule", "trace", "detections", "labels"}
    assert "timestamp" not in metrics.decode().lower().replace("_timestamp", "")
    out = capsys.readouterr()
    assert "ok: 86 events in 10 traces" in out.out
    assert "not yet verified" in out.err


def test_scan_and_metrics_are_byte_identical_across_runs(tmp_path: Path) -> None:
    first = run_pipeline(tmp_path)
    copies = tmp_path / "first"
    copies.mkdir()
    for name in ("detections.jsonl", "metrics.json"):
        shutil.copy(tmp_path / name, copies / name)
    second = run_pipeline(tmp_path)
    assert first == second
    assert (copies / "metrics.json").read_bytes() == (tmp_path / "metrics.json").read_bytes()


def test_dev_split_flag(tmp_path: Path) -> None:
    run_pipeline(tmp_path)
    out = tmp_path / "dev.json"
    code = main(
        [
            "metrics",
            "--rules",
            str(PLUMBING_RULES),
            "--traces",
            str(FIXTURE_TRACES),
            "--detections",
            str(tmp_path / "detections.jsonl"),
            "--labels",
            str(FIXTURE_LABELS),
            "--split",
            "dev",
            "--external-basename",
            "--out",
            str(out),
            "--fixtures",
            str(FIXTURE_TRACES),
        ]
    )
    assert code == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["split"] == "dev"
    assert report["population"]["traces"] == 4


def test_checked_in_schemas_match_models() -> None:
    assert schema_drift(SCHEMAS_DIR) == []
    assert main(["export-schemas", "--check", "--out", str(SCHEMAS_DIR)]) == 0


def test_export_and_drift_detection(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "schemas"
    assert main(["export-schemas", "--out", str(target)]) == 0
    assert schema_drift(target) == []
    (target / "rule.schema.json").write_text("{}\n", encoding="utf-8")
    (target / "extra.json").write_text("{}\n", encoding="utf-8")
    (target / "label.schema.json").unlink()
    assert schema_drift(target) == ["extra.json", "label.schema.json", "rule.schema.json"]
    assert main(["export-schemas", "--check", "--out", str(target)]) == 1
    assert "out of date" in capsys.readouterr().err
    assert len(export_schemas(target)) == 7


def test_errors_exit_non_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"schema_version": "0.1"\n', encoding="utf-8")
    assert main(["validate-traces", str(bad)]) == 1
    err = capsys.readouterr().err
    assert "<outside repo>/bad.jsonl:1: malformed JSON" in err
    assert tmp_path.as_posix() not in err

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "ADG-0001.yaml").write_text(
        (PLUMBING_RULES / "ADG-0001.yaml")
        .read_text(encoding="utf-8")
        .replace("syn-0003", "syn-9999"),
        encoding="utf-8",
    )
    fixtures = ["--fixtures", str(FIXTURE_TRACES)]
    assert main(["validate-rules", str(rules), *fixtures]) == 1
    assert "syn-9999" in capsys.readouterr().err
    code = main(
        [
            "scan",
            "--rules",
            str(rules),
            "--traces",
            str(FIXTURE_TRACES),
            "--out",
            str(tmp_path / "d.jsonl"),
            *fixtures,
        ]
    )
    assert code == 1
    assert "rule validation failed with 1 error(s)" in capsys.readouterr().err


def test_metrics_rejects_mismatched_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_pipeline(tmp_path)
    labels = tmp_path / "labels.jsonl"
    labels.write_text(
        "".join(
            line + "\n"
            for line in FIXTURE_LABELS.read_text(encoding="utf-8").splitlines()
            if "syn-0009" not in line
        ),
        encoding="utf-8",
    )
    code = main(
        [
            "metrics",
            "--rules",
            str(PLUMBING_RULES),
            "--traces",
            str(FIXTURE_TRACES),
            "--detections",
            str(tmp_path / "detections.jsonl"),
            "--labels",
            str(labels),
            "--out",
            str(tmp_path / "m.json"),
            "--external-basename",
            "--fixtures",
            str(FIXTURE_TRACES),
        ]
    )
    assert code == 1
    assert "traces without a label: ['syn-0009']" in capsys.readouterr().err


def test_missing_output_directory_is_created(tmp_path: Path) -> None:
    out = tmp_path / "a" / "b" / "d.jsonl"
    code = main(
        [
            "scan",
            "--rules",
            str(PLUMBING_RULES),
            "--traces",
            str(FIXTURE_TRACES),
            "--out",
            str(out),
            "--fixtures",
            str(FIXTURE_TRACES),
        ]
    )
    assert code == 0
    assert out.is_file()


def test_os_error_is_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    code = main(
        [
            "scan",
            "--rules",
            str(PLUMBING_RULES),
            "--traces",
            str(FIXTURE_TRACES),
            "--out",
            str(blocker / "d.jsonl"),
            "--fixtures",
            str(FIXTURE_TRACES),
        ]
    )
    assert code == 1
    lines = capsys.readouterr().err.splitlines()
    assert any(line.startswith("error:") for line in lines)


def test_console_entry_point_runs_as_module() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "agent_detection_gauntlet", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "gauntlet 0.1.0"


def test_metrics_rejects_partial_or_empty_detections(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_pipeline(tmp_path)
    full = (tmp_path / "detections.jsonl").read_text(encoding="utf-8").splitlines()
    for name, lines in (("partial.jsonl", full[:1]), ("empty.jsonl", [])):
        path = tmp_path / name
        path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
        code = main(
            [
                "metrics",
                "--rules",
                str(PLUMBING_RULES),
                "--traces",
                str(FIXTURE_TRACES),
                "--detections",
                str(path),
                "--labels",
                str(FIXTURE_LABELS),
                "--out",
                str(tmp_path / "m.json"),
                "--external-basename",
                "--fixtures",
                str(FIXTURE_TRACES),
            ]
        )
        assert code == 1
        assert "does not match a scan" in capsys.readouterr().err
