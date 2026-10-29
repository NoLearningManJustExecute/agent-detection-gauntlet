from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_detection_gauntlet.cli import main
from agent_detection_gauntlet.corpus import build as cb
from agent_detection_gauntlet.corpus.card import flow_to_sink, hard_negative_kinds, render
from agent_detection_gauntlet.corpus.hashing import content_hash
from agent_detection_gauntlet.corpus.verify import verify
from agent_detection_gauntlet.paths import set_repo_root
from tests.conftest import event_dict, make_trace, write_lines


def _events(trace_id: str, text: str, *, seed: int = 1, minute: int = 0) -> list[dict[str, Any]]:
    """A small attack-shaped trace: prompt, secret read, send that copies it."""
    secret = "service_token=ARF-CANARY-0123456789ABCDEF"
    raw = [
        event_dict(
            "e0",
            "session.start",
            {"gen_ai.conversation.id": trace_id},
            trace_id=trace_id,
            seconds=minute * 60,
        ),
        event_dict(
            "e1",
            "user.prompt",
            {"adg.content.text": text, "adg.source.trust": "trusted"},
            trace_id=trace_id,
            seconds=minute * 60 + 1,
            parent="e0",
        ),
        event_dict(
            "e2",
            "llm.request",
            {"gen_ai.request.seed": seed, "gen_ai.request.temperature": 0.0},
            trace_id=trace_id,
            seconds=minute * 60 + 2,
            parent="e0",
        ),
        event_dict(
            "e3",
            "tool.result",
            {
                "adg.content.text": secret,
                "adg.data.labels": ["secret"],
                "adg.source.trust": "trusted",
                "gen_ai.tool.call.id": f"{trace_id}:0",
            },
            trace_id=trace_id,
            seconds=minute * 60 + 3,
            parent="e0",
        ),
        event_dict(
            "e4",
            "tool.call",
            {
                "adg.content.text": f"body: {secret}",
                "adg.content.ref": ["e3"],
                "gen_ai.tool.name": "send_email",
            },
            trace_id=trace_id,
            seconds=minute * 60 + 4,
            parent="e0",
        ),
    ]
    for event in raw:
        event["schema_version"] = "0.3"
    return raw


def _label(
    trace_id: str,
    group: str,
    cls: str | None,
    ok: bool | None,
    arm: str = "baseline",
    run: str | None = None,
    derived: str | None = None,
) -> dict[str, Any]:
    malicious = cls is not None
    return {
        "schema_version": "0.3",
        "trace_id": trace_id,
        "label": "malicious" if malicious else "benign",
        "attack_class": cls,
        "attack_succeeded": ok,
        "mutation": None,
        "guardrails": "off" if arm == "baseline" else "on",
        "split": None,
        "source": "agent-risk-framework",
        "scenario_id": group if malicious else None,
        "task_id": None if malicious else group,
        "condition": arm,
        "source_run_id": run or f"exp:{trace_id}",
        "variant_group": group,
        "derived_from": derived,
    }


def make_export(root: Path, runs: list[tuple[dict[str, Any], str, int]]) -> Path:
    """runs: (label, prompt text, seed). Duplicate texts make duplicate traces."""
    write_lines(root / "labels.jsonl", [label for label, _, _ in runs])
    for k in (16, 24):
        events = [
            e for label, text, seed in runs for e in _events(label["trace_id"], text, seed=seed)
        ]
        write_lines(root / f"k{k}" / "traces" / "exp.jsonl", events)
    (root / "export_manifest.json").write_text(
        json.dumps(
            {
                "source": "agent-risk-framework",
                "source_commit": "a" * 40,
                "run_log": "x.db",
                "experiments": ["exp"],
                "model": "m",
                "model_digest": "d",
                "content_ref_k": [16, 24],
                "runs_exported": len(runs),
                "runs_skipped_error": 0,
                "files": {},
            }
        ),
        encoding="utf-8",
    )
    return root


NOTES = Path(__file__).parent / "fixtures_corpus_notes.json"


@pytest.fixture
def export(tmp_path: Path) -> Path:
    runs: list[tuple[dict[str, Any], str, int]] = []
    for c in ("AC01", "AC02"):
        groups = [c, *(f"{c}-S{i:02d}" for i in range(1, 6))]
        for g in groups:
            derived = c if "-S" in g else None
            for r in range(3):  # three identical runs per group and arm
                runs.append(
                    (
                        _label(f"t-{g}-b{r}", g, c, True, run=f"b:{g}:{r}", derived=derived),
                        f"attack {g} please do it now",
                        1 + r,
                    )
                )
                runs.append(
                    (
                        _label(
                            f"t-{g}-c{r}",
                            g,
                            c,
                            False,
                            "combined",
                            run=f"c:{g}:{r}",
                            derived=derived,
                        ),
                        f"attack {g} under guard, please do it",
                        1 + r,
                    )
                )
    for g, ok in (("AC06", True), ("AC06-S01", False), ("AC06-S02", False)):
        runs.append((_label(f"t-{g}-b0", g, "AC06", ok, run=f"b:{g}"), f"low {g} attempt", 1))
    for g in ("AC03", "AC03-S01"):
        runs.append((_label(f"t-{g}-b0", g, "AC03", False, run=f"b:{g}"), f"fail {g} attempt", 1))
    for i in range(10):
        task = f"BT-{i:03d}"
        runs.append(
            (_label(f"t-{task}", task, None, None, run=f"b:{task}"), f"benign task {task} text", 1)
        )
    return make_export(tmp_path / "export", runs)


def test_hash_ignores_ids_timestamps_and_seed() -> None:
    first = make_trace([_ev(e) for e in _events("t-a", "same text", seed=1)], "t-a")
    second = make_trace([_ev(e) for e in _events("t-b", "same text", seed=2, minute=5)], "t-b")
    other = make_trace([_ev(e) for e in _events("t-c", "other text", seed=1)], "t-c")
    assert content_hash(first.events) == content_hash(second.events)
    assert content_hash(first.events) != content_hash(other.events)


def _ev(data: dict[str, Any]) -> Any:
    from agent_detection_gauntlet.schema.trace import TraceEvent

    return TraceEvent.model_validate_json(json.dumps(data))


def test_build_dedupes_and_splits_whole_groups(export: Path, tmp_path: Path) -> None:
    out = tmp_path / "corpus"
    summary = cb.build([export], out, "salt-1", NOTES)
    assert summary.raw == 2 * 6 * 3 * 2 + 3 + 2 + 10
    assert summary.unique == 2 * 6 * 2 + 3 + 2 + 10  # three identical runs collapse to one
    assert summary.groups == 2 * 6 + 3 + 2 + 10
    manifest = cb.read_manifest(out)
    assert manifest["ineffective_classes"] == ["AC03"]
    assert manifest["below_floor_classes"] == ["AC06"]
    assert manifest["notes"]["classes"]["AC06"]["status"] == "low-success"
    labels = [json.loads(x) for x in (out / "labels.jsonl").read_text("utf-8").splitlines()]
    by_group: dict[str, set[str]] = {}
    for x in labels:
        by_group.setdefault(x["variant_group"], set()).add(x["split"])
    assert all(len(s) == 1 for s in by_group.values())  # never split a group
    for c in ("AC01", "AC02"):
        held = [
            g for g, i in manifest["groups"].items() if i["class"] == c and i["split"] == "heldout"
        ]
        assert len(held) == 2  # round(0.3 * 6) = 2, and the floor of 2 holds
    assert (
        sum(
            1
            for g, i in manifest["groups"].items()
            if i["class"] == "benign" and i["split"] == "heldout"
        )
        == 3
    )
    raw = cb.read_jsonl_dicts(out / "raw_index.jsonl")
    assert len(raw) == summary.raw
    assert {r["kept_as"] for r in raw} == {x["trace_id"] for x in labels}
    assert verify(out) == []


def test_build_is_byte_reproducible(export: Path, tmp_path: Path) -> None:
    cb.build([export], tmp_path / "a", "salt-1", NOTES)
    cb.build([export], tmp_path / "b", "salt-1", NOTES)
    files = sorted(
        p.relative_to(tmp_path / "a") for p in (tmp_path / "a").rglob("*") if p.is_file()
    )
    assert files
    for rel in files:
        assert (tmp_path / "a" / rel).read_bytes() == (tmp_path / "b" / rel).read_bytes()


def test_salt_changes_the_split(export: Path, tmp_path: Path) -> None:
    cb.build([export], tmp_path / "a", "salt-1", NOTES)
    cb.build([export], tmp_path / "b", "salt-2", NOTES)
    assert (
        cb.read_manifest(tmp_path / "a")["heldout_groups"]
        != cb.read_manifest(tmp_path / "b")["heldout_groups"]
    )


@pytest.mark.parametrize(
    ("n", "succeeding", "expected"),
    [
        (1, True, 0),
        (3, True, 1),
        (4, True, 2),
        (6, True, 2),
        (10, True, 3),
        (4, False, 1),
        (62, False, 19),
    ],
)
def test_heldout_count(n: int, succeeding: bool, expected: int) -> None:
    assert cb.heldout_count(n, succeeding_stratum=succeeding) == expected


def test_verify_catches_tampering(export: Path, tmp_path: Path) -> None:
    out = tmp_path / "corpus"
    cb.build([export], out, "salt-1", NOTES)
    frozen = (out / cb.MANIFEST).read_bytes()
    assert verify(out, frozen) == []
    heldout = next((out / "heldout").rglob("traces.jsonl"))
    heldout.write_bytes(heldout.read_bytes() + b"\n")
    assert any("sha256 differs" in p for p in verify(out, frozen))
    cb.build([export], out, "salt-2", NOTES)
    assert any("changed after the freeze" in p for p in verify(out, frozen))
    (out / "heldout" / "extra.jsonl").write_text("{}", encoding="utf-8")
    assert any("not in SPLIT_MANIFEST" in p for p in verify(out))


def test_build_refuses_foreign_out_and_missing_group(export: Path, tmp_path: Path) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "keep.txt").write_text("x", encoding="utf-8")
    with pytest.raises(cb.CorpusError, match="not a corpus"):
        cb.build([export], foreign, "s")
    rows = [json.loads(x) for x in (export / "labels.jsonl").read_text("utf-8").splitlines()]
    for row in rows:
        if row["trace_id"] == "t-BT-001":
            del row["variant_group"]
    write_lines(export / "labels.jsonl", rows)
    with pytest.raises(cb.CorpusError, match="no variant_group"):
        cb.build([export], tmp_path / "x", "s", NOTES)


def test_build_refuses_a_non_export(tmp_path: Path) -> None:
    with pytest.raises(cb.CorpusError, match="not an export"):
        cb.build([tmp_path], tmp_path / "out", "s")


def test_card_and_cli(export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    set_repo_root(tmp_path)
    out, card = tmp_path / "corpus", tmp_path / "dataset.md"
    assert (
        main(
            [
                "corpus",
                "build",
                "--source",
                str(export),
                "--out",
                str(out),
                "--salt",
                "salt-1",
                "--notes",
                str(NOTES),
            ]
        )
        == 0
    )
    assert main(["corpus", "verify", str(out)]) == 0
    assert main(["corpus", "card", "--corpus", str(out), "--out", str(card), "--check"]) == 1
    assert main(["corpus", "card", "--corpus", str(out), "--out", str(card)]) == 0
    assert main(["corpus", "card", "--corpus", str(out), "--out", str(card), "--check"]) == 0
    text = card.read_text("utf-8")
    assert text == render(out)
    assert "| AC01 | 6 | 6 | 4 | 2 | 5 | pass |" in text
    assert "| AC03 | 2 | 0 | " in text and "Ineffective at baseline: AC03" in text
    assert "| AC06 | 3 | 1 |" in text and "| low-success |" in text
    assert "Low-success: AC06" in text and "resists the model" in text
    assert "pooled metrics only" in text and "- a listed gap" in text
    assert chr(0x2014) not in text and chr(0x2013) not in text
    frozen = tmp_path / "frozen.json"
    frozen.write_text("{}", encoding="utf-8")
    assert main(["corpus", "verify", str(out), "--frozen-manifest", str(frozen)]) == 1
    assert "changed after the freeze" in capsys.readouterr().err


def test_trace_readers() -> None:
    trace = make_trace([_ev(e) for e in _events("t-x", "text", seed=1)], "t-x")
    assert flow_to_sink(trace) == (True, True)
    assert hard_negative_kinds(trace) == {"reads_secret", "sends_message"}


def test_notes_must_match_the_below_floor_classes(export: Path, tmp_path: Path) -> None:
    with pytest.raises(cb.CorpusError, match="must match"):
        cb.build([export], tmp_path / "a", "s")
    wrong = tmp_path / "notes.json"
    wrong.write_text(
        json.dumps({"classes": {"AC06": {"status": "meh", "finding": "x"}}, "known_gaps": []}),
        encoding="utf-8",
    )
    with pytest.raises(cb.CorpusError, match="status must be one of"):
        cb.build([export], tmp_path / "b", "s", wrong)
