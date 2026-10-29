"""Turn exporter output into the frozen corpus: dedupe, split by variant group, manifest.

Inputs are export directories as the source repositories write them: `labels.jsonl`,
`export_manifest.json` and `k<K>/traces/*.jsonl` for each content-reference K.

- **Dedupe.** Traces are hashed on the K=24 version (`hashing.content_hash`). Traces
  with equal hashes and equal labels (run ids aside) are one unique trace; the smallest
  trace id is kept. `raw_index.jsonl` maps every raw run to the trace kept for it, so
  raw counts stay reportable.
- **Split.** Whole variant groups go to dev or heldout, never part of a group. Groups
  are stratified by class and by whether the group's attack succeeded at baseline, and
  ordered by sha256 of `salt + group id`; the first `round(0.3 n)` of each stratum are
  heldout. A succeeding class with at least four successful groups holds out at least
  two of them, so heldout can measure recall on every class that succeeds.
- **Manifest.** `SPLIT_MANIFEST.json` records the salt, every group's split, the
  ineffective and below-floor classes (with their notes), the sources, and the sha256
  of every heldout
  file and of the
  labels file. `verify.py` checks it; CI refuses any change after the freeze commit.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_detection_gauntlet.corpus.hashing import IGNORED_ATTRIBUTES, IGNORED_FIELDS, content_hash
from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.io.jsonl import (
    canonical_json,
    pretty_json,
    strict_json_loads,
    write_text,
)
from agent_detection_gauntlet.io.labels import load_labels
from agent_detection_gauntlet.io.traces import load_traces
from agent_detection_gauntlet.paths import shown_path
from agent_detection_gauntlet.schema.labels import LabelRecord, Split, Verdict

MANIFEST = "SPLIT_MANIFEST.json"
LABELS = "labels.jsonl"
RAW_INDEX = "raw_index.jsonl"
HASH_K = 24
HELDOUT_FRACTION = 0.3
MIN_HELDOUT_SUCCESSFUL = 2
MIN_GROUPS_FOR_FLOOR = 4
BASELINE = "baseline"
BENIGN_CLASS = "benign"
# Attributes removed from corpus traces. The per-run seed is base seed plus run index, and
# sources ran different numbers of runs, so its value would hint at the label. Its range per
# source is kept in the manifest instead.
STRIPPED_ATTRIBUTES: tuple[str, ...] = ("gen_ai.request.seed",)
# Label fields that name the run, not what happened in it; dedupe ignores them.
RUN_FIELDS: tuple[str, ...] = ("trace_id", "source_run_id", "split")


class CorpusError(GauntletError):
    """The corpus cannot be built or does not verify."""


@dataclass(frozen=True)
class Source:
    path: Path
    manifest: dict[str, Any]
    labels: dict[str, LabelRecord]
    lines: dict[int, dict[str, list[str]]]  # K -> trace id -> raw lines in file order
    hashes: dict[str, str]  # trace id -> content hash (K=24)


def _raw_lines(directory: Path) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for file in sorted(directory.glob("*.jsonl")):
        for line in file.read_text(encoding="utf-8").splitlines():
            grouped.setdefault(strict_json_loads(line)["trace_id"], []).append(line)
    return grouped


def _strip(line: str) -> str:
    event = strict_json_loads(line)
    attributes = event.get("attributes", {})
    if not any(name in attributes for name in STRIPPED_ATTRIBUTES):
        return line
    for name in STRIPPED_ATTRIBUTES:
        attributes.pop(name, None)
    return canonical_json(event)


def _seed_range(source: Source) -> list[int] | None:
    seeds = [
        attributes["gen_ai.request.seed"]
        for lines in source.lines[HASH_K].values()
        for attributes in (strict_json_loads(x).get("attributes", {}) for x in lines)
        if isinstance(attributes.get("gen_ai.request.seed"), int)
    ]
    return [min(seeds), max(seeds)] if seeds else None


def load_source(path: Path) -> Source:
    manifest_path = path / "export_manifest.json"
    if not manifest_path.is_file():
        raise CorpusError(f"{shown_path(path)}: not an export (no export_manifest.json)")
    manifest = strict_json_loads(manifest_path.read_text(encoding="utf-8"))
    ks = manifest.get("content_ref_k")
    if not isinstance(ks, list) or HASH_K not in ks:
        raise CorpusError(f"{shown_path(path)}: export must include K={HASH_K}")
    labels = load_labels([path / LABELS])
    lines = {int(k): _raw_lines(path / f"k{k}" / "traces") for k in ks}
    traces = load_traces([path / f"k{HASH_K}" / "traces"])
    hashes = {t.trace_id: content_hash(t.events) for t in traces.traces}
    for k, by_trace in lines.items():
        if set(by_trace) != set(labels):
            raise CorpusError(f"{shown_path(path)}: k{k} traces and labels name different runs")
    return Source(path, manifest, labels, lines, hashes)


def _label_key(label: LabelRecord) -> str:
    data = label.model_dump(mode="json")
    return canonical_json({k: v for k, v in data.items() if k not in RUN_FIELDS})


def class_of(label: LabelRecord) -> str:
    return label.attack_class if label.attack_class is not None else BENIGN_CLASS


def group_of(label: LabelRecord) -> str:
    if label.variant_group is None:
        raise CorpusError(f"trace {label.trace_id}: label has no variant_group (schema 0.3)")
    return label.variant_group


def _round_half_up(value: float) -> int:
    return int(value + 0.5)


def heldout_count(n: int, *, succeeding_stratum: bool) -> int:
    count = _round_half_up(HELDOUT_FRACTION * n)
    if succeeding_stratum and n >= MIN_GROUPS_FOR_FLOOR:
        count = max(count, MIN_HELDOUT_SUCCESSFUL)
    return count


def group_rank(salt: str, group: str) -> str:
    return hashlib.sha256(f"{salt}\x1f{group}".encode()).hexdigest()


@dataclass
class GroupInfo:
    cls: str
    succeeded: bool  # any baseline trace of the group is an oracle-confirmed success
    split: Split = Split.DEV
    traces: list[str] = field(default_factory=list)


def assign_splits(labels: Sequence[LabelRecord], salt: str) -> dict[str, GroupInfo]:
    groups: dict[str, GroupInfo] = {}
    for label in labels:
        group = group_of(label)
        info = groups.setdefault(group, GroupInfo(class_of(label), False))
        if info.cls != class_of(label):
            raise CorpusError(f"group {group} spans classes {info.cls} and {class_of(label)}")
        if label.label is Verdict.MALICIOUS and label.condition == BASELINE:
            info.succeeded = info.succeeded or bool(label.attack_succeeded)
        info.traces.append(label.trace_id)
    strata: dict[tuple[str, bool], list[str]] = {}
    for group, info in groups.items():
        strata.setdefault((info.cls, info.succeeded), []).append(group)
    for (_, succeeded), members in strata.items():
        ranked = sorted(members, key=lambda g: (group_rank(salt, g), g))
        for group in ranked[: heldout_count(len(ranked), succeeding_stratum=succeeded)]:
            groups[group].split = Split.HELDOUT
    return groups


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _clear(out: Path) -> None:
    """Remove only what a previous build wrote."""
    if not out.exists():
        return
    if any(out.iterdir()) and not (out / MANIFEST).is_file():
        raise CorpusError(f"{shown_path(out)} exists and is not a corpus; choose another --out")
    for name in ("dev", "heldout"):
        shutil.rmtree(out / name, ignore_errors=True)
    for name in (LABELS, RAW_INDEX, MANIFEST):
        (out / name).unlink(missing_ok=True)


@dataclass(frozen=True)
class BuildSummary:
    raw: int
    unique: int
    groups: int
    heldout_groups: int


# Why a class that succeeds at baseline still has fewer successful groups than the floor.
# Different findings, so the corpus names them differently.
BELOW_FLOOR_STATUSES: dict[str, str] = {
    "low-success": "the attack resists this model: few inputs succeed",
    "underpowered": "the seeding method could not preserve the attack's structure",
}


def read_notes(path: Path | None) -> dict[str, Any]:
    """Corpus notes: a status and finding per below-floor class, and extra known gaps."""
    if path is None:
        return {"classes": {}, "known_gaps": []}
    data = strict_json_loads(path.read_text(encoding="utf-8"))
    classes = data.get("classes", {}) if isinstance(data, dict) else None
    gaps = data.get("known_gaps", []) if isinstance(data, dict) else None
    if not isinstance(classes, dict) or not isinstance(gaps, list):
        raise CorpusError(f"{shown_path(path)}: needs a 'classes' object and a 'known_gaps' list")
    for cls, note in classes.items():
        if not isinstance(note, dict) or note.get("status") not in BELOW_FLOOR_STATUSES:
            raise CorpusError(f"{cls}: status must be one of {sorted(BELOW_FLOOR_STATUSES)}")
        if not isinstance(note.get("finding"), str) or not note["finding"].strip():
            raise CorpusError(f"{cls}: a note needs its finding")
    if not all(isinstance(g, str) and g.strip() for g in gaps):
        raise CorpusError("known_gaps entries must be non-empty strings")
    return {"classes": classes, "known_gaps": gaps}


def build(
    sources: Sequence[Path], out: Path, salt: str, notes_path: Path | None = None
) -> BuildSummary:
    notes = read_notes(notes_path)
    loaded = [load_source(path) for path in sources]
    ks = sorted(loaded[0].lines)
    if any(sorted(s.lines) != ks for s in loaded):
        raise CorpusError("every source must export the same K values")

    kept: dict[tuple[str, str], tuple[str, Source]] = {}  # (hash, label key) -> trace
    raw_index: list[dict[str, str]] = []
    for source in loaded:
        for trace_id in sorted(source.labels):
            label = source.labels[trace_id]
            key = (source.hashes[trace_id], _label_key(label))
            if key not in kept or trace_id < kept[key][0]:
                kept[key] = (trace_id, source)
    representative = {key: trace_id for key, (trace_id, _) in kept.items()}
    for source in loaded:
        for trace_id, label in sorted(source.labels.items()):
            key = (source.hashes[trace_id], _label_key(label))
            raw_index.append(
                {
                    "source_run_id": label.source_run_id or trace_id,
                    "trace_id": trace_id,
                    "kept_as": representative[key],
                }
            )
    if len({r["source_run_id"] for r in raw_index}) != len(raw_index):
        raise CorpusError("two sources export the same source_run_id")

    unique = {trace_id: source for trace_id, source in kept.values()}
    labels = [unique[t].labels[t] for t in sorted(unique)]
    groups = assign_splits(labels, salt)

    _clear(out)
    final = [label.model_copy(update={"split": groups[group_of(label)].split}) for label in labels]
    write_text(
        out / LABELS,
        "".join(canonical_json(x.model_dump(mode="json")) + "\n" for x in final),
    )
    write_text(
        out / RAW_INDEX,
        "".join(canonical_json(r) + "\n" for r in sorted(raw_index, key=canonical_json)),
    )
    files: dict[str, str] = {LABELS: _sha256(out / LABELS)}
    for split in Split:
        members = sorted(x.trace_id for x in final if x.split is split)
        for k in ks:
            rel = f"{split.value}/k{k}/traces.jsonl"
            body = "".join(_strip(line) + "\n" for t in members for line in unique[t].lines[k][t])
            write_text(out / rel, body)
            if split is Split.HELDOUT:
                files[rel] = _sha256(out / rel)

    succeeding = {g.cls for g in groups.values() if g.succeeded}
    below_floor = sorted(
        c
        for c in succeeding
        if sum(1 for g in groups.values() if g.cls == c and g.succeeded) < MIN_GROUPS_FOR_FLOOR
    )
    noted = set(notes["classes"])
    if noted != set(below_floor):
        raise CorpusError(
            f"below-floor classes {below_floor} and noted classes {sorted(noted)} must match"
        )
    attack_classes = {g.cls for g in groups.values() if g.cls != BENIGN_CLASS}
    manifest = {
        "manifest_version": 1,
        "salt": salt,
        "heldout_fraction": HELDOUT_FRACTION,
        "min_heldout_successful_groups": MIN_HELDOUT_SUCCESSFUL,
        "content_hash": {
            "k": HASH_K,
            "ignored_fields": list(IGNORED_FIELDS),
            "ignored_attributes": list(IGNORED_ATTRIBUTES),
        },
        "content_ref_k": ks,
        "ineffective_classes": sorted(attack_classes - succeeding),
        # Succeeds at baseline, but with fewer distinct successful groups than the floor:
        # included and labeled, too few heldout groups for a per-class estimate. Each needs a
        # note saying why (BELOW_FLOOR_STATUSES).
        "below_floor_classes": below_floor,
        "notes": notes,
        "groups": {
            group: {"class": info.cls, "split": info.split.value, "succeeded": info.succeeded}
            for group, info in sorted(groups.items())
        },
        "heldout_groups": sorted(g for g, i in groups.items() if i.split is Split.HELDOUT),
        "files": files,
        "stripped_attributes": list(STRIPPED_ATTRIBUTES),
        "sources": [
            {**{k: v for k, v in s.manifest.items() if k != "files"}, "seeds": _seed_range(s)}
            for s in loaded
        ],
    }
    write_text(out / MANIFEST, pretty_json(manifest))
    return BuildSummary(
        len(raw_index),
        len(final),
        len(groups),
        len(manifest["heldout_groups"]),  # type: ignore[arg-type]
    )


def read_manifest(corpus: Path) -> dict[str, Any]:
    path = corpus / MANIFEST
    if not path.is_file():
        raise CorpusError(f"{shown_path(corpus)}: no {MANIFEST}")
    data = strict_json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise CorpusError(f"{MANIFEST} must be an object")
    return data


def read_jsonl_dicts(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
