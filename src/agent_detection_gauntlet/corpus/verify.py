"""Check a built corpus against its split manifest.

Fails when a heldout file or the labels file no longer matches its recorded sha256,
when a label's split disagrees with its group's split, when a group's traces sit on
both sides, or (with `frozen`) when the manifest differs from the frozen one. CI passes
the manifest as it was in the freeze commit, so any later change to the split, the
heldout data or the labels fails the build.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from agent_detection_gauntlet.corpus.build import (
    LABELS,
    MANIFEST,
    CorpusError,
    group_of,
    read_manifest,
)
from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.io.labels import load_labels
from agent_detection_gauntlet.io.traces import load_traces
from agent_detection_gauntlet.schema.labels import Split


def verify(corpus: Path, frozen: bytes | None = None) -> list[str]:
    """Problems found; empty when the corpus matches its manifest."""
    problems: list[str] = []
    manifest = read_manifest(corpus)
    if frozen is not None and (corpus / MANIFEST).read_bytes() != frozen:
        problems.append(f"{MANIFEST} changed after the freeze commit")
    files = manifest.get("files", {})
    for rel, digest in sorted(files.items()):
        path = corpus / rel
        if not path.is_file():
            problems.append(f"{rel}: missing")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            problems.append(f"{rel}: sha256 differs from {MANIFEST}")
    heldout_files = {p.relative_to(corpus).as_posix() for p in (corpus / "heldout").rglob("*")}
    unlisted = sorted(f for f in heldout_files if f not in files and (corpus / f).is_file())
    problems.extend(f"{f}: heldout file not in {MANIFEST}" for f in unlisted)
    if LABELS not in files:
        problems.append(f"{MANIFEST} does not pin {LABELS}")

    groups = manifest.get("groups", {})
    labels = load_labels([corpus / LABELS])
    for label in labels.values():
        group = group_of(label)
        expected = groups.get(group, {}).get("split")
        if label.split is None or label.split.value != expected:
            problems.append(
                f"trace {label.trace_id}: split {label.split} but group {group} is {expected}"
            )
    heldout = sorted(g for g, info in groups.items() if info.get("split") == Split.HELDOUT.value)
    if heldout != manifest.get("heldout_groups"):
        problems.append("heldout_groups does not match the per-group splits")

    for split in Split:
        for k in manifest.get("content_ref_k", []):
            path = corpus / split.value / f"k{k}" / "traces.jsonl"
            if not path.is_file() or not path.read_bytes():
                continue
            try:
                ids = set(load_traces([path]).trace_ids())
            except GauntletError as exc:
                problems.append(f"{split.value}/k{k}: unreadable: {exc}")
                continue
            wrong = sorted(t for t in ids if t not in labels or labels[t].split is not split)
            if wrong:
                problems.append(
                    f"{split.value}/k{k}: traces labeled for another split: {wrong[:3]}"
                )
            missing = sorted(t for t, x in labels.items() if x.split is split and t not in ids)
            if missing:
                problems.append(f"{split.value}/k{k}: labeled traces missing: {missing[:3]}")
    return problems


def require_valid(corpus: Path, frozen: bytes | None = None) -> None:
    problems = verify(corpus, frozen)
    if problems:
        raise CorpusError("corpus does not verify:\n  " + "\n  ".join(problems))
