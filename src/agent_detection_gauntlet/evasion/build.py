"""Turn the source lab's export of the evasion runs into datasets/evasion, and check it.

Dedupe works as in the corpus. Labels carry split heldout and the mutation. The manifest pins every
file, so a later change to the traces or the inputs fails `gauntlet evasion verify`. Nothing here
prints trace content; the corpus is read for its content hashes only.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agent_detection_gauntlet.corpus.build import (
    HASH_K,
    LABELS,
    RAW_INDEX,
    Source,
    _label_key,
    _seed_range,
    _strip,
    load_source,
    read_jsonl_dicts,
)
from agent_detection_gauntlet.corpus.hashing import content_hash
from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.evasion.inputs import (
    check_inputs_file,
    normalized_payload,
    payload_of,
)
from agent_detection_gauntlet.evasion.model import Disjointness, EvasionPlan
from agent_detection_gauntlet.io.jsonl import (
    canonical_json,
    pretty_json,
    strict_json_loads,
    write_text,
)
from agent_detection_gauntlet.io.labels import load_labels
from agent_detection_gauntlet.io.traces import load_traces
from agent_detection_gauntlet.metrics.compute import sha256_file
from agent_detection_gauntlet.schema.labels import LabelRecord, Split
from agent_detection_gauntlet.validation.prereg import MANIFEST_FILE

MANIFEST = "EVASION_MANIFEST.json"
INPUTS_FILE = "mutated_scenarios.json"
PLAN_TRACES = "traces.jsonl"


def read_inputs_file(evasion: Path) -> dict[str, Any]:
    path = evasion / INPUTS_FILE
    if not path.is_file():
        raise GauntletError(f"{path.name} is missing; run `gauntlet evasion mutate` first")
    data = strict_json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise GauntletError(f"{path.name} must be an object")
    return data


def expected_inputs(plan: EvasionPlan, inputs: Mapping[str, Any]) -> set[str]:
    return {item["scenario_id"] for item in inputs["scenarios"]} | set(plan.attack_variants)


def _check_source(plan: EvasionPlan, source: Source, inputs: Mapping[str, Any]) -> None:
    manifest = source.manifest
    if manifest.get("source_commit") != plan.source_commit:
        raise GauntletError("the export ran from another source commit than the registered one")
    if (manifest.get("model"), manifest.get("model_digest")) != (plan.model, plan.model_digest):
        raise GauntletError("the export names another model than the registered one")
    if manifest.get("runs_skipped_unlisted"):
        raise GauntletError("the export skipped runs of unlisted scenarios")
    known = plan.payload_mutations + plan.attack_routes
    wrong = sorted(t for t, x in source.labels.items() if x.mutation not in known)
    if wrong:
        raise GauntletError(f"traces without a registered mutation: {wrong[:3]}")
    ran = {x.scenario_id or "" for x in source.labels.values()}
    expected = expected_inputs(plan, inputs)
    if ran != expected:
        raise GauntletError(f"the export and the inputs differ: {sorted(ran ^ expected)[:5]}")


def build_evasion(source_path: Path, out: Path, plan: EvasionPlan) -> tuple[int, int]:
    """Write labels, raw index and traces. Returns (raw runs, unique traces)."""
    source = load_source(source_path)
    inputs = read_inputs_file(out)
    _check_source(plan, source, inputs)

    kept: dict[tuple[str, str], str] = {}
    for trace_id in sorted(source.labels):
        key = (source.hashes[trace_id], _label_key(source.labels[trace_id]))
        kept.setdefault(key, trace_id)
    raw_index = [
        {
            "source_run_id": label.source_run_id or trace_id,
            "trace_id": trace_id,
            "kept_as": kept[(source.hashes[trace_id], _label_key(label))],
        }
        for trace_id, label in sorted(source.labels.items())
    ]
    unique = sorted(kept.values())
    labels = [source.labels[t].model_copy(update={"split": Split.HELDOUT}) for t in unique]
    write_text(
        out / LABELS,
        "".join(canonical_json(x.model_dump(mode="json")) + "\n" for x in labels),
    )
    write_text(
        out / RAW_INDEX,
        "".join(canonical_json(r) + "\n" for r in sorted(raw_index, key=canonical_json)),
    )
    files = {LABELS: sha256_file(out / LABELS), RAW_INDEX: sha256_file(out / RAW_INDEX)}
    files[INPUTS_FILE] = sha256_file(out / INPUTS_FILE)
    for k in plan.content_ref_ks:
        rel = f"k{k}/{PLAN_TRACES}"
        body = "".join(_strip(line) + "\n" for t in unique for line in source.lines[k][t])
        write_text(out / rel, body)
        files[rel] = sha256_file(out / rel)
    manifest = {
        "manifest_version": 1,
        "source": {
            **{k: v for k, v in source.manifest.items() if k != "files"},
            "seeds": _seed_range(source),
        },
        "plan_sha256": hashlib.sha256(
            pretty_json(plan.model_dump(mode="json")).encode("utf-8")
        ).hexdigest(),
        "files": files,
    }
    write_text(out / MANIFEST, pretty_json(manifest))
    return len(raw_index), len(unique)


def read_manifest(evasion: Path) -> dict[str, Any]:
    path = evasion / MANIFEST
    if not path.is_file():
        raise GauntletError(f"no {MANIFEST}; run `gauntlet evasion build` first")
    data = strict_json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise GauntletError(f"{MANIFEST} must be an object")
    return data


def _corpus_hashes(corpus: Path, k: int) -> set[str]:
    hashes: set[str] = set()
    for split in Split:
        traces = load_traces([corpus / split.value / f"k{k}"]).traces
        hashes |= {content_hash(trace.events) for trace in traces}
    return hashes


def disjointness(
    plan: EvasionPlan,
    corpus: Path,
    evasion: Path,
    corpus_labels: Mapping[str, LabelRecord],
    inputs: Mapping[str, Any],
) -> Disjointness:
    groups = strict_json_loads((corpus / MANIFEST_FILE).read_text(encoding="utf-8"))
    heldout = set(groups["heldout_groups"])
    corpus_hashes = _corpus_hashes(corpus, HASH_K)
    traces = load_traces([evasion / f"k{HASH_K}" / PLAN_TRACES]).traces
    bases = {name: normalized_payload(item["payload"]) for name, item in inputs["bases"].items()}
    payloads = {normalized_payload(payload_of(item)) for item in inputs["scenarios"]}
    return Disjointness(
        bases_outside_heldout=sorted(
            b.scenario_id for b in plan.bases if b.variant_group not in heldout
        ),
        inputs_matching_corpus_payloads=len(payloads & set(bases.values())),
        traces_matching_corpus_hashes=sum(
            content_hash(trace.events) in corpus_hashes for trace in traces
        ),
        corpus_labels_with_mutation=sum(x.mutation is not None for x in corpus_labels.values()),
        corpus_payloads_checked_at_generation=int(inputs["corpus_payloads_checked"]),
    )


def verify_evasion(plan: EvasionPlan, corpus: Path, evasion: Path) -> list[str]:
    """Problems found; empty when the inputs, traces and labels match the registration."""
    problems: list[str] = []
    inputs = read_inputs_file(evasion)
    problems += check_inputs_file(inputs, plan.bases)
    if inputs.get("source_commit") != plan.source_commit:
        problems.append(f"{INPUTS_FILE} names another source commit than the registered one")
    if not (evasion / MANIFEST).is_file():
        return problems
    manifest = read_manifest(evasion)
    expected = hashlib.sha256(pretty_json(plan.model_dump(mode="json")).encode("utf-8")).hexdigest()
    if manifest.get("plan_sha256") != expected:
        problems.append(f"{MANIFEST} was built under another registration")
    for rel, digest in sorted(manifest.get("files", {}).items()):
        path = evasion / rel
        if not path.is_file():
            problems.append(f"{rel}: missing")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            problems.append(f"{rel}: sha256 differs from {MANIFEST}")
    pinned = set(manifest.get("files", {}))
    present = {p.relative_to(evasion).as_posix() for p in evasion.rglob("*") if p.is_file()}
    problems += [f"{f}: not in {MANIFEST}" for f in sorted(present - pinned - {MANIFEST})]
    if problems:
        return problems
    labels = load_labels([evasion / LABELS])
    if {x.scenario_id for x in labels.values()} != expected_inputs(plan, inputs):
        problems.append("the labels and the registered inputs differ")
    for k in plan.content_ref_ks:
        ids = set(load_traces([evasion / f"k{k}" / PLAN_TRACES]).trace_ids())
        if ids != set(labels):
            problems.append(f"k{k}: traces and labels name different runs")
    raw = read_jsonl_dicts(evasion / RAW_INDEX)
    if {row["kept_as"] for row in raw} != set(labels):
        problems.append(f"{RAW_INDEX} and the labels name different traces")
    corpus_labels = load_labels([corpus / LABELS])
    found = disjointness(plan, corpus, evasion, corpus_labels, inputs)
    if found.bases_outside_heldout:
        problems.append(f"bases outside the held-out split: {found.bases_outside_heldout}")
    if found.inputs_matching_corpus_payloads:
        problems.append("an evasion input repeats the payload of its base")
    if found.traces_matching_corpus_hashes:
        problems.append("an evasion trace has the content hash of a corpus trace")
    if found.corpus_labels_with_mutation:
        problems.append("a corpus label carries a mutation")
    return problems
