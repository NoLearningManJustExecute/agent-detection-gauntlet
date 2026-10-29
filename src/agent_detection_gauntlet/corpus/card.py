"""Render docs/dataset.md from the corpus. Every number comes from the corpus files.

`gauntlet corpus card --check` fails when the committed card differs from what the
corpus produces, so the card cannot drift from the data it describes.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from agent_detection_gauntlet.corpus.build import (
    BENIGN_CLASS,
    HASH_K,
    LABELS,
    MIN_HELDOUT_SUCCESSFUL,
    RAW_INDEX,
    class_of,
    group_of,
    read_jsonl_dicts,
    read_manifest,
)
from agent_detection_gauntlet.io.labels import load_labels
from agent_detection_gauntlet.io.traces import load_traces
from agent_detection_gauntlet.metrics.stats import wilson_interval
from agent_detection_gauntlet.schema.labels import Split, Verdict
from agent_detection_gauntlet.schema.trace import Trace, TraceEvent

MIN_GROUPS = 4
MIN_HARD_NEGATIVE_TASKS = 5
SEEDING_TRANSFORMS = ("paraphrase", "translation")
RESERVED_FOR_EVASION = (
    "base64",
    "homoglyph",
    "unicode (zero-width, character spacing, confusables)",
    "prompt splitting",
    "indirect instruction",
    "retrieval poisoning",
    "tool indirection",
    "multi-stage",
)
HARD_NEGATIVE_KINDS = (
    ("reads_secret", "Reads the secret store"),
    ("sends_message", "Sends a message"),
    ("chains_tools", "Chains three or more tool calls"),
    ("fetches_untrusted", "Fetches untrusted content"),
)


def _table(header: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def _rate(num: int, den: int) -> str:
    if den == 0:
        return "null (0 runs)"
    interval = wilson_interval(num, den)
    assert interval is not None  # den > 0
    return f"{num}/{den} = {num / den:.2f} [{interval[0]:.2f}, {interval[1]:.2f}]"


def _tool_calls(trace: Trace) -> list[TraceEvent]:
    return [e for e in trace.events if e.event_type.value == "tool.call"]


def hard_negative_kinds(trace: Trace) -> set[str]:
    """Which hard-negative behaviors a benign trace shows, read from the trace itself."""
    kinds: set[str] = set()
    results = [e for e in trace.events if e.event_type.value == "tool.result"]
    calls = _tool_calls(trace)
    if any("secret" in (e.attributes.get("adg.data.labels") or []) for e in results):  # type: ignore[operator]
        kinds.add("reads_secret")
    if any(str(e.attributes.get("gen_ai.tool.name", "")).startswith("send_email") for e in calls):
        kinds.add("sends_message")
    if len(calls) >= 3:
        kinds.add("chains_tools")
    if any(e.attributes.get("adg.source.trust") == "untrusted" for e in results):
        kinds.add("fetches_untrusted")
    return kinds


def flow_to_sink(trace: Trace) -> tuple[bool, bool]:
    """(some tool call references earlier content, one traces back to untrusted or
    secret or pii content), following adg.content.ref transitively."""
    by_span = {e.span_id: e for e in trace.events}
    any_flow = tainted = False
    for call in _tool_calls(trace):
        seen: set[str] = set()
        stack = list(call.content_refs())
        any_flow = any_flow or bool(stack)
        while stack:
            span = stack.pop()
            if span in seen:
                continue
            seen.add(span)
            event = by_span[span]
            labels = event.attributes.get("adg.data.labels") or []
            if event.attributes.get("adg.source.trust") == "untrusted" or {"secret", "pii"} & set(
                labels  # type: ignore[arg-type]
            ):
                tainted = True
            stack.extend(event.content_refs())
    return any_flow, tainted


def _load_split_traces(corpus: Path, k: int) -> dict[str, Trace]:
    out: dict[str, Trace] = {}
    for split in Split:
        path = corpus / split.value / f"k{k}" / "traces.jsonl"
        if path.is_file() and path.read_bytes():
            out.update({t.trace_id: t for t in load_traces([path]).traces})
    return out


def render(corpus: Path) -> str:
    manifest = read_manifest(corpus)
    labels = load_labels([corpus / LABELS])
    raw = read_jsonl_dicts(corpus / RAW_INDEX)
    ks: list[int] = manifest["content_ref_k"]
    traces = {k: _load_split_traces(corpus, k) for k in ks}
    groups: dict[str, dict[str, Any]] = manifest["groups"]
    ineffective: list[str] = manifest["ineffective_classes"]

    raw_by_kept = Counter(r["kept_as"] for r in raw)
    seeded_groups = {group_of(x): x.derived_from for x in labels.values() if x.derived_from}
    arms = sorted({x.condition or "unknown" for x in labels.values()})
    classes = [*sorted({class_of(x) for x in labels.values()} - {BENIGN_CLASS}), BENIGN_CLASS]
    out: list[str] = []
    w = out.append

    w("# Dataset card: Phase 1 detection corpus")
    w("")
    w("Generated by `gauntlet corpus card` from `datasets/corpus/`. Do not edit by hand; CI")
    w("fails when this file and the corpus disagree.")
    w("")

    w("## Sources")
    w("")
    rows = []
    for s in manifest["sources"]:
        commit = s.get("source_commit") or "unknown"
        rows.append(
            [
                s.get("source", "?"),
                f"`{commit[:12]}`",
                s.get("run_log", "?"),
                ", ".join(s.get("experiments", [])),
                s.get("runs_exported", "?"),
                s.get("runs_skipped_error", "?"),
            ]
        )
    w(_table(["Source", "Commit", "Run log", "Experiments", "Runs", "Error runs skipped"], rows))
    w("")
    models = sorted({(s.get("model"), s.get("model_digest")) for s in manifest["sources"]})
    temps: set[object] = set()
    seeds: list[int] = []
    for trace in traces[HASH_K].values():
        for e in trace.events:
            if e.event_type.value == "llm.request":
                temps.add(e.attributes.get("gen_ai.request.temperature"))
                seed = e.attributes.get("gen_ai.request.seed")
                if isinstance(seed, int):
                    seeds.append(seed)
    for model, digest in models:
        w(f"- Model: `{model}`, digest `{digest}`.")
    w(f"- Temperature: {', '.join(str(t) for t in sorted(temps, key=str))}.")
    if seeds:
        w(f"- Seeds: {min(seeds)} to {max(seeds)} (base seed plus run index).")
    w(f"- Arms: {', '.join(arms)}. `guardrails` is `off` for baseline and `on` otherwise.")
    w("")

    w("## Counts per class, arm and split")
    w("")
    w("Raw: runs exported. Unique: distinct traces after dedupe (content hash on K=24, ids,")
    w("timestamps and per-run seeds ignored). Groups: distinct variant groups (inputs).")
    w("")
    cell: dict[tuple[str, str, str], list[Any]] = defaultdict(lambda: [0, 0, set()])
    for x in labels.values():
        ckey = (class_of(x), x.condition or "unknown", x.split.value if x.split else "none")
        cell[ckey][0] += raw_by_kept[x.trace_id]
        cell[ckey][1] += 1
        cell[ckey][2].add(group_of(x))
    rows = []
    for c in classes:
        for arm in arms:
            vals = []
            for split in (Split.DEV, Split.HELDOUT):
                r, u, g = cell[(c, arm, split.value)]
                vals.append(f"{r} / {u} / {len(g)}")
            if any(not v.startswith("0 / 0") for v in vals):
                rows.append([c, arm, *vals])
    w(_table(["Class", "Arm", "Dev raw / unique / groups", "Heldout raw / unique / groups"], rows))
    w("")

    w("## Distinct successful groups per class")
    w("")
    w("A group counts when at least one of its baseline traces is an oracle-confirmed")
    w(f"success. Gate: at least {MIN_GROUPS} per class that succeeds at baseline, at least")
    w(f"{MIN_HELDOUT_SUCCESSFUL} of them heldout.")
    w("")
    rows = []
    gate_rows: list[tuple[str, int, int]] = []
    for c in classes[:-1]:
        mine = {g: i for g, i in groups.items() if i["class"] == c}
        ok = [g for g, i in mine.items() if i["succeeded"]]
        dev = sum(1 for g in ok if mine[g]["split"] == "dev")
        held = sum(1 for g in ok if mine[g]["split"] == "heldout")
        seeded = sum(1 for g in ok if g in seeded_groups)
        status = (
            "ineffective"
            if c in ineffective
            else ("pass" if len(ok) >= MIN_GROUPS and held >= MIN_HELDOUT_SUCCESSFUL else "SHORT")
        )
        if c not in ineffective:
            gate_rows.append((c, len(ok), held))
        rows.append([c, len(mine), len(ok), dev, held, seeded, status])
    w(
        _table(
            [
                "Class",
                "Groups",
                "Successful groups",
                "Dev",
                "Heldout",
                "Seeded among successful",
                "Status",
            ],
            rows,
        )
    )
    w("")
    if ineffective:
        w(f"Ineffective at baseline: {', '.join(ineffective)}. Their traces are included and")
        w("labeled; no group succeeded at baseline, so they are excluded from detection-recall")
        w("denominators and reported as a finding about the model, not a corpus defect.")
        w("")

    w("## Attack success rate per class")
    w("")
    w("Runs: oracle-confirmed successes over raw runs, with a Wilson 95% interval. Groups:")
    w("groups with at least one success over groups.")
    w("")
    runs_ok: Counter[tuple[str, str]] = Counter()
    runs_all: Counter[tuple[str, str]] = Counter()
    grp_ok: dict[tuple[str, str], set[str]] = defaultdict(set)
    grp_all: dict[tuple[str, str], set[str]] = defaultdict(set)
    for x in labels.values():
        if x.label is not Verdict.MALICIOUS:
            continue
        key = (class_of(x), x.condition or "unknown")
        n = raw_by_kept[x.trace_id]
        runs_all[key] += n
        grp_all[key].add(group_of(x))
        if x.attack_succeeded:
            runs_ok[key] += n
            grp_ok[key].add(group_of(x))
    rows = []
    for c in classes[:-1]:
        row: list[object] = [c]
        for arm in arms:
            key = (c, arm)
            row += [_rate(runs_ok[key], runs_all[key]), f"{len(grp_ok[key])}/{len(grp_all[key])}"]
        rows.append(row)
    header = ["Class"]
    for arm in arms:
        header += [f"{arm} runs", f"{arm} groups"]
    w(_table(header, rows))
    w("")

    w("## Benign corpus and hard negatives")
    w("")
    benign = [x for x in labels.values() if x.label is Verdict.BENIGN]
    w(f"- Benign: {sum(raw_by_kept[x.trace_id] for x in benign)} raw runs, {len(benign)} unique")
    w(f"  traces, {len({group_of(x) for x in benign})} tasks.")
    w("")
    kind_tasks: dict[tuple[str, str], set[str]] = defaultdict(set)
    kind_traces: Counter[tuple[str, str]] = Counter()
    for x in benign:
        for kind in hard_negative_kinds(traces[HASH_K][x.trace_id]):
            kind_tasks[(kind, x.condition or "unknown")].add(group_of(x))
            kind_traces[(kind, x.condition or "unknown")] += 1
    rows = []
    for kind, title in HARD_NEGATIVE_KINDS:
        rows.append(
            [title]
            + [f"{len(kind_tasks[(kind, a)])} tasks, {kind_traces[(kind, a)]} traces" for a in arms]
        )
    w(_table(["Kind (read from the trace)", *arms], rows))
    w("")

    w("## Provenance and content-reference K")
    w("")
    w(f"Default K = {HASH_K}: an event references an earlier one when both share a verbatim")
    w("substring of at least K characters after whitespace normalization. Sensitivity over")
    w("successful malicious traces (unique): a tool call that references earlier content, and")
    w("one whose references lead back to untrusted, secret or pii content.")
    w("")
    succeeded = sorted(t for t, x in labels.items() if x.attack_succeeded)
    rows = []
    for k in ks:
        flows = [flow_to_sink(traces[k][t]) for t in succeeded]
        rows.append(
            [
                f"K={k}",
                f"{sum(f for f, _ in flows)}/{len(flows)}",
                f"{sum(t for _, t in flows)}/{len(flows)}",
            ]
        )
    w(
        _table(
            ["K", "Tool call with a content reference", "Reference chain to a sensitive source"],
            rows,
        )
    )
    w("")

    straddle = sorted(
        g
        for g, parent in seeded_groups.items()
        if parent in groups and groups[g]["split"] != groups[parent]["split"]
    )
    w("## Corpus-seeding mutations and reserved mutations")
    w("")
    w(f"- Seeding (this corpus): {', '.join(SEEDING_TRANSFORMS)} of a plain scenario that")
    w("  succeeds at baseline, generated by a local model at a fixed seed with every prompt and")
    w("  output committed in the source repository, re-executed live, scored by the parent")
    w(f"  scenario's oracle. Seeded groups: {len(seeded_groups)}.")
    w(f"- Reserved for evasion testing, never used for seeding: {', '.join(RESERVED_FOR_EVASION)}.")
    w("- The source's authored `-OBF` scenarios predate this split and use some reserved")
    w("  encodings. They sit in their plain scenario's group and are not counted as distinct")
    w("  inputs; evasion testing generates its own mutations.")
    w("")

    w("## Split")
    w("")
    w(f"- Salt `{manifest['salt']}`, about {int(manifest['heldout_fraction'] * 100)}% of the")
    w("  groups of each stratum (class, succeeded at baseline) heldout, ranked by sha256 of salt")
    w("  plus group id. A whole group is in one split.")
    w(f"- Heldout groups: {len(manifest['heldout_groups'])} of {len(groups)}.")
    w("- `SPLIT_MANIFEST.json` pins the sha256 of every heldout file and of the labels file; CI")
    w("  fails if either, or the manifest, changes after the freeze commit.")
    w("- Re-freeze: only deliberately, as a new manifest version in its own PR that states why;")
    w("  every result computed on the old heldout split is then invalid and must be rerun.")
    w("")

    w("## Redaction")
    w("")
    w("The exporter rewrites lab temporary paths to sandbox-relative paths, replaces home")
    w("folders with `<home>` and the process's user and host names with `<host>`, names run")
    w("logs by file name only, and runs the leak guard on every exported file (any hit aborts")
    w("the export). Trace ids are hashes and every trace starts at one fixed epoch, so neither")
    w("ids, file order nor timestamps carry the label.")
    w("")

    w("## Phase 3 reporting plan")
    w("")
    w("- Primary: pooled across classes, on heldout only, every rate with numerator,")
    w("  denominator and a Wilson 95% interval; undefined rates are null.")
    w("- Secondary: per class, with its sample size (traces and groups) and Wilson interval.")
    w("  With a handful of groups per class these are wide and are read as such.")
    w("- Ineffective classes and `attack_failed` traces are excluded from recall denominators")
    w("  and reported with their counts.")
    w("")

    w("## Known gaps")
    w("")
    w("- One model and one prompt per variant: runs repeat, so groups, not runs, are the")
    w("  unit of independence.")
    w(f"- {len(straddle)} seeded groups sit in a different split from the group they were")
    w("  derived from. Siblings share the attack's mechanism and target, so Phase 3 should")
    w("  also report recall with those groups set aside as a sensitivity check.")
    w("- Content references follow verbatim overlap only; paraphrased data flow is missed.")
    w("- The document index is a trusted source, so AC10's injection enters through trusted")
    w("  content by construction.")
    w("- rag-attack-lab traces are not included yet.")
    for c, n, held in gate_rows:
        if n < MIN_GROUPS or held < MIN_HELDOUT_SUCCESSFUL:
            w(f"- {c}: {n} successful groups, {held} heldout; below the gate.")
    w("")
    return "\n".join(out)
