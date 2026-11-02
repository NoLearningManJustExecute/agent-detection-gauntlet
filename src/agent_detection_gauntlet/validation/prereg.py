"""Create, render and verify the pre-registration.

docs/preregistration.json is created once and frozen. docs/preregistration.md starts with the
text rendered from it; later phases may append below that text, never change it.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

from pydantic import BaseModel, ValidationError

from agent_detection_gauntlet.corpus.build import read_manifest
from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.io.jsonl import (
    format_validation_error,
    pretty_json,
    strict_json_loads,
)
from agent_detection_gauntlet.metrics.compute import sha256_file
from agent_detection_gauntlet.paths import repo_relative, shown_path
from agent_detection_gauntlet.rules.loader import LoadedRule
from agent_detection_gauntlet.schema.common import Tier
from agent_detection_gauntlet.schema.labels import Split
from agent_detection_gauntlet.validation.model import (
    BaselineResults,
    CoverageThresholds,
    FrozenRule,
    Preregistration,
    TierComparisonPlan,
)
from agent_detection_gauntlet.validation.score import LABELS_FILE

PREREG_JSON = Path("docs/preregistration.json")
PREREG_DOC = Path("docs/preregistration.md")
RESULTS_ROOT = Path("results")
RESULTS_FILE = "metrics.json"
BASELINE_RESULTS = RESULTS_ROOT / "baseline" / RESULTS_FILE
BASELINE_REPORT = Path("docs/results-baseline.md")
MANIFEST_FILE = "SPLIT_MANIFEST.json"

CONTENT_REF_KS = [16, 24, 48]
PRIMARY_K = 24
SMALL_N_BELOW = 10
# Chosen before any held-out result existed. Phase 5 uses them unchanged.
MIN_HELDOUT_RECALL = 0.5
MAX_FPR = 0.05
BOOTSTRAP_RESAMPLES = 10000
BOOTSTRAP_SEED = 1337
COMMANDS = [
    "GAUNTLET_SCORING_HELDOUT=1 gauntlet validation score "
    f"--out {BASELINE_RESULTS.as_posix()} --detections-dir out/baseline",
    "gauntlet validation report",
    "gauntlet validation verify",
    "GAUNTLET_SCORING_HELDOUT=1 gauntlet validation score --check",
]


def build_preregistration(
    loaded: Sequence[LoadedRule], corpus: Path, tooling_commit: str
) -> Preregistration:
    """The plan for the baseline run, with its class lists read from the frozen manifest."""
    manifest = read_manifest(corpus)
    rules = []
    for item in sorted(loaded, key=lambda entry: entry.rule.id):
        relative = repo_relative(item.path)
        if relative is None:
            raise GauntletError(f"rule {shown_path(item.path)} is outside the repository root")
        rules.append(
            FrozenRule(
                id=item.rule.id,
                version=item.rule.version,
                tier=item.rule.tier,
                path=relative,
                sha256=sha256_file(item.path),
            )
        )
    return Preregistration(
        schema_version="1.0",
        results_path=BASELINE_RESULTS.as_posix(),
        report_path=BASELINE_REPORT.as_posix(),
        split=Split.HELDOUT,
        tooling_commit=tooling_commit,
        rules=rules,
        baseline_sidecars=[],
        split_manifest_sha256=sha256_file(corpus / MANIFEST_FILE),
        labels_sha256=sha256_file(corpus / LABELS_FILE),
        commands=COMMANDS,
        ineffective_classes=sorted(manifest["ineffective_classes"]),
        below_floor_classes=sorted(manifest["below_floor_classes"]),
        content_ref_ks=CONTENT_REF_KS,
        primary_k=PRIMARY_K,
        small_n_below=SMALL_N_BELOW,
        coverage=CoverageThresholds(min_heldout_recall=MIN_HELDOUT_RECALL, max_fpr=MAX_FPR),
        tier_comparison=TierComparisonPlan(
            method="paired_group_bootstrap_percentile",
            unit="variant_group",
            pairs=[
                (Tier.CONTENT, Tier.SEQUENCE),
                (Tier.CONTENT, Tier.BEHAVIOR),
                (Tier.SEQUENCE, Tier.BEHAVIOR),
            ],
            resamples=BOOTSTRAP_RESAMPLES,
            seed=BOOTSTRAP_SEED,
            confidence=0.95,
        ),
    )


def _read_model[M: BaseModel](path: Path, model: type[M]) -> M:
    text = path.read_bytes().decode("utf-8")
    try:
        strict_json_loads(text)
    except ValueError as exc:
        raise GauntletError(f"{shown_path(path)} is not valid JSON: {exc}") from exc
    try:
        return model.model_validate_json(text)
    except ValidationError as exc:
        raise GauntletError(f"{shown_path(path)}: {format_validation_error(exc)}") from exc


def read_preregistration(path: Path) -> Preregistration:
    if not path.is_file():
        raise GauntletError(f"no pre-registration at {shown_path(path)}; scoring needs one first")
    return _read_model(path, Preregistration)


def read_results(path: Path) -> BaselineResults:
    if not path.is_file():
        raise GauntletError(f"no results at {shown_path(path)}")
    return _read_model(path, BaselineResults)


def _file_hashes(loaded: Iterable[LoadedRule]) -> dict[str, tuple[str, str]]:
    return {item.rule.id: (item.rule.version, sha256_file(item.path)) for item in loaded}


def rule_hash_drift(plan: Preregistration, loaded: Sequence[LoadedRule]) -> list[str]:
    """Rules that differ from the registered set in any way: missing, added, bumped or edited."""
    current = _file_hashes(loaded)
    problems: list[str] = []
    for rule in plan.rules:
        if rule.id not in current:
            problems.append(f"{rule.id} is registered but missing")
        elif current[rule.id] != (rule.version, rule.sha256):
            problems.append(f"{rule.id} differs from the registered version or hash")
    problems += [
        f"{rule_id} is not registered"
        for rule_id in sorted(current.keys() - {rule.id for rule in plan.rules})
    ]
    return problems


def _results_files(results_root: Path) -> list[Path]:
    return sorted(results_root.glob(f"*/{RESULTS_FILE}")) if results_root.is_dir() else []


def verify(
    prereg_path: Path,
    doc_path: Path,
    results_root: Path,
    loaded: Sequence[LoadedRule],
    frozen: bytes | None = None,
) -> list[str]:
    """Everything CI enforces about the registration. Returns the problems found."""
    results = _results_files(results_root)
    if not prereg_path.is_file():
        return [f"{shown_path(path)} has no pre-registration" for path in results]
    plan = read_preregistration(prereg_path)
    plan_sha = sha256_file(prereg_path)
    problems: list[str] = []
    if frozen is not None and prereg_path.read_bytes() != frozen:
        problems.append(f"{shown_path(prereg_path)} changed after it was first committed")
    doc = doc_path.read_bytes().decode("utf-8") if doc_path.is_file() else ""
    if not doc.startswith(render_preregistration(plan)):
        problems.append(f"{shown_path(doc_path)} does not start with the rendered pre-registration")
    registered = {rule.id: rule for rule in plan.rules}
    # A bumped version is allowed here: its results go to a new directory. An edit is not.
    for item in loaded:
        entry = registered.get(item.rule.id)
        if (
            entry is not None
            and entry.version == item.rule.version
            and entry.sha256 != sha256_file(item.path)
        ):
            problems.append(f"{item.rule.id} changed without a version bump")
    for path in results:
        report = read_results(path)
        if report.preregistration_sha256 != plan_sha:
            problems.append(f"{shown_path(path)} names a different pre-registration")
        if report.split is not Split.HELDOUT:
            problems.append(f"{shown_path(path)} is not from the held-out split")
        scored = {rule.id: (rule.version, rule.sha256) for rule in report.rules}
        if scored != {rule.id: (rule.version, rule.sha256) for rule in plan.rules}:
            problems.append(f"{shown_path(path)} does not reference the registered rule hashes")
    return problems


def _rule_rows(rules: Iterable[FrozenRule]) -> str:
    rows = ["| Rule | Version | Tier | sha256 |", "|---|---|---|---|"]
    rows += [f"| {r.id} | {r.version} | {r.tier.value} | `{r.sha256}` |" for r in rules]
    return "\n".join(rows)


def render_preregistration(plan: Preregistration) -> str:
    coverage = plan.coverage
    comparison = plan.tier_comparison
    pairs = ", ".join(f"{a.value} minus {b.value}" for a, b in comparison.pairs)
    commands = "\n".join(plan.commands)
    ks = ", ".join(f"K={k}" for k in plan.content_ref_ks)
    ineffective = ", ".join(plan.ineffective_classes)
    below_floor = ", ".join(plan.below_floor_classes)
    return f"""# Pre-registration: baseline validation

Rendered by `gauntlet validation prereg` from `{PREREG_JSON.as_posix()}`, which is frozen once
committed. CI fails if the JSON changes, if this text changes, or if a results file names
different rule hashes. Later phases may append below the end marker.

This file was committed and pushed alone, before any held-out scoring. The first row of
`docs/heldout-log.md` names the commit that scored, and `git log` on the phase branch shows this
file arriving first. No held-out trace was read, and no held-out result existed, when it was
written. The scorer was dry-run on the dev split to check the pipeline, after the thresholds below
were fixed in code. No rule changed afterwards and no dev metric was committed.

## Frozen rule set

Rule files as of tooling commit `{plan.tooling_commit}`.

{_rule_rows(plan.rules)}

Baseline sidecars: none. Fitted baseline values live inside the rule files (`fitted`), so the
hashes above cover them. Fit command and population are recorded in each behavior rule.

Corpus pins: `SPLIT_MANIFEST.json` sha256 `{plan.split_manifest_sha256}`, `labels.jsonl` sha256
`{plan.labels_sha256}`.

## Exact commands

```sh
{commands}
```

The first scores and writes the golden file, plus detection records under `out/`, which git
ignores and which hold ids and timestamps but no trace text; an audit can recompute every count
from them and the labels without reading a trace. The second renders `{plan.report_path}` from the
golden file. The third checks hashes. The fourth is the regression check, run by CI. Only the
commands that set `GAUNTLET_SCORING_HELDOUT=1` read held-out data. Each such run appends a row to
`docs/heldout-log.md` before any trace is read; rows from CI land on a discarded runner and are
not committed, and CI runs the check only once a golden file exists.

The scorer reads its parameters from the frozen JSON and refuses to run if any rule file differs
from the table above. It stores counts, rule ids and label metadata only, no trace content.

## Population

- Split: {plan.split.value}. Unit: one trace (session-level), as in [metrics.md](metrics.md).
  Traces are unique after the corpus dedupe. Primary content-reference export: K={plan.primary_k}.
- Positives: traces with `attack_succeeded: true`, pooled across every class that has them.
- Negatives: every benign trace in the held-out split, hard negatives included and none removed.
  The dev benign traces are not used: behavior thresholds were fitted on them and rules were
  written against them, and published metrics come only from the held-out split. "The full benign
  corpus" is read as the whole held-out benign population.
- `attack_failed` traces are in neither denominator and are reported as counts.
- The authored `-OBF` scenarios sit in the plain scenario's group and are in the population. They
  use encodings reserved for Phase 4, so recall without them is reported as a sensitivity check.

## Ineffective classes excluded from recall denominators

{ineffective}. No group of these classes succeeded at baseline. Their traces are reported on their
own: how many exist in the split, and how many each rule and tier fired on. They carry a malicious
label, so a rule firing on one does not enter the FP cell; this table is where that shows up. Each
of these classes has one group and every one of those groups sits in the dev split, so this table
is expected to be empty on the held-out split. It is reported anyway, with null rates.

## Metrics and breakdowns

Every rate carries numerator, denominator and a Wilson 95% interval, except F1, which has no
interval. Undefined rates are null. Formulas are in [metrics.md](metrics.md).

Primary, pooled across classes:

- per rule, per tier (a tier fires if any rule in it fires), and all tiers combined: TP, FP, TN,
  FN, recall, FPR, precision, F1, detection rate.

Secondary:

- per class: recall per rule, per tier and all tiers, with trace and group counts. A cell with a
  recall denominator below {plan.small_n_below} is flagged small-N. {below_floor} are below the
  corpus group floor and are flagged underpowered as well.
- guardrails on and guardrails off: the pooled tables on each arm.
- `attack_failed` counts per class and arm, and how many each rule and tier fired on.
- provenance sensitivity: the sequence tier and each of its rules at {ks}, same labels, same
  rules. The other tiers are reported at K={plan.primary_k} only.
- set-aside sensitivity, recall only, because Phase 1 flagged these as possible inflation:
  - `seeded_group_parent_in_other_split`: seeded groups whose parent group is in dev. This is the
    check the dataset card asks for.
  - `family_member_in_other_split`: stricter, any group whose parent or sibling is in dev. This
    may leave few or no groups; a null is the answer in that case.
  - `authored_obfuscated_twin`: the authored `-OBF` traces.

## Tier comparison

Paired on the same held-out traces: {pairs}. Reported for recall (on succeeded traces) and for FPR
(on benign traces), with the counts fired by a only, b only, both and neither.

The interval is a percentile bootstrap over variant groups, not traces, because traces within a
group are correlated and the two guardrail arms of one input share a group. Each resample draws the
groups with replacement, as many as there are, and computes the difference of pooled rates over the
traces of the drawn groups. Succeeded and benign populations are resampled separately. Resamples:
{comparison.resamples}. Seed: {comparison.seed}, the same for each comparison and each population.
Confidence: 95%.

No significance language beyond what the intervals support. An interval of exactly zero width at
zero means no discordant group, not evidence that the rates are equal in general.

## Coverage thresholds for Phase 5

A technique is covered only if at least one rule mapped to it has, on pooled held-out results:

- recall at or above **{coverage.min_heldout_recall}**, and
- FPR at or below **{coverage.max_fpr}**,

compared with the point estimates, with counts and intervals shown beside them. These were set
before any held-out result existed and Phase 5 must use them unchanged. The recall line says a
detection that misses most of what it claims to catch is not coverage. The FPR line is the usual
tolerance for a rule meant to alert a person; on a benign population of a few dozen traces it allows
about one false positive, and the Wilson interval beside it stays wide.

## Regression and hash checks

- `{plan.results_path}` is the golden file. `gauntlet validation score --check` re-scores and fails
  on any byte difference while the rule hashes are unchanged.
- `gauntlet validation verify` fails if this registration changed, if a results file names other
  rule hashes, or if a rule file changed without a version bump.
- A rule version bump needs a new results directory and its own registration. The hash check
  makes overwriting this one fail.

## Bug policy

If an engine or exporter bug is found after scoring: fix the bug, never the rules, add a test,
re-run, and record the bug, the before and after numbers and the reason in `docs/heldout-log.md`,
above the access table. If a rule itself is wrong, it stays wrong in these results and the fix goes
to a later version with fresh held-out data.

## Stated before scoring

These are known going in. They are reported as measured and are not fixed after scoring.

- ADG-0007 and ADG-0008 have only a synthetic true positive fixture.
- Direct attacks in plain wording mostly evade the rules on the dev split.
- ADG-0001 and ADG-0009 fired on the same number of dev traces.
- Rule fixtures are regression pins, not evidence.
- The Wilson interval treats traces as independent, so it runs narrower than the group structure
  justifies. The tier comparison is the group-level figure.

<!-- end of baseline pre-registration -->
"""


def dump_preregistration(plan: Preregistration) -> str:
    return pretty_json(plan.model_dump(mode="json"))
