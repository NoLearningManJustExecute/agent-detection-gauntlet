"""Session-level scoring of detections against ground-truth labels.

Formulas are in docs/metrics.md. Inputs are cross-checked before anything is counted, and any
mismatch fails closed with MetricsInputError.
"""

from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from agent_detection_gauntlet import __version__
from agent_detection_gauntlet.errors import MetricsInputError
from agent_detection_gauntlet.metrics.report import (
    AttackFailed,
    Confusion,
    InputFile,
    InputRole,
    Interval,
    MetricsReport,
    Population,
    Provenance,
    Rate,
    Rates,
    RuleMetrics,
    RuleRef,
    TierMetrics,
)
from agent_detection_gauntlet.metrics.stats import ratio, wilson_interval
from agent_detection_gauntlet.rules.model import Rule
from agent_detection_gauntlet.schema.common import SCHEMA_VERSION, TIER_ORDER
from agent_detection_gauntlet.schema.detection import Detection
from agent_detection_gauntlet.schema.labels import LabelRecord, Split, Verdict


class Outcome(StrEnum):
    BENIGN = "benign"
    MALICIOUS_SUCCEEDED = "malicious_succeeded"
    ATTACK_FAILED = "attack_failed"


def outcome_of(label: LabelRecord) -> Outcome:
    if label.label is Verdict.BENIGN:
        return Outcome.BENIGN
    if label.attack_succeeded:
        return Outcome.MALICIOUS_SUCCEEDED
    return Outcome.ATTACK_FAILED


def make_rate(numerator: int, denominator: int, *, interval: bool = True) -> Rate:
    bounds = wilson_interval(numerator, denominator) if interval else None
    return Rate(
        value=ratio(numerator, denominator),
        numerator=numerator,
        denominator=denominator,
        ci95=None
        if bounds is None
        else Interval(method="wilson", confidence=0.95, lower=bounds[0], upper=bounds[1]),
    )


def compute_rates(confusion: Confusion) -> Rates:
    tp, fp, tn, fn = confusion.tp, confusion.fp, confusion.tn, confusion.fn
    return Rates(
        precision=make_rate(tp, tp + fp),
        recall=make_rate(tp, tp + fn),
        f1=make_rate(2 * tp, 2 * tp + fp + fn, interval=False),
        fpr=make_rate(fp, fp + tn),
        detection_rate=make_rate(tp, tp + fn),
    )


def score(outcomes: Mapping[str, Outcome], detected: set[str]) -> tuple[Confusion, AttackFailed]:
    tp = fp = tn = fn = failed = failed_detected = 0
    for trace_id in sorted(outcomes):
        hit = trace_id in detected
        outcome = outcomes[trace_id]
        if outcome is Outcome.BENIGN:
            fp += hit
            tn += not hit
        elif outcome is Outcome.MALICIOUS_SUCCEEDED:
            tp += hit
            fn += not hit
        else:
            failed += 1
            failed_detected += hit
    return (
        Confusion(tp=tp, fp=fp, tn=tn, fn=fn),
        AttackFailed(count=failed, detected=failed_detected),
    )


@dataclass(frozen=True)
class ScoringInputs:
    rules: Sequence[Rule]
    trace_ids: Sequence[str]
    labels: Mapping[str, LabelRecord]
    detections: Sequence[Detection]
    split: Split


def check_inputs(inputs: ScoringInputs) -> None:
    """Fail closed when rules, traces, labels and detections do not line up."""
    traces = set(inputs.trace_ids)
    unlabeled = sorted(traces - set(inputs.labels))
    if unlabeled:
        raise MetricsInputError(f"traces without a label: {unlabeled}")
    missing = sorted(
        trace_id
        for trace_id, label in inputs.labels.items()
        if label.split is inputs.split and trace_id not in traces
    )
    if missing:
        raise MetricsInputError(
            f"labels in split {inputs.split.value!r} name traces that were not supplied: {missing}"
        )
    versions = {rule.id: rule.version for rule in inputs.rules}
    if len(versions) != len(inputs.rules):
        raise MetricsInputError("duplicate rule ids in the rule set")
    for record in inputs.detections:
        if record.rule_id not in versions:
            raise MetricsInputError(f"detection names unknown rule {record.rule_id}")
        if record.rule_version != versions[record.rule_id]:
            raise MetricsInputError(
                f"detection for {record.rule_id} has version {record.rule_version}, "
                f"but the rule set has {versions[record.rule_id]}"
            )
        if record.trace_id not in traces:
            raise MetricsInputError(f"detection names trace {record.trace_id!r} not supplied")


def compute_metrics(
    inputs: ScoringInputs,
) -> tuple[Population, list[RuleMetrics], list[TierMetrics]]:
    check_inputs(inputs)
    outcomes = {
        trace_id: outcome_of(inputs.labels[trace_id])
        for trace_id in sorted(inputs.trace_ids)
        if inputs.labels[trace_id].split is inputs.split
    }
    counts = {outcome: 0 for outcome in Outcome}
    for outcome in outcomes.values():
        counts[outcome] += 1
    population = Population(
        traces=len(outcomes),
        benign=counts[Outcome.BENIGN],
        malicious_succeeded=counts[Outcome.MALICIOUS_SUCCEEDED],
        attack_failed=counts[Outcome.ATTACK_FAILED],
    )

    detected_by_rule: dict[str, set[str]] = {rule.id: set() for rule in inputs.rules}
    for record in inputs.detections:
        detected_by_rule[record.rule_id].add(record.trace_id)

    per_rule: list[RuleMetrics] = []
    for rule in sorted(inputs.rules, key=lambda item: item.id):
        confusion, failed = score(outcomes, detected_by_rule[rule.id])
        per_rule.append(
            RuleMetrics(
                rule_id=rule.id,
                rule_version=rule.version,
                tier=rule.tier,
                confusion=confusion,
                attack_failed=failed,
                rates=compute_rates(confusion),
            )
        )

    per_tier: list[TierMetrics] = []
    for tier in TIER_ORDER:
        members = sorted(rule.id for rule in inputs.rules if rule.tier is tier)
        if not members:
            continue
        detected = set().union(*(detected_by_rule[rule_id] for rule_id in members))
        confusion, failed = score(outcomes, detected)
        per_tier.append(
            TierMetrics(
                tier=tier,
                rule_ids=members,
                confusion=confusion,
                attack_failed=failed,
                rates=compute_rates(confusion),
            )
        )
    return population, per_rule, per_tier


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def describe_inputs(files: Iterable[tuple[InputRole, Path]]) -> list[InputFile]:
    entries = {
        (role, path.as_posix()): InputFile(
            role=role, path=path.as_posix(), sha256=sha256_file(path)
        )
        for role, path in files
    }
    return [entries[key] for key in sorted(entries)]


def _git(args: Sequence[str], cwd: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def git_provenance() -> tuple[str | None, bool | None]:
    """Commit and dirty flag of the checkout this package runs from, or None outside git."""
    here = Path(__file__).resolve().parent
    commit = _git(["rev-parse", "HEAD"], here)
    if commit is None:
        return None, None
    status = _git(["status", "--porcelain", "--untracked-files=no"], here)
    return commit.strip(), None if status is None else bool(status.strip())


def build_report(inputs: ScoringInputs, files: Iterable[tuple[InputRole, Path]]) -> MetricsReport:
    population, per_rule, per_tier = compute_metrics(inputs)
    commit, dirty = git_provenance()
    return MetricsReport(
        schema_version=SCHEMA_VERSION,
        split=inputs.split,
        provenance=Provenance(package_version=__version__, git_commit=commit, git_dirty=dirty),
        inputs=describe_inputs(files),
        rules=[
            RuleRef(id=rule.id, version=rule.version, tier=rule.tier)
            for rule in sorted(inputs.rules, key=lambda item: item.id)
        ],
        population=population,
        per_rule=per_rule,
        per_tier=per_tier,
    )
