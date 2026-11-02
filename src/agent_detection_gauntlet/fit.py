"""Fit behavior baselines on dev benign traces and record the result in the rule file.

Deterministic: integer counts over traces in sorted order, nearest-rank percentile, sorted
output. Fails closed when any supplied trace is not labeled dev. Lives outside the engine
because it reads labels, which the engine never does.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

from agent_detection_gauntlet.engine.primitives import baseline_events, trace_transitions
from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.firewall import refuse_heldout
from agent_detection_gauntlet.io.labels import load_labels
from agent_detection_gauntlet.io.traces import load_traces
from agent_detection_gauntlet.paths import repo_relative
from agent_detection_gauntlet.rules.loader import load_rule_file, rule_files
from agent_detection_gauntlet.rules.model import BaselineLogic, BaselineSpec, BaselineStatistic
from agent_detection_gauntlet.schema.labels import Split, Verdict
from agent_detection_gauntlet.schema.trace import Trace

_FITTED_BLOCK = re.compile(r"^fitted:.*\Z", re.MULTILINE | re.DOTALL)


def nearest_rank(values: Sequence[int], percentile: int) -> int:
    """The smallest value with at least ``percentile`` percent of the values at or below it."""
    ordered = sorted(values)
    return ordered[max(math.ceil(percentile * len(ordered) / 100), 1) - 1]


def fit_values(spec: BaselineSpec, traces: Sequence[Trace]) -> dict[str, object]:
    if spec.statistic is BaselineStatistic.CHAIN_LENGTH:
        lengths = [len(baseline_events(spec, trace)) for trace in traces]
        return {"threshold": nearest_rank(lengths, spec.percentile or 100)}
    counts: Counter[str] = Counter()
    for trace in traces:
        counts.update(key for _, _, key in trace_transitions(spec, trace))
    return {"transitions": dict(sorted(counts.items()))}


def benign_dev_traces(trace_paths: Sequence[Path], labels_path: Path) -> list[Trace]:
    refuse_heldout(trace_paths, "baseline fitting")
    labels = load_labels([labels_path])
    traces = load_traces(trace_paths).traces
    not_dev = sum(
        1
        for trace in traces
        if trace.trace_id not in labels or labels[trace.trace_id].split is not Split.DEV
    )
    if not_dev:
        raise GauntletError(f"baseline fitting takes dev traces only; {not_dev} supplied are not")
    benign = [trace for trace in traces if labels[trace.trace_id].label is Verdict.BENIGN]
    if not benign:
        raise GauntletError("baseline fitting found no dev benign traces")
    return benign


def _command_text(rules_dir: Path, trace_paths: Sequence[Path], labels_path: Path) -> str:
    parts = {"--rules": [rules_dir], "--traces": list(trace_paths), "--labels": [labels_path]}
    words = ["gauntlet", "fit-baselines"]
    for flag, paths in parts.items():
        relative = [repo_relative(path) for path in paths]
        if None in relative:
            raise GauntletError(f"{flag} must be inside the repository, so the fit can be rerun")
        words += [flag, *(str(item) for item in relative)]
    return " ".join(words)


@dataclass(frozen=True)
class FitOutcome:
    written: list[Path]
    stale: list[Path]
    fitted: int


def fit_baselines(
    rules_dir: Path, trace_paths: Sequence[Path], labels_path: Path, *, check: bool = False
) -> FitOutcome:
    """Refit every baseline rule. With ``check`` nothing is written, stale rules are reported."""
    command = _command_text(rules_dir, trace_paths, labels_path)
    traces = benign_dev_traces(trace_paths, labels_path)
    written: list[Path] = []
    stale: list[Path] = []
    fitted = 0
    for path in rule_files(rules_dir):
        rule = load_rule_file(path)
        if not isinstance(rule.logic, BaselineLogic):
            continue
        fitted += 1
        block: dict[str, object] = {
            "command": command,
            "population": "dev benign",
            "traces": len(traces),
        }
        block.update(fit_values(rule.logic.baseline, traces))
        current = path.read_bytes().decode("utf-8")
        kept = _FITTED_BLOCK.sub("", current).rstrip("\n")
        updated = f"{kept}\n{yaml.safe_dump({'fitted': block}, sort_keys=True, width=100)}"
        if updated == current:
            continue
        stale.append(path)
        if not check:
            path.write_bytes(updated.encode("utf-8"))
            load_rule_file(path)
            written.append(path)
    return FitOutcome(written=written, stale=stale, fitted=fitted)
