"""Rule validation for ``gauntlet validate-rules``.

Checks, in order: each file parses against the rule model, file name matches the rule id,
ids are unique, baseline rules have been fitted, every mapping id is in the catalog (warning
when unverified), every fixture trace exists, and the rule fires on each tp fixture and on no
fp fixture.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from agent_detection_gauntlet.catalog import Catalog
from agent_detection_gauntlet.engine.executor import rule_hits
from agent_detection_gauntlet.engine.primitives import TraceContext
from agent_detection_gauntlet.errors import InputError
from agent_detection_gauntlet.io.traces import load_traces
from agent_detection_gauntlet.paths import shown_path
from agent_detection_gauntlet.rules.loader import LoadedRule, load_rule_file, rule_files
from agent_detection_gauntlet.rules.model import BaselineLogic
from agent_detection_gauntlet.schema.trace import Trace


class IssueLevel(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class Issue:
    level: IssueLevel
    source: str
    message: str

    def render(self) -> str:
        return f"{self.level.value}: {self.source}: {self.message}"


@dataclass
class ValidationReport:
    rules: list[LoadedRule] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)

    @property
    def errors(self) -> list[Issue]:
        return [issue for issue in self.issues if issue.level is IssueLevel.ERROR]

    @property
    def warnings(self) -> list[Issue]:
        return [issue for issue in self.issues if issue.level is IssueLevel.WARNING]

    @property
    def ok(self) -> bool:
        return not self.errors

    def error(self, source: Path | str, message: str) -> None:
        self.issues.append(Issue(IssueLevel.ERROR, _source(source), message))

    def warning(self, source: Path | str, message: str) -> None:
        self.issues.append(Issue(IssueLevel.WARNING, _source(source), message))


def _source(source: Path | str) -> str:
    return shown_path(source) if isinstance(source, Path) else source


def load_rule_set(directory: Path, report: ValidationReport) -> None:
    """Parse every rule file, recording schema, file name and duplicate id problems."""
    for path in rule_files(directory):
        try:
            rule = load_rule_file(path)
        except InputError as exc:
            report.error(path, exc.detail)
            continue
        if path.stem != rule.id:
            report.error(path, f"file name must be {rule.id}{path.suffix} to match the rule id")
        report.rules.append(LoadedRule(path=path, rule=rule))

    seen: dict[str, Path] = {}
    for loaded in report.rules:
        first = seen.setdefault(loaded.rule.id, loaded.path)
        if first != loaded.path:
            report.error(loaded.path, f"duplicate rule id {loaded.rule.id} (also in {first.name})")


def check_fitted(report: ValidationReport) -> None:
    """A baseline rule that has not been fitted cannot run, so it leaves the rule set."""
    unfitted = [
        loaded
        for loaded in report.rules
        if isinstance(loaded.rule.logic, BaselineLogic) and loaded.rule.fitted is None
    ]
    for loaded in unfitted:
        report.error(loaded.path, "baseline rule is not fitted; run gauntlet fit-baselines")
        report.rules.remove(loaded)


def check_mappings(report: ValidationReport, catalog: Catalog) -> None:
    for loaded in report.rules:
        for family, ids in loaded.rule.mappings.by_family().items():
            for mapping_id in ids:
                entry = catalog.lookup(family, mapping_id)
                if entry is None:
                    report.error(loaded.path, f"{family} id {mapping_id} is not in the catalog")
                elif not entry.verified:
                    report.warning(
                        loaded.path,
                        f"{family} id {mapping_id} ({entry.name}) is not verified "
                        "against the primary source",
                    )


def check_fixtures(report: ValidationReport, fixture_paths: Sequence[Path]) -> None:
    if not report.rules:
        return
    try:
        trace_set = load_traces(fixture_paths)
    except InputError as exc:
        report.error(exc.path, f"cannot load fixture traces: {exc.detail}")
        return
    traces: dict[str, Trace] = {trace.trace_id: trace for trace in trace_set.traces}
    for loaded in report.rules:
        rule = loaded.rule
        for kind, trace_ids, should_fire in (
            ("tp", rule.fixtures.tp, True),
            ("fp", rule.fixtures.fp, False),
        ):
            for trace_id in trace_ids:
                trace = traces.get(trace_id)
                if trace is None:
                    report.error(loaded.path, f"{kind} fixture trace {trace_id!r} does not exist")
                    continue
                fired = bool(rule_hits(rule, TraceContext(trace)))
                if fired and not should_fire:
                    report.error(loaded.path, f"rule fires on fp fixture {trace_id!r}")
                elif should_fire and not fired:
                    report.error(loaded.path, f"rule does not fire on tp fixture {trace_id!r}")


def validate_rules(
    directory: Path, fixture_paths: Sequence[Path], catalog: Catalog
) -> ValidationReport:
    report = ValidationReport()
    load_rule_set(directory, report)
    check_fitted(report)
    check_mappings(report, catalog)
    check_fixtures(report, fixture_paths)
    return report
