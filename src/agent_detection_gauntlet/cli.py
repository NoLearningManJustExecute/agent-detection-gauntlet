"""Command line interface: ``gauntlet <command>``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from agent_detection_gauntlet import __version__
from agent_detection_gauntlet.catalog import load_catalog
from agent_detection_gauntlet.engine.executor import scan
from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.io.jsonl import pretty_json, read_jsonl, write_jsonl, write_text
from agent_detection_gauntlet.io.labels import load_labels
from agent_detection_gauntlet.io.traces import load_traces
from agent_detection_gauntlet.metrics.compute import (
    ScoringInputs,
    build_report,
    check_detections_reproduce,
)
from agent_detection_gauntlet.metrics.report import InputRole
from agent_detection_gauntlet.rules.validator import ValidationReport, validate_rules
from agent_detection_gauntlet.schema.detection import Detection
from agent_detection_gauntlet.schema.export import export_schemas, schema_drift
from agent_detection_gauntlet.schema.labels import Split

DEFAULT_FIXTURES = Path("datasets/fixtures/traces")
DEFAULT_SCHEMAS = Path("schemas")


def _print_issues(report: ValidationReport) -> None:
    for issue in report.issues:
        print(issue.render(), file=sys.stderr)


def _require_valid_rules(rules_dir: Path, fixtures: Sequence[Path]) -> ValidationReport:
    report = validate_rules(rules_dir, fixtures, load_catalog())
    _print_issues(report)
    if not report.ok:
        raise GauntletError(f"rule validation failed with {len(report.errors)} error(s)")
    return report


def cmd_validate_traces(args: argparse.Namespace) -> int:
    trace_set = load_traces(args.paths)
    print(
        f"ok: {trace_set.event_count} events in {len(trace_set.traces)} traces "
        f"from {len(trace_set.files)} file(s)"
    )
    return 0


def cmd_validate_rules(args: argparse.Namespace) -> int:
    report = validate_rules(args.directory, args.fixtures, load_catalog())
    _print_issues(report)
    if not report.ok:
        print(f"failed: {len(report.errors)} error(s), {len(report.warnings)} warning(s)")
        return 1
    print(f"ok: {len(report.rules)} rule(s), {len(report.warnings)} warning(s)")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    report = _require_valid_rules(args.rules, args.fixtures)
    trace_set = load_traces(args.traces)
    detections = scan([loaded.rule for loaded in report.rules], trace_set.traces)
    write_jsonl(args.out, detections)
    print(
        f"ok: {len(detections)} detection(s) from {len(report.rules)} rule(s) "
        f"over {len(trace_set.traces)} trace(s) -> {args.out.as_posix()}"
    )
    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    report = _require_valid_rules(args.rules, args.fixtures)
    trace_set = load_traces(args.traces)
    labels = load_labels([args.labels])
    detections = [record for _, record in read_jsonl(args.detections, Detection)]
    rules = [loaded.rule for loaded in report.rules]
    check_detections_reproduce(detections, scan(rules, trace_set.traces))
    split = Split(args.split)
    files: list[tuple[InputRole, Path]] = [("rule", loaded.path) for loaded in report.rules]
    files += [("trace", path) for path in trace_set.files]
    files += [("detections", args.detections), ("labels", args.labels)]
    metrics = build_report(
        ScoringInputs(
            rules=rules,
            trace_ids=trace_set.trace_ids(),
            labels=labels,
            detections=detections,
            split=split,
        ),
        files,
    )
    write_text(args.out, pretty_json(metrics.model_dump(mode="json")))
    print(
        f"ok: split {split.value}, {metrics.population.traces} trace(s) scored "
        f"-> {args.out.as_posix()}"
    )
    return 0


def cmd_export_schemas(args: argparse.Namespace) -> int:
    if args.check:
        drift = schema_drift(args.out)
        if drift:
            for name in drift:
                print(f"error: {args.out.as_posix()}/{name} is out of date", file=sys.stderr)
            print("run `gauntlet export-schemas` and commit the result", file=sys.stderr)
            return 1
        print(f"ok: schemas in {args.out.as_posix()} match the models")
        return 0
    written = export_schemas(args.out)
    print(f"ok: wrote {len(written)} schema(s) to {args.out.as_posix()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gauntlet",
        description="Evaluate AI-agent detections against labeled traces.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    fixtures_help = f"fixture trace files or directories (default: {DEFAULT_FIXTURES})"

    p = sub.add_parser("validate-traces", help="validate trace JSONL files")
    p.add_argument("paths", nargs="+", type=Path, help="trace files or directories")
    p.set_defaults(handler=cmd_validate_traces)

    p = sub.add_parser("validate-rules", help="validate a directory of rules")
    p.add_argument("directory", type=Path)
    p.add_argument(
        "--fixtures", nargs="+", type=Path, default=[DEFAULT_FIXTURES], help=fixtures_help
    )
    p.set_defaults(handler=cmd_validate_rules)

    p = sub.add_parser("scan", help="run rules over traces and write detections")
    p.add_argument("--rules", type=Path, required=True)
    p.add_argument("--traces", nargs="+", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument(
        "--fixtures", nargs="+", type=Path, default=[DEFAULT_FIXTURES], help=fixtures_help
    )
    p.set_defaults(handler=cmd_scan)

    p = sub.add_parser("metrics", help="score detections against labels")
    p.add_argument("--rules", type=Path, required=True)
    p.add_argument("--traces", nargs="+", type=Path, required=True)
    p.add_argument("--detections", type=Path, required=True)
    p.add_argument("--labels", type=Path, required=True)
    p.add_argument("--split", choices=[split.value for split in Split], default=Split.HELDOUT.value)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument(
        "--fixtures", nargs="+", type=Path, default=[DEFAULT_FIXTURES], help=fixtures_help
    )
    p.set_defaults(handler=cmd_metrics)

    p = sub.add_parser("export-schemas", help="regenerate the JSON Schemas")
    p.add_argument("--out", type=Path, default=DEFAULT_SCHEMAS)
    p.add_argument("--check", action="store_true", help="fail if checked-in schemas drifted")
    p.set_defaults(handler=cmd_export_schemas)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except GauntletError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
