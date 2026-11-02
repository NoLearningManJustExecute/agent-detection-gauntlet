"""Command line interface: ``gauntlet <command>``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from agent_detection_gauntlet import __version__
from agent_detection_gauntlet.catalog import load_catalog
from agent_detection_gauntlet.corpus.build import build as build_corpus
from agent_detection_gauntlet.corpus.card import render as render_card
from agent_detection_gauntlet.corpus.verify import require_valid
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
from agent_detection_gauntlet.paths import set_repo_root, shown_path
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
        f"over {len(trace_set.traces)} trace(s) -> {shown_path(args.out)}"
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
        external_basename=args.external_basename,
    )
    write_text(args.out, pretty_json(metrics.model_dump(mode="json")))
    print(
        f"ok: split {split.value}, {metrics.population.traces} trace(s) scored "
        f"-> {shown_path(args.out)}"
    )
    return 0


def cmd_export_schemas(args: argparse.Namespace) -> int:
    if args.check:
        drift = schema_drift(args.out)
        if drift:
            for name in drift:
                print(f"error: {shown_path(args.out / name)} is out of date", file=sys.stderr)
            print("run `gauntlet export-schemas` and commit the result", file=sys.stderr)
            return 1
        print(f"ok: schemas in {shown_path(args.out)} match the models")
        return 0
    written = export_schemas(args.out)
    print(f"ok: wrote {len(written)} schema(s) to {shown_path(args.out)}")
    return 0


DEFAULT_CORPUS = Path("datasets/corpus")
DEFAULT_CARD = Path("docs/dataset.md")


def cmd_corpus_build(args: argparse.Namespace) -> int:
    summary = build_corpus(args.source, args.out, args.salt, args.notes)
    print(
        f"ok: {summary.raw} raw runs, {summary.unique} unique traces, {summary.groups} groups, "
        f"{summary.heldout_groups} heldout"
    )
    return 0


def cmd_corpus_verify(args: argparse.Namespace) -> int:
    frozen = args.frozen_manifest.read_bytes() if args.frozen_manifest else None
    require_valid(args.corpus, frozen)
    print("ok: corpus matches its split manifest")
    return 0


def cmd_corpus_card(args: argparse.Namespace) -> int:
    text = render_card(args.corpus)
    if args.check:
        current = args.out.read_bytes().decode("utf-8") if args.out.is_file() else None
        if current != text:
            print(f"{shown_path(args.out)} is out of date; run `gauntlet corpus card`")
            return 1
        print("ok: dataset card matches the corpus")
        return 0
    write_text(args.out, text)
    print(f"ok: wrote {shown_path(args.out)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gauntlet",
        description="Evaluate AI-agent detections against labeled traces.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--root",
        type=Path,
        help="repository root that recorded and printed paths are relative to "
        "(default: nearest parent of the working directory holding .git)",
    )
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
    p.add_argument(
        "--external-basename",
        action="store_true",
        help="allow inputs outside the repository root and record only their file names",
    )
    p.set_defaults(handler=cmd_metrics)

    corpus = sub.add_parser("corpus", help="build, verify or describe the frozen corpus")
    csub = corpus.add_subparsers(dest="corpus_command", required=True, metavar="action")
    c = csub.add_parser("build", help="dedupe exports and split by variant group")
    c.add_argument("--source", type=Path, action="append", required=True, help="export dir")
    c.add_argument("--out", type=Path, default=DEFAULT_CORPUS)
    c.add_argument("--salt", required=True, help="split salt, recorded in the manifest")
    c.add_argument(
        "--notes", type=Path, default=None, help="class notes and known gaps (JSON), recorded"
    )
    c.set_defaults(handler=cmd_corpus_build)
    c = csub.add_parser("verify", help="check the corpus against SPLIT_MANIFEST.json")
    c.add_argument("corpus", type=Path, nargs="?", default=DEFAULT_CORPUS)
    c.add_argument(
        "--frozen-manifest", type=Path, default=None, help="manifest from the freeze commit"
    )
    c.set_defaults(handler=cmd_corpus_verify)
    c = csub.add_parser("card", help="render the dataset card from the corpus")
    c.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    c.add_argument("--out", type=Path, default=DEFAULT_CARD)
    c.add_argument("--check", action="store_true", help="fail if the card is out of date")
    c.set_defaults(handler=cmd_corpus_card)

    p = sub.add_parser("export-schemas", help="regenerate the JSON Schemas")
    p.add_argument("--out", type=Path, default=DEFAULT_SCHEMAS)
    p.add_argument("--check", action="store_true", help="fail if checked-in schemas drifted")
    p.set_defaults(handler=cmd_export_schemas)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_repo_root(args.root)
    try:
        return int(args.handler(args))
    except GauntletError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        where = f"{shown_path(str(exc.filename))}: " if exc.filename else ""
        print(f"error: {where}{exc.strerror or type(exc).__name__}", file=sys.stderr)
        return 1
