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
from agent_detection_gauntlet.firewall import (
    refuse_heldout,
    refuse_output,
    require_clearance,
)
from agent_detection_gauntlet.fit import fit_baselines
from agent_detection_gauntlet.io.jsonl import pretty_json, read_jsonl, write_jsonl, write_text
from agent_detection_gauntlet.io.labels import load_labels
from agent_detection_gauntlet.io.traces import load_traces
from agent_detection_gauntlet.metrics.compute import (
    ScoringInputs,
    build_report,
    check_detections_reproduce,
    git_provenance,
    sha256_file,
)
from agent_detection_gauntlet.metrics.report import InputRole
from agent_detection_gauntlet.paths import set_repo_root, shown_path
from agent_detection_gauntlet.rules.docgen import render as render_rules_doc
from agent_detection_gauntlet.rules.validator import ValidationReport, validate_rules
from agent_detection_gauntlet.schema.detection import Detection
from agent_detection_gauntlet.schema.export import export_schemas, schema_drift
from agent_detection_gauntlet.schema.labels import LabelSource, Split
from agent_detection_gauntlet.validation.prereg import (
    BASELINE_REPORT,
    BASELINE_RESULTS,
    PREREG_DOC,
    PREREG_JSON,
    RESULTS_ROOT,
    build_preregistration,
    dump_preregistration,
    read_preregistration,
    read_results,
    render_preregistration,
    rule_hash_drift,
    verify,
)
from agent_detection_gauntlet.validation.report import render_results
from agent_detection_gauntlet.validation.score import score_split, traces_dir

# Rule fixtures: the synthetic traces and the dev split at the default content-reference K.
DEFAULT_FIXTURES = [Path("datasets/fixtures/traces"), Path("datasets/corpus/dev/k24")]
DEFAULT_SCHEMAS = Path("schemas")


def _print_issues(report: ValidationReport) -> None:
    for issue in report.issues:
        print(issue.render(), file=sys.stderr)


def _require_valid_rules(rules_dir: Path, fixtures: Sequence[Path]) -> ValidationReport:
    refuse_heldout(fixtures, "rule fixtures")
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
    refuse_heldout(args.fixtures, "rule fixtures")
    report = validate_rules(args.directory, args.fixtures, load_catalog())
    _print_issues(report)
    if not report.ok:
        print(f"failed: {len(report.errors)} error(s), {len(report.warnings)} warning(s)")
        return 1
    print(f"ok: {len(report.rules)} rule(s), {len(report.warnings)} warning(s)")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    refuse_output(args.out)
    require_clearance("scan", args.traces)
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
    refuse_output(args.out)
    logged = require_clearance("metrics", [*args.traces, args.detections, args.labels])
    labels = load_labels([args.labels])
    split = Split(args.split)
    # Synthetic fixtures carry heldout labels too; only corpus labels are the real split.
    scores_corpus = split is Split.HELDOUT and any(
        label.split is Split.HELDOUT and label.source is not LabelSource.SYNTHETIC
        for label in labels.values()
    )
    if scores_corpus and not logged:
        require_clearance("metrics", [], scoring_split=True, anchors=[args.labels])
    report = _require_valid_rules(args.rules, args.fixtures)
    trace_set = load_traces(args.traces)
    detections = [record for _, record in read_jsonl(args.detections, Detection)]
    rules = [loaded.rule for loaded in report.rules]
    check_detections_reproduce(detections, scan(rules, trace_set.traces))
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
    refuse_output(args.out)
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
DEFAULT_RULES = Path("rules")
DEFAULT_DETECTIONS_DOC = Path("docs/detections.md")
DEFAULT_FIT_TRACES = [DEFAULT_CORPUS / "dev" / "k24"]
DEFAULT_FIT_LABELS = DEFAULT_CORPUS / "labels.jsonl"


def cmd_fit_baselines(args: argparse.Namespace) -> int:
    outcome = fit_baselines(args.rules, args.traces, args.labels, check=args.check)
    if args.check and outcome.stale:
        for path in outcome.stale:
            print(f"error: {shown_path(path)} is out of date", file=sys.stderr)
        print("run `gauntlet fit-baselines` and commit the result", file=sys.stderr)
        return 1
    print(f"ok: {outcome.fitted} baseline rule(s), {len(outcome.written)} rewritten")
    return 0


def cmd_rules_doc(args: argparse.Namespace) -> int:
    refuse_output(args.out)
    text = render_rules_doc(args.rules)
    if args.check:
        current = args.out.read_bytes().decode("utf-8") if args.out.is_file() else None
        if current != text:
            print(f"{shown_path(args.out)} is out of date; run `gauntlet rules-doc`")
            return 1
        print("ok: detections doc matches the rules")
        return 0
    write_text(args.out, text)
    print(f"ok: wrote {shown_path(args.out)}")
    return 0


def cmd_validation_prereg(args: argparse.Namespace) -> int:
    refuse_output(args.out)
    refuse_output(args.doc)
    if args.out.exists():
        raise GauntletError(f"{shown_path(args.out)} already exists; a registration is frozen")
    commit, dirty = git_provenance()
    if commit is None or dirty is not False:
        raise GauntletError("register from a clean git checkout, so the tooling commit is exact")
    report = _require_valid_rules(args.rules, args.fixtures)
    plan = build_preregistration(report.rules, args.corpus, commit)
    write_text(args.out, dump_preregistration(plan))
    write_text(args.doc, render_preregistration(plan))
    print(f"ok: registered {len(plan.rules)} rule(s) -> {shown_path(args.out)}")
    return 0


def cmd_validation_score(args: argparse.Namespace) -> int:
    if not args.check and args.out is None:
        raise GauntletError("score needs --out or --check")
    for output in (args.out, args.detections_dir):
        if output is not None:
            refuse_output(output)
    plan = read_preregistration(args.prereg)
    split = Split(args.split)
    report = _require_valid_rules(args.rules, args.fixtures)
    drift = rule_hash_drift(plan, report.rules)
    if args.check:
        golden = read_results(args.results)
        current = {item.rule.id: sha256_file(item.path) for item in report.rules}
        if current != {rule.id: rule.sha256 for rule in golden.rules}:
            print("skipped: rule hashes differ from the golden file, whose rules are historical")
            return 0
    if drift:
        raise GauntletError("rules differ from the pre-registration: " + "; ".join(drift))
    paths = [traces_dir(args.corpus, split, k) for k in plan.content_ref_ks]
    command = "validation score --check" if args.check else "validation score"
    require_clearance(command, paths)
    scored = score_split(plan, sha256_file(args.prereg), report.rules, args.corpus, split)
    if args.detections_dir is not None:
        for k, records in scored.detections.items():
            write_jsonl(args.detections_dir / f"detections-k{k}.jsonl", records)
    text = pretty_json(scored.results.model_dump(mode="json"))
    if args.check:
        if args.results.read_bytes() != text.encode("utf-8"):
            print(f"error: {shown_path(args.results)} differs from a fresh score", file=sys.stderr)
            return 1
        print("ok: a fresh score is byte-identical to the golden file")
        return 0
    write_text(args.out, text)
    print(f"ok: split {split.value} scored -> {shown_path(args.out)}")
    return 0


def cmd_validation_report(args: argparse.Namespace) -> int:
    refuse_output(args.out)
    text = render_results(read_results(args.results), read_preregistration(args.prereg))
    if args.check:
        current = args.out.read_bytes().decode("utf-8") if args.out.is_file() else None
        if current != text:
            print(f"{shown_path(args.out)} is out of date; run `gauntlet validation report`")
            return 1
        print("ok: results report matches the JSON")
        return 0
    write_text(args.out, text)
    print(f"ok: wrote {shown_path(args.out)}")
    return 0


def cmd_validation_verify(args: argparse.Namespace) -> int:
    report = _require_valid_rules(args.rules, args.fixtures)
    frozen = args.frozen_prereg.read_bytes() if args.frozen_prereg else None
    problems = verify(args.prereg, args.doc, args.results_root, report.rules, frozen)
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    if problems:
        return 1
    if args.prereg.is_file():
        print("ok: registration frozen, rule hashes and results agree")
    else:
        print("ok: no pre-registration yet and no results")
    return 0


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
    refuse_output(args.out)
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

    default_fixtures = " ".join(path.as_posix() for path in DEFAULT_FIXTURES)
    fixtures_help = f"fixture trace files or directories (default: {default_fixtures})"

    p = sub.add_parser("validate-traces", help="validate trace JSONL files")
    p.add_argument("paths", nargs="+", type=Path, help="trace files or directories")
    p.set_defaults(handler=cmd_validate_traces)

    p = sub.add_parser("validate-rules", help="validate a directory of rules")
    p.add_argument("directory", type=Path)
    p.add_argument("--fixtures", nargs="+", type=Path, default=DEFAULT_FIXTURES, help=fixtures_help)
    p.set_defaults(handler=cmd_validate_rules)

    p = sub.add_parser("scan", help="run rules over traces and write detections")
    p.add_argument("--rules", type=Path, required=True)
    p.add_argument("--traces", nargs="+", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--fixtures", nargs="+", type=Path, default=DEFAULT_FIXTURES, help=fixtures_help)
    p.set_defaults(handler=cmd_scan)

    p = sub.add_parser("metrics", help="score detections against labels")
    p.add_argument("--rules", type=Path, required=True)
    p.add_argument("--traces", nargs="+", type=Path, required=True)
    p.add_argument("--detections", type=Path, required=True)
    p.add_argument("--labels", type=Path, required=True)
    p.add_argument("--split", choices=[split.value for split in Split], default=Split.HELDOUT.value)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--fixtures", nargs="+", type=Path, default=DEFAULT_FIXTURES, help=fixtures_help)
    p.add_argument(
        "--external-basename",
        action="store_true",
        help="allow inputs outside the repository root and record only their file names",
    )
    p.set_defaults(handler=cmd_metrics)

    p = sub.add_parser("fit-baselines", help="fit behavior baselines on dev benign traces")
    p.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    p.add_argument("--traces", nargs="+", type=Path, default=DEFAULT_FIT_TRACES)
    p.add_argument("--labels", type=Path, default=DEFAULT_FIT_LABELS)
    p.add_argument("--check", action="store_true", help="fail if a fitted rule is out of date")
    p.set_defaults(handler=cmd_fit_baselines)

    p = sub.add_parser("rules-doc", help="render the detection catalog from the rules")
    p.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    p.add_argument("--out", type=Path, default=DEFAULT_DETECTIONS_DOC)
    p.add_argument("--check", action="store_true", help="fail if the doc is out of date")
    p.set_defaults(handler=cmd_rules_doc)

    validation = sub.add_parser("validation", help="pre-register, score and report the baseline")
    vsub = validation.add_subparsers(dest="validation_command", required=True, metavar="action")
    v = vsub.add_parser("prereg", help="freeze the rule hashes and the plan, once")
    v.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    v.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    v.add_argument("--out", type=Path, default=PREREG_JSON)
    v.add_argument("--doc", type=Path, default=PREREG_DOC)
    v.add_argument("--fixtures", nargs="+", type=Path, default=DEFAULT_FIXTURES, help=fixtures_help)
    v.set_defaults(handler=cmd_validation_prereg)
    v = vsub.add_parser("score", help="score a split as registered and write the results")
    v.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    v.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    v.add_argument("--prereg", type=Path, default=PREREG_JSON)
    v.add_argument("--split", choices=[split.value for split in Split], default=Split.HELDOUT.value)
    v.add_argument("--out", type=Path, default=None, help="results file to write")
    v.add_argument("--results", type=Path, default=BASELINE_RESULTS, help="golden file for --check")
    v.add_argument("--check", action="store_true", help="fail if a fresh score differs from it")
    v.add_argument("--detections-dir", type=Path, default=None, help="also write detections here")
    v.add_argument("--fixtures", nargs="+", type=Path, default=DEFAULT_FIXTURES, help=fixtures_help)
    v.set_defaults(handler=cmd_validation_score)
    v = vsub.add_parser("report", help="render the results report from the JSON")
    v.add_argument("--prereg", type=Path, default=PREREG_JSON)
    v.add_argument("--results", type=Path, default=BASELINE_RESULTS)
    v.add_argument("--out", type=Path, default=BASELINE_REPORT)
    v.add_argument("--check", action="store_true", help="fail if the report is out of date")
    v.set_defaults(handler=cmd_validation_report)
    v = vsub.add_parser("verify", help="check the registration, rule hashes and results agree")
    v.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    v.add_argument("--prereg", type=Path, default=PREREG_JSON)
    v.add_argument("--doc", type=Path, default=PREREG_DOC)
    v.add_argument("--results-root", type=Path, default=RESULTS_ROOT)
    v.add_argument(
        "--frozen-prereg", type=Path, default=None, help="registration as first committed"
    )
    v.add_argument("--fixtures", nargs="+", type=Path, default=DEFAULT_FIXTURES, help=fixtures_help)
    v.set_defaults(handler=cmd_validation_verify)

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
