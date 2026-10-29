# agent-detection-gauntlet

A research platform that measures which AI-agent detection techniques stay effective when
attackers deliberately evade them. Agent traces are recorded in a fixed schema, detection rules
are run over them by a deterministic engine, and every result is scored against ground truth
that the engine never sees. The goal is a measured answer, with denominators and confidence
intervals, rather than a list of claimed coverage.

Core question:

> Which AI-agent detection techniques remain effective when attackers intentionally evade them?

## Pipeline

1. **Attack**: run known attack classes against instrumented agents, alongside benign work.
2. **Telemetry**: record every run as a trace of schema-checked JSONL events.
3. **Detection**: evaluate content, sequence and behavior rules over the traces.
4. **Evasion**: mutate payloads and vary attack structure, then capture new traces.
5. **Validation**: score detections against held-out ground truth with intervals.
6. **Findings**: report what held up, what did not, and the limits of the measurement.

## Status

**Phase 0: foundation, no findings yet.**

Phase 0 contains:

- A trace schema for agent sessions, aligned with the OpenTelemetry GenAI semantic conventions
  plus a small set of `adg.*` provenance extensions ([docs/schema.md](docs/schema.md)).
- A native YAML rule format with framework mappings, hypothesis, limitations and fixtures
  ([docs/rule-format.md](docs/rule-format.md)).
- A detection engine with three primitives: `match`, `sequence` (with value binding and
  provenance following) and `threshold` ([docs/engine.md](docs/engine.md)).
- A rule validator that checks schema, mapping IDs against a catalog, and true positive and
  false positive fixtures.
- A metrics stage that produces session-level confusion matrices and rates with Wilson 95%
  intervals ([docs/metrics.md](docs/metrics.md)).
- A command line interface, `gauntlet`.
- Nine synthetic fixture traces with labels, used only to check that the pipeline works.

## Quickstart

Requires Python 3.12 or later.

```sh
python3.12 -m venv .venv
# Windows: .venv\Scripts\activate
. .venv/bin/activate
pip install -e ".[dev]"
```

Run the five commands in order from the repository root:

```sh
# 1. Check trace files against the schema and cross-event integrity rules.
gauntlet validate-traces datasets/fixtures/traces

# 2. Check rules: schema, file names, mapping IDs, and tp/fp fixtures.
gauntlet validate-rules rules

# 3. Run the rules over traces and write detection records.
gauntlet scan --rules rules --traces datasets/fixtures/traces --out out/detections.jsonl

# 4. Score detections against ground-truth labels.
gauntlet metrics --rules rules --traces datasets/fixtures/traces \
  --detections out/detections.jsonl --labels datasets/fixtures/labels.jsonl \
  --out out/metrics.json

# 5. Regenerate the JSON Schemas, or check that the committed ones are current.
gauntlet export-schemas
gauntlet export-schemas --check
```

Notes:

- `metrics` takes `--rules` and `--traces` in addition to `--detections` and `--labels`. It
  re-validates the rule set, checks that rules, traces, labels and detections line up, and
  records a sha256 of every input in the report.
- `metrics` defaults to `--split heldout`. Pass `--split dev` to score the development split.
- `validate-rules`, `scan` and `metrics` run each rule against its fixtures before doing
  anything else. Fixtures are read from `datasets/fixtures/traces` by default; use
  `--fixtures` to point elsewhere.
- Every path recorded in a report or printed in a log is relative to the repository root, so
  reports do not depend on the working directory. `metrics` refuses inputs outside the root
  unless `--external-basename` is given, which records their file names only.
- `out/` is ignored by git. Any numbers produced from the fixtures are pipeline checks on
  synthetic data, not findings.

## Scope and limits

- Local only. The tool reads and writes local files. It is not a monitoring product and has no
  live SIEM integration.
- Synthetic fixtures only until Phase 1. Real traces will come from instrumented attack and
  defense lab environments.
- Framework mapping IDs (MITRE ATLAS, OWASP, MITRE ATT&CK) are listed in a catalog but are not
  yet verified against the primary sources. The validator warns about each one. Verification
  is scheduled for Phase 7.
- The OpenTelemetry GenAI conventions are still marked as development (experimental). The trace
  schema is versioned so it can follow them when they change.

## Repository layout

| Path | Contents |
| --- | --- |
| `src/agent_detection_gauntlet/schema/` | Trace event, label and detection models; JSON Schema export |
| `src/agent_detection_gauntlet/rules/` | Rule model, YAML loader, rule validator |
| `src/agent_detection_gauntlet/engine/` | Field resolution, conditions, primitives, executor |
| `src/agent_detection_gauntlet/metrics/` | Rates, Wilson intervals, scoring, report model |
| `src/agent_detection_gauntlet/io/` | Strict JSONL reading, trace and label loading |
| `src/agent_detection_gauntlet/catalog/` | Mapping ID catalogs for ATLAS, OWASP LLM, OWASP Agentic, ATT&CK |
| `src/agent_detection_gauntlet/cli.py` | The `gauntlet` command |
| `rules/` | Detection rules, one YAML file per rule, named after the rule id |
| `datasets/fixtures/` | Synthetic fixture traces and their labels |
| `schemas/` | Generated JSON Schemas for every file format |
| `tests/` | Test suite |
| `tools/leak_guard.py` | Standalone guard against personal data, local paths and secrets |
| `.githooks/` | Pre-commit and pre-push hooks that run the leak guard |
| `docs/` | Format, engine, metrics and methodology documentation |

## Documentation

- [docs/schema.md](docs/schema.md): trace, label and detection formats
- [docs/rule-format.md](docs/rule-format.md): rule fields, logic grammar, mappings, validator
- [docs/engine.md](docs/engine.md): exact engine semantics
- [docs/metrics.md](docs/metrics.md): metric definitions and the report format
- [docs/methodology.md](docs/methodology.md): measurement principles and limitations
- [ROADMAP.md](ROADMAP.md): phases and gates
- [SECURITY.md](SECURITY.md): security scope and reporting
- [CONTRIBUTING.md](CONTRIBUTING.md): setup, checks, the leak guard and git hooks

## License

MIT. See [LICENSE](LICENSE).
