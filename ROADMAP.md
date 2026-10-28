# Roadmap

The project answers one question:

> Which AI-agent detection techniques remain effective when attackers intentionally evade them?

Work is split into eight phases. Each phase has a goal and a gate. A phase is done only when its
gate is met.

## Principles

1. Telemetry comes from real agent runs, not synthetic strings. Synthetic data is used only to
   check the pipeline.
2. Sequence and behavior detections are measured next to content (keyword) baselines.
3. Precision and recall are measured, not asserted.
4. Coverage is computed from measured results, never declared.
5. Evasion testing is a first-class part of the evaluation.
6. MITRE ATLAS is the primary mapping. MITRE ATT&CK is used only when the agent performs a host
   action.

## Methodology commitments

These apply to every phase. [docs/methodology.md](docs/methodology.md) explains them in more
detail.

- A held-out split of roughly 30% of traces is frozen before Phase 2. Rules are written without
  access to it.
- Published metrics come only from the held-out split.
- Ground truth lives in a separate labels file, never inside traces. The engine never reads
  labels.
- Malicious runs where the attack did not succeed go to an `attack_failed` bucket. They are
  excluded from recall and reported with their count.
- Every rate ships with its numerator, denominator and a Wilson 95% interval. Undefined rates
  are null, never 0.
- Agent runs use a fixed seed and temperature, with N runs per case.
- Hypotheses stay hypotheses until measured. If keyword rules beat sequence or behavior rules on
  some attack class, that is a finding and is reported as one.

## Phase 0: Foundation (in progress)

**Goal:** the repository, a JSONL trace schema aligned with the OpenTelemetry GenAI semantic
conventions, the native rule format, a detection engine with `match`, `sequence` (with binding)
and `threshold`, a rule validator, a metrics framework, synthetic fixtures, tests, linting and
CI. Runs on synthetic fixtures only.

**Gate:** CI is green, a trace loads, a rule executes, a detection is generated, and the metrics
JSON is byte-identical across two runs.

## Phase 1: Telemetry

**Goal:** instrument the attack and defense lab environments so every run emits standardized
traces: prompts, retrieved documents, tool calls and arguments, tool outputs, model responses and
guardrail actions. Build a benign corpus that includes hard negatives: legitimate traces that
read secrets, send messages, chain many tools, and fetch untrusted web content. Label every trace
with whether guardrails were on or off. Freeze the held-out split at the end of the phase.

**Gate:** at least 20 successful malicious runs per attack class, at least 200 benign traces
including hard negatives, fixed seed and temperature, and all traces pass schema validation.

If telemetry quality is insufficient, stop and fix telemetry before moving on, then revalidate.

## Phase 2: Detections

**Goal:** 12 to 15 rules across three tiers:

- Content: analysis of prompts, responses and tool arguments.
- Sequence: untrusted source, then ingestion, then tool execution, then a sensitive sink, with
  values carried between steps.
- Behavior: novel tool use, excessive chaining, privilege escalation, abnormal execution paths.

Each rule carries a threat description, a hypothesis, MITRE ATLAS, OWASP LLM and OWASP Agentic
mappings (MITRE ATT&CK when a host action occurs), expected telemetry, logic, limitations, and
true positive and false positive fixtures.

**Gate:** every rule passes its true positive and false positive tests on development data.

## Phase 3: Baseline validation

**Goal:** score every rule on unmutated held-out attacks and the benign corpus. Report TP, FP,
TN, FN, precision, recall, F1, false positive rate and detection rate, all with denominators.
Add a regression suite.

**Gate:** metrics are generated and reproducible in CI.

## Phase 4: Evasion research

**Goal:** test every rule against two separate categories of evasion.

- Payload mutations: paraphrase, translation, base64, Unicode tricks, homoglyphs and prompt
  splitting. A local model produces the mutations at a fixed seed, and they are re-executed
  against the agent to produce new traces. Content rules may also be scored on offline text mutations.
  Sequence and behavior rules are scored only on re-executed traces.
- Attack variants: indirect instruction, retrieval poisoning, tool indirection and multi-stage
  attacks, each captured as its own traces.

Attack success rate is reported per mutation class.

**Gate:** every rule is tested against every mutation class, results are stored automatically,
and each result is reported as a change from the Phase 3 baseline.

## Phase 5: Coverage

**Goal:** compute coverage. A technique counts as covered only when a detection exists, it has
a passing held-out true positive test, and its false positive rate is under a stated threshold.
Coverage is mapped to MITRE ATLAS, OWASP LLM, OWASP Agentic, and MITRE ATT&CK where applicable.

**Gate:** no manually declared coverage anywhere.

## Phase 6: Detection engineering

**Goal:** the native rule format stays the source of truth. Converted artifacts for common SIEM
query languages are generated automatically, each labeled "converted, not live SIEM validated".
Add rule linting and a release workflow.

**Gate:** artifact generation, linting and release workflows succeed.

## Phase 7: Research publication

**Goal:** publish the results: an architecture diagram, a static coverage dashboard built from
CI output, a detection catalog, a findings write-up and a short demo. Verify every MITRE ATLAS
and OWASP ID against the primary source and mark the catalog entries as verified.

The write-up answers:

- Which detection tier performs best on unmutated attacks?
- Which mutations evade which tiers, and by how much?
- How do sequence and behavior detections compare with content detections under each mutation
  class?
- What coverage gaps remain?

Known limitations to state: a single local model, a single-author corpus, guardrails labeled per
trace, and OpenTelemetry GenAI conventions pinned to one version.

**Gate:** an independent review and a pre-publication audit are complete.
