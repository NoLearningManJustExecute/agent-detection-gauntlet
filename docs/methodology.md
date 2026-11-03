# Methodology

This document states the measurement principles the project follows. They exist so that a
reported number means what it appears to mean. The roadmap in [ROADMAP.md](https://github.com/NoLearningManJustExecute/agent-detection-gauntlet/blob/main/ROADMAP.md) lists
them as commitments for every phase.

## Ground truth is separate from evidence

Traces are the evidence: what the agent did, as recorded by instrumentation. Labels are the
ground truth: whether a trace is malicious, whether the attack succeeded, which split it belongs
to. They live in different files.

- Labels are never stored inside traces. The trace schema has no field for them.
- The engine never reads labels. `gauntlet scan` takes rules and traces only.
- Only the metrics stage joins detections to labels, after detection is finished.

This keeps detection logic from depending, even by accident, on information a real defender
would not have.

## Held-out discipline

- Before detection work begins (Phase 2), roughly 30% of traces are assigned to a `heldout`
  split and the assignment is frozen.
- Rules are written and tuned on the `dev` split only. Rule authors do not look at held-out
  traces or held-out results while writing rules.
- Published metrics come only from the held-out split. `gauntlet metrics` scores `heldout` by
  default and records the split in every report.
- If held-out results are poor, the rule is not retuned against them and re-scored. Results are
  reported as measured.
- `gauntlet validation score` also refuses to run unless the rules match a committed
  pre-registration hash for hash. CI re-scores and fails on any change to the golden file while
  rule hashes are unchanged.
- The command line enforces this. `gauntlet scan`, `gauntlet metrics` and
  `gauntlet validation score` refuse held-out inputs unless `GAUNTLET_SCORING_HELDOUT=1` is set, and every such run is appended to
  [heldout-log.md](heldout-log.md), in the checkout the input sits in, before any trace is read.
  An input counts as held-out by what it would read: its path or an expanded file is under
  `corpus/heldout`, or a file's hash is pinned as held-out in the split manifest. `metrics` checks
  `--traces`, `--detections` and `--labels` this way, then reads the labels and also treats scoring
  the held-out split of labels that are not synthetic as a held-out read. Rule fixtures and baseline
  fits refuse held-out data whatever the environment says. Commands that take `--out` may not write
  into the held-out folder or over the log; `gauntlet corpus build` is the one exception, since it
  creates the split, and CI's freeze check covers it.
- Evasion inputs and traces (`datasets/evasion`) derive from held-out attacks, so the same checks
  treat them as held-out data. `gauntlet evasion score` and `gauntlet evasion mutate` log their reads.
- What the firewall protects is held-out attack content reaching detection work. Blocked: showing
  held-out attack content to rule authoring or human review, and scoring the held-out split before
  rules are frozen and pre-registered.
- Allowed: opaque byte-level access by privacy and integrity tooling, which pattern-matches or
  parses without showing attack content to whoever writes the rules. The leak guard scans every
  file, held-out included, because privacy scanning is mandatory and has no exceptions, and it
  reports hits only. `gauntlet validate-traces`, `gauntlet corpus verify` and `gauntlet corpus card`
  read the split for CI's schema and freeze checks. Manifest and label parsing and lint also read
  it. Folder names alone carry no attack content.
- Known limits of the command-line checks: a deleted manifest disables copy detection, and an
  edited copy no longer matches its pinned hash; path checks still apply. `gauntlet scan` and
  `gauntlet metrics` with the variable set read held-out data without asking for a registration
  (the run is still logged), and `gauntlet validation score --prereg` accepts any valid file;
  `gauntlet validation verify` is what ties committed results to the frozen registration.
- Behavior thresholds are fitted by code on dev benign traces only, and the fit command is
  recorded in the rule. See [engine.md](engine.md#baseline).

## Outcome buckets

Not every malicious run is an attack that worked. A run where the agent ignored the injected
instruction, or a guardrail blocked the action, is malicious in intent but did no harm. Counting
it as a positive that a rule should catch would distort recall in either direction.

So every scored trace falls into one bucket: `benign`, `malicious_succeeded` or `attack_failed`.
Precision, recall and the other rates use only `benign` and `malicious_succeeded`. The
`attack_failed` bucket is reported with its count and with how many of its traces each rule
detected. Definitions are in [metrics.md](metrics.md).

## Denominators and intervals

- Every rate is published with its numerator and denominator.
- Every proportion carries a Wilson 95% interval. Small denominators produce wide intervals, and
  the width is part of the result.
- A rate with a zero denominator is undefined and reported as `null`, never as 0.
- F1 is reported without an interval because it is not a binomial proportion.

## Determinism

- The engine and the metrics stage are deterministic. The same inputs give byte-identical
  detection files and metrics reports. Neither contains wall-clock time.
- Every metrics report records the sha256 of each input file, the package version, and the git
  commit and dirty flag of the code that produced it.
- Agent runs use a fixed seed and a fixed temperature, with N runs per case, so
  that variation between runs can be measured rather than hidden.

## Synthetic fixtures

The traces in `datasets/fixtures/` are hand-written synthetic data. They exist to check that the
pipeline works end to end: that traces load, rules fire where they should and stay silent where
they should, and metrics are computed correctly. Numbers produced from them are pipeline checks.
**They are never published as findings** about any detection technique.

## Framework mappings

Rules map to MITRE ATLAS, the OWASP Top 10 for LLM Applications, the OWASP Top 10 for Agentic
Applications and, when the agent performs a host action, MITRE ATT&CK. Every mapping ID must
exist in the catalog shipped with the package. An entry is marked verified only when its ID and
title matched the primary source, and the validator warns about every unverified ID. The result of
that check is in [mappings.md](mappings.md).

## Hypotheses and findings

Each rule states a hypothesis about why it should work. A hypothesis stays a hypothesis until
held-out measurement supports or refutes it. If simple keyword rules outperform sequence or
behavior rules on some attack class, that is a finding and is reported as one.

Coverage is computed from measured results, never declared. A technique counts as covered only
when a rule for it passes a held-out true positive test with a false positive rate under a stated
threshold. The computed table is [coverage.md](coverage.md).

## Limitations

The full list is in [limitations.md](limitations.md). These are the ones about method.

- **Single-author corpus.** Attacks, benign traces and rules were written by one author. Blind
  spots in that author's view of attacks and normal use carry into the results. The held-out
  split guards against overfitting to specific traces, not against a shared bias in how all
  traces were made.
- **Limited model coverage.** Every run used a single local model. Results may not transfer to
  other models or agent frameworks.
- **Guardrails are labeled per trace.** A trace is labeled with guardrails on or off as a whole,
  not per action.
- **OpenTelemetry GenAI conventions are experimental.** Every GenAI attribute used has stability
  `development` and may change. The trace schema is pinned to one version (see
  [schema.md](schema.md)) and versioned so it can move.
- **Provenance depends on instrumentation.** Sequence rules that follow `adg.content.ref` are
  only as good as the provenance links recorded. Missing links cause misses; overly broad links
  cause false positives.
- **No live SIEM validation.** Rules run only in this engine. Converted artifacts are labeled as
  not validated on a live SIEM.
