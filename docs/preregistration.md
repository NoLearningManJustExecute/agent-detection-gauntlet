# Pre-registration: baseline validation

Rendered by `gauntlet validation prereg` from `docs/preregistration.json`, which is frozen once
committed. CI fails if the JSON changes, if this text changes, or if a results file names
different rule hashes. Later phases may append below the end marker.

This file was committed and pushed alone, before any held-out scoring. The first row of
`docs/heldout-log.md` names the commit that scored, and `git log` on the phase branch shows this
file arriving first. No held-out trace was read, and no held-out result existed, when it was
written. The scorer was dry-run on the dev split to check the pipeline, after the thresholds below
were fixed in code. No rule changed afterwards and no dev metric was committed.

## Frozen rule set

Rule files as of tooling commit `e62a78566645b03d6b5791764e5e762b002dc259`.

| Rule | Version | Tier | sha256 |
|---|---|---|---|
| ADG-0001 | 0.1.1 | sequence | `3b36938d7dacae92febc831cfa0abb4e26d6da9f1a2d1429ec393852f0efef8b` |
| ADG-0002 | 0.1.0 | content | `0c9bb5dffa3336127e04e8a0b0ff8a56ac2811cf16bd4c745b5849ba7d7ea12a` |
| ADG-0003 | 0.1.0 | content | `cb87ef68bd5f23f1140fe8543a48b9ff52114e6bb0d1fbb394daf1097f72ec59` |
| ADG-0004 | 0.1.0 | content | `b20de768ae2c1918ff1ddc6a74526c6ff453c9d8eff9e28dbc2e464093e2f5d7` |
| ADG-0005 | 0.1.0 | content | `5b3ef7534ed06da43648a6988cc7b0c84245a28048d0ac9598a20259c99b2316` |
| ADG-0006 | 0.1.0 | content | `55a771de8cfd61912ff0e679169c669fccf0da8770528fbb4003b72bd54c01fe` |
| ADG-0007 | 0.1.0 | sequence | `26e2888cc5388ebaad31e69a353fcd6cb416bcdd3b7a27969f519feafdea608e` |
| ADG-0008 | 0.1.0 | sequence | `6475093289318763d99b8b0e6d869d1b72b94019a7987395e78c02d102f02efe` |
| ADG-0009 | 0.1.0 | sequence | `cd4816634bb64b414860cd6f07e765a251296ddd6215bb06638ef344a04fcb0e` |
| ADG-0010 | 0.1.0 | sequence | `0870bb33b8bf177d8ad7d5a84dae98dca9a1eab7934d1bf0302997586455a642` |
| ADG-0011 | 0.1.0 | behavior | `2426f8fc9ff65a0a359d86e7e8a1786bff4827e7e4282ca3c3592cf0446f66d1` |
| ADG-0012 | 0.1.0 | behavior | `0b4d2aaca4f56715ff5921cb7b63a66a699b98c933f3fde7d461b7895877746b` |
| ADG-0013 | 0.1.0 | behavior | `43ca7133b2239e84b69b30aeb22be883effb6bfc2e10c3baf83b33ee7ed96a2f` |
| ADG-0014 | 0.1.0 | behavior | `5936f9aabcaf27d75e52d8e156f54dc3112bc740dd374724e4f4af4c61b3d8b1` |

Baseline sidecars: none. Fitted baseline values live inside the rule files (`fitted`), so the
hashes above cover them. Fit command and population are recorded in each behavior rule.

Corpus pins: `SPLIT_MANIFEST.json` sha256 `63dc33b98482cabd2319a65dcfd36a8206ecbe9276dfbf9113462097e2b1a5bf`, `labels.jsonl` sha256
`1734e7a10906eca9a4fc086a667f6c10c52e7733ce4a5ca26ae784453aa10eff`.

## Exact commands

```sh
GAUNTLET_SCORING_HELDOUT=1 gauntlet validation score --out results/baseline/metrics.json --detections-dir out/baseline
gauntlet validation report
gauntlet validation verify
GAUNTLET_SCORING_HELDOUT=1 gauntlet validation score --check
```

The first scores and writes the golden file, plus detection records under `out/`, which git
ignores and which hold ids and timestamps but no trace text; an audit can recompute every count
from them and the labels without reading a trace. The second renders `docs/results-baseline.md` from the
golden file. The third checks hashes. The fourth is the regression check, run by CI. Only the
commands that set `GAUNTLET_SCORING_HELDOUT=1` read held-out data. Each such run appends a row to
`docs/heldout-log.md` before any trace is read; rows from CI land on a discarded runner and are
not committed, and CI runs the check only once a golden file exists.

The scorer reads its parameters from the frozen JSON and refuses to run if any rule file differs
from the table above. It stores counts, rule ids and label metadata only, no trace content.

## Population

- Split: heldout. Unit: one trace (session-level), as in [metrics.md](metrics.md).
  Traces are unique after the corpus dedupe. Primary content-reference export: K=24.
- Positives: traces with `attack_succeeded: true`, pooled across every class that has them.
- Negatives: every benign trace in the held-out split, hard negatives included and none removed.
  The dev benign traces are not used: behavior thresholds were fitted on them and rules were
  written against them, and published metrics come only from the held-out split. "The full benign
  corpus" is read as the whole held-out benign population.
- `attack_failed` traces are in neither denominator and are reported as counts.
- The authored `-OBF` scenarios sit in the plain scenario's group and are in the population. They
  use encodings reserved for Phase 4, so recall without them is reported as a sensitivity check.

## Ineffective classes excluded from recall denominators

AC03, AC09, AC10. No group of these classes succeeded at baseline. Their traces are reported on their
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
  recall denominator below 10 is flagged small-N. AC06, AC12A are below the
  corpus group floor and are flagged underpowered as well.
- guardrails on and guardrails off: the pooled tables on each arm.
- `attack_failed` counts per class and arm, and how many each rule and tier fired on.
- provenance sensitivity: the sequence tier and each of its rules at K=16, K=24, K=48, same labels, same
  rules. The other tiers are reported at K=24 only.
- set-aside sensitivity, recall only, because Phase 1 flagged these as possible inflation:
  - `seeded_group_parent_in_other_split`: seeded groups whose parent group is in dev. This is the
    check the dataset card asks for.
  - `family_member_in_other_split`: stricter, any group whose parent or sibling is in dev. This
    may leave few or no groups; a null is the answer in that case.
  - `authored_obfuscated_twin`: the authored `-OBF` traces.

## Tier comparison

Paired on the same held-out traces: content minus sequence, content minus behavior, sequence minus behavior. Reported for recall (on succeeded traces) and for FPR
(on benign traces), with the counts fired by a only, b only, both and neither.

The interval is a percentile bootstrap over variant groups, not traces, because traces within a
group are correlated and the two guardrail arms of one input share a group. Each resample draws the
groups with replacement, as many as there are, and computes the difference of pooled rates over the
traces of the drawn groups. Succeeded and benign populations are resampled separately. Resamples:
10000. Seed: 1337, the same for each comparison and each population.
Confidence: 95%.

No significance language beyond what the intervals support. An interval of exactly zero width at
zero means no discordant group, not evidence that the rates are equal in general.

## Coverage thresholds for Phase 5

A technique is covered only if at least one rule mapped to it has, on pooled held-out results:

- recall at or above **0.5**, and
- FPR at or below **0.05**,

compared with the point estimates, with counts and intervals shown beside them. These were set
before any held-out result existed and Phase 5 must use them unchanged. The recall line says a
detection that misses most of what it claims to catch is not coverage. The FPR line is the usual
tolerance for a rule meant to alert a person; on a benign population of a few dozen traces it allows
about one false positive, and the Wilson interval beside it stays wide.

## Regression and hash checks

- `results/baseline/metrics.json` is the golden file. `gauntlet validation score --check` re-scores and fails
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
