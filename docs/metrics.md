# Metrics

`gauntlet metrics` scores detections against ground-truth labels and writes one JSON report. The
code is in `src/agent_detection_gauntlet/metrics/`: `stats.py` (rates and intervals),
`compute.py` (input checks and scoring) and `report.py` (the report model). The generated JSON
Schema is `schemas/metrics-report.schema.json`.

```sh
gauntlet metrics --rules rules --traces datasets/fixtures/traces \
  --detections out/detections.jsonl --labels datasets/fixtures/labels.jsonl \
  --out out/metrics.json            # --split heldout is the default
```

## Unit of scoring

Scoring is **session-level**: the unit is one trace. A rule "detects" a trace when it produced
at least one detection record on it. The number of detections per trace does not matter.

## Outcome buckets

Each trace in the selected split goes into exactly one bucket, from its label:

| Bucket | Label |
| --- | --- |
| `benign` | `label: benign` |
| `malicious_succeeded` | `label: malicious`, `attack_succeeded: true` |
| `attack_failed` | `label: malicious`, `attack_succeeded: false` |

`attack_failed` traces are malicious runs where the attack did not achieve its goal. They are
not counted as positives or negatives. They are kept out of the confusion matrix and out of
recall, and reported separately (see [attack_failed](#attack_failed)).

## Confusion matrix

For each rule, over the traces in the selected split:

| | Detected | Not detected |
| --- | --- | --- |
| `malicious_succeeded` | TP | FN |
| `benign` | FP | TN |

The same counts are computed **per tier**. A trace counts as detected by a tier when **any rule
in that tier** detected it. Tiers are reported in the order `content`, `sequence`, `behavior`.
A tier with no rules in the rule set is omitted from the report.

## Rates

| Rate | Formula | Interval |
| --- | --- | --- |
| `precision` | TP / (TP + FP) | Wilson 95% |
| `recall` | TP / (TP + FN) | Wilson 95% |
| `f1` | 2TP / (2TP + FP + FN) | none |
| `fpr` | FP / (FP + TN) | Wilson 95% |
| `detection_rate` | TP / (TP + FN) | Wilson 95% |

`detection_rate` is **identical to recall by definition**. It is reported under its security
name because that is how detection results are usually read. `attack_failed` traces are never
counted in it, exactly as in recall.

Every rate is reported as an object:

```json
{"value": 0.5, "numerator": 1, "denominator": 2, "ci95": {"method": "wilson", "confidence": 0.95, "lower": 0.094531, "upper": 0.905469}}
```

- `numerator` and `denominator` are always present.
- When the denominator is 0, the rate is undefined: `value` is `null` and `ci95` is `null`.
  An undefined rate is never reported as 0.
- `value`, `lower` and `upper` are rounded to 6 decimal places.
- `f1` always has `ci95: null`. F1 is not a binomial proportion, so a Wilson interval does not
  apply. Its `numerator` is 2TP and its `denominator` is 2TP + FP + FN.

## Wilson score interval

For `k` successes in `n` trials with `n > 0`, `p = k / n`, and `z` the standard normal quantile
at 0.975 (`z = inverse_normal_cdf(0.975)`, about 1.959964, computed in code rather than hard-coded):

```text
center      = (p + z^2 / (2n)) / (1 + z^2 / n)
half_width  = z * sqrt( p(1 - p)/n + z^2 / (4n^2) ) / (1 + z^2 / n)
lower       = max(0, center - half_width)
upper       = min(1, center + half_width)
```

Both bounds are rounded to 6 decimal places. When `n = 0` there is no interval and `ci95` is
`null`. The Wilson interval is used because it behaves well at small `n` and at proportions near
0 or 1, where the normal approximation gives bounds outside [0, 1] or of zero width.

## attack_failed

Each rule and each tier carries:

```json
"attack_failed": {"count": 1, "detected": 1}
```

- `count`: number of `attack_failed` traces in the selected split.
- `detected`: how many of them the rule (or tier) detected.

These traces are excluded from every rate. Reporting them separately shows whether a rule fires
on attempted attacks that did not succeed, for example because a guardrail blocked the action,
without letting those traces inflate or deflate recall.

## Input cross-checks

Before anything is counted, the inputs must line up. Any mismatch stops the command with an
error; nothing is scored and no report is written.

Loading (shared with other commands):

- The rule set passes full rule validation, including tp and fp fixtures
  ([rule-format.md](rule-format.md#validator-checks)).
- Traces load under the full trace rules ([schema.md](schema.md)).
- Labels load strictly, and no trace is labeled twice.
- Every line of the detections file validates as a detection record.

Cross-checks:

1. Every supplied trace has a label, whatever its split.
2. Every label in the selected split names a trace that was supplied. Scoring a split with
   missing traces would silently shrink the denominators.
3. Rule ids in the rule set are unique.
4. Every detection names a rule in the rule set.
5. Every detection's `rule_version` equals the version of that rule in the rule set. A
   detections file from an older rule version cannot be scored against a newer rule.
6. Every detection names a trace that was supplied.
7. No rule names a heldout trace as a tp or fp fixture. Fixtures are the data a rule is written
   against, so a heldout fixture would mean tuning on the evaluation split.
8. The detections file is exactly what `scan` produces for the supplied rules and traces: the
   same records in the same order. `gauntlet metrics` re-runs the scan to check this, so a stale,
   partial, empty or edited detections file is rejected instead of turning unscanned traces into
   silent true negatives or false negatives.

## Paths in reports and logs

No report, log line or error message carries an absolute local path.

- Every input path in the report is written **relative to the repository root**, with `/`
  separators. The root is the nearest directory at or above the working directory that holds
  `.git`, or the working directory itself when there is none. `gauntlet --root DIR <command>`
  sets it explicitly.
- Because paths are relative to the root and not to the working directory, `x`, `./x`, `../x`
  from a subdirectory and the absolute form of the same file all record the same path, and a
  report is byte-identical whichever directory the command runs from.
- An input **outside the repository root fails closed**: `gauntlet metrics` stops with an error
  and writes no report. With `--external-basename`, such an input is accepted and recorded by its
  file name only, with `"external": true`. Its sha256 is still recorded. Two different external
  inputs of the same role and file name are rejected, since the report could not tell them apart.
- Output files (`--out`) may be written anywhere. Their paths are not recorded in reports.
- Log lines and error messages show paths inside the root the same way, and paths outside it as
  `<outside repo>/<file name>`.
- The report model itself rejects any input path that is absolute, uses `\`, starts with a
  drive letter, or contains an empty, `.` or `..` segment.

Labels in the other split that name traces not supplied are allowed and ignored. Detections on
supplied traces outside the selected split are allowed and do not count.

## Report fields

The report is one JSON object:

| Field | Contents |
| --- | --- |
| `schema_version` | `"0.3"` (`"0.1"` and `"0.2"` are still read) |
| `split` | The split scored: `heldout` or `dev`. |
| `provenance.package_version` | Version of the installed package. |
| `provenance.git_commit` | Commit of the git checkout the package runs from, or `null`. |
| `provenance.git_dirty` | `true` if tracked files in that checkout have uncommitted changes, `false` if not, `null` if unknown. Untracked files are ignored. |
| `inputs` | One entry per input file: `role` (`rule`, `trace`, `detections`, `labels`), `path` relative to the repository root (or the file name only when `external`), `external` (`true` only for an input outside the root accepted with `--external-basename`), and the `sha256` of the file bytes. Sorted by role, then path. |
| `rules` | Each rule scored: `id`, `version`, `tier`, sorted by id. |
| `population` | Traces in the selected split: `traces`, `benign`, `malicious_succeeded`, `attack_failed`. |
| `per_rule` | Per rule, sorted by id: `rule_id`, `rule_version`, `tier`, `confusion` (`tp`, `fp`, `tn`, `fn`), `attack_failed` (`count`, `detected`), `rates` (`precision`, `recall`, `f1`, `fpr`, `detection_rate`). |
| `per_tier` | Per tier with at least one rule: `tier`, `rule_ids` (sorted), `confusion`, `attack_failed`, `rates`. |

`git_commit` and `git_dirty` come from running `git rev-parse HEAD` and
`git status --porcelain --untracked-files=no` in the directory of the installed package. With an
editable install from a clone, that is the repository itself. Outside a git checkout, or when
git is not available, both are `null`.

## Reproducibility

The report contains **no timestamps** and no other run-specific values. It is written as JSON
with sorted keys, two-space indentation, a trailing newline and LF line endings. Running the
same command again, with the same input files, the same input bytes and the same checkout state,
gives a byte-identical file, from the repository root or from any subdirectory. No report field
depends on the working directory. The only fields that can change between two runs on the same
inputs are `provenance.git_commit` and `provenance.git_dirty`, when the checkout itself changes. Each input's sha256 lets a reader confirm which exact files a
report was computed from.

## Default split

`--split` defaults to `heldout`. Published metrics come only from the held-out split, which is
frozen before rules are written and is not used while writing them (see
[methodology.md](methodology.md)). Making `heldout` the default means the command that produces
publishable numbers is the one you get without extra flags. Scoring the development split
requires asking for it with `--split dev`, and the chosen split is recorded in the report.

## Example output

Running the command above on the synthetic fixtures scores six held-out traces (three benign,
two `malicious_succeeded`, one `attack_failed`). Those numbers, including the rate object shown
earlier, are a pipeline check on synthetic data. They are not a finding about any detection
technique.
