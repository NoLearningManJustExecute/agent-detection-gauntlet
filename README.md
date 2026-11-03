![agent-detection-gauntlet: under homoglyph mutation, content rules fall to 0/21 while behavior rules still catch 9/21](docs/assets/demo-banner.svg)

# agent-detection-gauntlet

Measures which AI-agent detection techniques stay effective when attackers deliberately evade them.

Live demo: https://NoLearningManJustExecute.github.io/agent-detection-gauntlet/

Third of a trilogy: [rag-attack-lab](https://github.com/NoLearningManJustExecute/rag-attack-lab)
attacks, [agent-risk-framework](https://github.com/NoLearningManJustExecute/agent-risk-framework)
defends, and this one detects.

> Which AI-agent detection techniques remain effective when attackers intentionally evade them?

**Homoglyph and zero-width characters blind keyword detection, while sequence and behavior detection
hold.**

Pooled over payload mutations, guardrails off. Recall is over attacks that still succeeded, which was
138/396 runs, or 57 distinct succeeded traces in 17 groups:

| Tier | Recall under payload mutation | Same attacks, unmutated | Change [95% interval] |
|---|---|---|---|
| content | 7/57 = 0.123 | 25/48 = 0.521 | -0.398 [-0.604, -0.170] |
| sequence | 8/57 = 0.140 | 7/48 = 0.146 | -0.005 [-0.060, +0.047] |
| behavior | 21/57 = 0.368 | 20/48 = 0.417 | -0.048 [-0.092, +0.012] |
| all tiers | 28/57 = 0.491 | 39/48 = 0.812 | -0.321 [-0.531, -0.065] |

- **Homoglyphs and zero-width characters** take content recall to 0/21 and 1/23. Fullwidth characters
  did not move it, because the rules normalize them away.
- **"Hold" means no measurable drop,** not good recall: both pooled intervals include zero, and behavior
  and sequence still miss most of these attacks.
- **Base64 is not an evasion here.** It broke the attack: 0/66 runs succeeded in each encoding, because
  the model could not act on it. A model that can decode could change that.
- **Together, on clean held-out attacks,** all tiers catch 20/28 = 0.714 [0.529, 0.847] of successful
  attacks, with a false positive rate of 1/38 = 0.026 [0.005, 0.135] over both guardrail arms. That is a
  different population from the 39/48 above, whose attacks were chosen because they succeeded.
- **Individual rules are weak.** Pooled over clean or mutated attacks, no single rule clears the
  registered bar of 0.5 recall at 0.05 FPR; the best is 7/28 = 0.250. The strength is in the combination, and the combination still
  drops under mutation.

14 rules, 887 scored live evasion runs, one local model. Read the [findings](docs/findings.md) and the
[limitations](docs/limitations.md), or browse the [dashboard](https://NoLearningManJustExecute.github.io/agent-detection-gauntlet/dashboard.html).

![Pipeline: lab, telemetry, detection, evaluation](docs/assets/architecture.svg)

## Why it matters

A detection's score on clean attacks says nothing about what it is worth once an attacker changes a few
characters. Here the attack keeps working and the alert goes away: under homoglyphs the attack still succeeded in 54/66 runs,
and the content tier caught 0/21 of them.

The same measurement says where to spend effort. Behavior and sequence rules did not measurably drop,
though they miss most attacks either way. Keyword rules are worth keeping for what they catch on clean
attacks, not as a primary control. Rules were frozen before scoring and CI re-scores the results byte for
byte, so you can check these numbers rather than trust me.

## Demo

No recording is published yet. The script is in [docs/demo.md](docs/demo.md).

<!-- GIF goes here. Owner: record with a generic shell prompt, no paths, no email in git config on screen, and scrub frames before posting. -->

## How it works

1. **Attack.** Known attack classes run against an instrumented agent, alongside benign work,
   including hard negatives such as legitimate sessions that read secrets and send messages.
2. **Telemetry.** Every run becomes a trace of schema-checked JSONL events, aligned with the
   OpenTelemetry GenAI conventions. Ground truth lives in a separate labels file.
3. **Detection.** A deterministic engine runs content, sequence and behavior rules over the traces. It
   never reads labels.
4. **Baseline.** Rules are hashed and pre-registered, then scored on a frozen held-out split.
5. **Evasion.** Payloads are mutated by fixed code and re-executed live, so the traces are what the
   agent really did. Attack variants run alongside and are kept separate.
6. **Coverage.** Per-technique results are computed from the scores, never declared.

Rules were never tuned after held-out results were seen. Every rate ships with its numerator and
denominator, undefined rates are null, and CI re-scores the golden results and fails on any difference.

## Scope and limits

- **One model, one author.** `llama3.1:8b` at temperature 0, with attacks and rules by one author.
  Results may not transfer.
- **Relatives across the split.** All 20 succeeded held-out groups have a relative in the dev split, so
  clean recall may be inflated, and no held-out group is free of this to test on.
- **Not measured.** Paraphrase and translation evasion, adaptive attackers, false positives under
  mutation, and real alert volume.
- **Exports are not live validated.** Sigma, KQL, SPL and ES|QL files are labeled "converted, not live
  SIEM validated". No SIEM or Sigma backend has run them, and most rules do not convert
  ([export.md](docs/export.md)).
- **Mappings.** Rules map to MITRE ATLAS, OWASP LLM, OWASP Agentic and, for host actions, MITRE ATT&CK.
  The IDs rules use were checked against primary sources; one is unverified, and OWASP LLM uses the
  2025 numbers ([mappings.md](docs/mappings.md)).
- **Not a product.** This is a local research tool with no live monitoring.

The full list is in [docs/limitations.md](docs/limitations.md).

## Reproducibility

The thesis is byte-exact re-scoring, so the toolchain is pinned, not ranged:

- **Python:** 3.12.15 in the CI jobs that install packages, on `ubuntu-latest`. The checks below also pass on 3.12.10 on Windows, except
  the two held-out re-scores, which I only run in CI.
- **Packages:** `requirements-lock.txt` holds every package, direct and transitive, at one exact version
  with sha256 hashes. `pyproject.toml` pins the direct ones to the same versions and the build backend to
  `setuptools==84.2.1` (exact version, not hash-checked). A test fails if the two disagree.
- **Model:** `llama3.1:8b`, digest
  `46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e`, at temperature 0. Only producing new
  traces needs it. Traces are committed, so scoring needs no model.

```sh
python3.12 -m venv .venv
# Windows: .venv\Scripts\activate
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-lock.txt
python -m pip install --no-deps -e .
```

Check the rules, the registrations and every generated document against what is committed. None of this
reads a held-out trace or changes a file. Each command exits 0 and ends with a line starting `ok:`;
`validate-rules` reports `ok: 14 rule(s), 5 warning(s)`, where the warnings are the one unverified ATLAS
ID ([mappings.md](docs/mappings.md)):

```sh
gauntlet validate-rules rules
gauntlet validation verify
gauntlet coverage build --check
gauntlet publish build --check
gauntlet publish numbers
```

Re-score the held-out traces and compare with the golden files, byte for byte. This is the only step that
reads them. Each run appends a row to `docs/heldout-log.md`, as every held-out read does. In PowerShell,
set `$env:GAUNTLET_SCORING_HELDOUT = "1"` first:

```sh
GAUNTLET_SCORING_HELDOUT=1 gauntlet validation score --check
GAUNTLET_SCORING_HELDOUT=1 gauntlet evasion score --check
```

A difference in either file exits non-zero. The CI `regression` job runs both on every push and pull
request, on a clean checkout installed from the lockfile. The golden files should hash to:

| File | sha256 |
|---|---|
| `results/baseline/metrics.json` | `50cc3ef8a9b87f13e09f2c64cd52b7825e3b642ac0db8987d6e374d76dfaa3f4` |
| `results/evasion/evasion.json` | `b7219ce8e0433477d23a4fac3c4e74129ed814ab71568dd18f74ed37f263f8b7` |

Producing new traces needs the source lab,
[agent-risk-framework](https://github.com/NoLearningManJustExecute/agent-risk-framework), and a local
Ollama, which this repository does not include.

To change a pin, edit `pyproject.toml` and re-run the command in the lockfile's header with `uv` installed.
A pin that moves a golden file fails `regression`.

## Lessons learned

- **Check the attack survived before calling it an evasion.** In an offline check, bare base64 took content
  rules from 12/23 to 2/23, which looks like a strong evasion. Run live, it succeeded in 0/66 runs, which I
  read as this model not acting on the encoded text. Scoring mutated text without re-running the attack would have reported
  the wrong finding.
- **Re-run the mutation. Do not edit the trace.** Editing captured text leaves the tool sequence as it was, so
  behavior rules would hold by construction. Re-running is slower, and it is why that result means anything.
- **One normalization step looks like the explanation for a whole result.** NFKC folds fullwidth characters and does
  not fold lookalikes or remove zero-width marks, and only fullwidth left content recall unchanged. Nothing toggled
  NFKC, so that is a reading, not a measurement, and the frozen rules mean the likely fix for zero-width stays untested.
- **Pre-registration costs you the comfortable answer.** Pooled over clean or mutated attacks, no single rule cleared
  the bar I set, and the best was 7/28. I kept the bar. The combined figures describe the system better, but they sit next to that result, not
  in place of it.
- **A group split is not independence.** I split whole variant groups, and flagged before scoring that relatives
  crossed the split. I still underestimated it: 20 of 20 succeeded held-out groups have a relative in dev, so no clean
  subset is left to test on. Next time I would split by mechanism and write held-out attacks separately.
- **Combining beat any one rule.** Content and behavior tied at 12/28 and caught mostly different attacks, which is
  how all tiers reached 20/28. Removing a cheap tier takes real weight with it, which is the evasion result.
- **Audit the scorer as hard as the rules.** A pre-merge audit found the scorer removing more than one registered
  set-aside said it would, after the first scoring run. The fix and the before and after numbers are a public
  record in [docs/heldout-log.md](docs/heldout-log.md).
- **Pin from the first day.** For most of this project, the byte-exact check ran against dependency ranges that
  resolved fresh on every run. It held, but nothing guaranteed that. The lockfile came last, and it should have
  come first.

## Repository layout

| Path | Contents |
| --- | --- |
| `rules/` | The 14 detection rules, one YAML file each |
| `datasets/` | Frozen corpus, evasion inputs and traces, and synthetic test fixtures |
| `results/` | Golden JSON for the baseline, evasion and per-technique results |
| `docs/` | Findings, limitations, generated reports, dashboard, method and formats |
| `src/agent_detection_gauntlet/` | Schema, engine, rules, metrics, validation, evasion, coverage, export, publish |
| `tools/leak_guard.py` | Standalone guard against personal data, local paths and secrets |
| `tests/` | Test suite |

## Documentation

- [docs/findings.md](docs/findings.md): the write-up
- [docs/limitations.md](docs/limitations.md): what the numbers cannot tell you
- [docs/threat-model.md](docs/threat-model.md): assets, abuse cases, the controls that exist, and the risk left
- [docs/results-baseline.md](docs/results-baseline.md), [docs/results-evasion.md](docs/results-evasion.md),
  [docs/coverage.md](docs/coverage.md): full generated tables
- [docs/detections.md](docs/detections.md): the rule catalog
- [docs/mappings.md](docs/mappings.md): framework IDs and how they were checked
- [docs/preregistration.md](docs/preregistration.md), [docs/heldout-log.md](docs/heldout-log.md): the
  registrations and every held-out read
- [docs/methodology.md](docs/methodology.md), [docs/metrics.md](docs/metrics.md),
  [docs/engine.md](docs/engine.md), [docs/schema.md](docs/schema.md),
  [docs/rule-format.md](docs/rule-format.md), [docs/dataset.md](docs/dataset.md),
  [docs/export.md](docs/export.md): method and formats
- [docs/demo.md](docs/demo.md): demo script and recording guide
- [ROADMAP.md](ROADMAP.md), [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md)

## License

MIT. See [LICENSE](LICENSE).
