# Threat model

This is the threat model for agent-detection-gauntlet itself, not for the agent it studies. The agent's
threat model is in the source lab,
[agent-risk-framework](https://github.com/NoLearningManJustExecute/agent-risk-framework/blob/main/docs/threat_model.md).

The repository is a local research tool with no service, no users' data and no credentials to steal. What
it has to protect is whether its published numbers can be believed, and whether the owner stays
unidentified. Most of what follows is about those two things. GitHub settings below are as of 2026-11-03.

## Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Published results: `results/`, generated reports, `docs/findings.md` | They are the point of the project. A wrong number misleads anyone who reads it. |
| A2 | Frozen inputs: rules and their registered hashes, the split manifest, held-out and evasion traces | Results mean something only if these did not move after results existed. |
| A3 | Separation of the held-out split from rule writing | Without it, a held-out score is a dev score with a different name. |
| A4 | The owner's identity | A public push cannot be taken back. |
| A5 | The repository and CI: `main`, the workflows, the `LEAK_DENYLIST` secret | They enforce A1 to A4. |
| A6 | The machine running the tool | The tool reads and writes local files and uses its CPU. |

There are no real people's data here. Traces come from a sandboxed agent against synthetic fixtures, on
reserved domains ([dataset.md](dataset.md)).

## Trust boundaries

| ID | Boundary | How it is crossed |
|---|---|---|
| B1 | Source lab to this repository | Traces are exported from agent-risk-framework and committed. They are taken as recorded. Nothing authenticates them. |
| B2 | Files to the parsers and engine | Rules, traces, labels and detections are read from disk and parsed strictly. They are treated as trusted local input ([SECURITY.md](https://github.com/NoLearningManJustExecute/agent-detection-gauntlet/blob/main/SECURITY.md)). |
| B3 | Dev split to held-out split | A command-line firewall and an access log. It is a discipline aid, not an access control. |
| B4 | Detections to labels | The engine never reads labels. Only the metrics stage joins them ([methodology.md](methodology.md)). |
| B5 | A change to CI | Pull request code runs in CI. Within `ci.yml`, only the `leak-guard` job can hold the private list, and it runs no code from the change. Three other workflows also hold it (C10, R8). |
| B6 | Local machine to GitHub | Git hooks and the leak guard, then the same guard in CI. |
| B7 | Package registries and Action publishers to CI | Hash-pinned lockfile and SHA-pinned Actions. |
| B8 | This repository to its readers | Generated reports, the dashboard, and rule exports. Nothing here controls what a reader does next. |

## Attack surface

- **`gauntlet` inputs:** YAML rules, JSONL traces, labels and detections, and every `--out` path.
- **`GAUNTLET_SCORING_HELDOUT`:** the environment variable that declares a held-out read. Anyone can set it.
- **Regular expressions in rules:** compiled and run with Python's `re`, with no timeout.
- **`git` subprocesses:** `firewall.py` and `metrics/compute.py` run `git` with fixed arguments to record the
  commit. Nothing else is executed, and trace content is only matched, never run.
- **GitHub:** pull request code, pull request text and comments (`pr-text.yml` reads them), and the
  workflow files, which are read from the change itself.
- **Dependencies:** every package in `requirements-lock.txt`, the build backend, and the pinned Actions.
- **GitHub Pages:** static pages. `dashboard.html` has no scripts. `index.html` has inline scripts and loads
  fonts from Google Fonts, so a visitor's browser contacts that one third party.
- **Exports:** generated Sigma, KQL, SPL and ES|QL files, built in CI and never committed.

## Threat actors

| ID | Actor | Goal | Realistic? |
|---|---|---|---|
| T1 | The author, me | Make a result look better, on purpose or by drift | Yes. This is the main threat to A1 to A3, which is why most controls aim here. |
| T2 | An attacker who reads the public rules | Write attacks that evade them | Yes. The rules and the mutation code are public on purpose. |
| T3 | An outside contributor | Land a bad change, or get at the CI secret through a pull request or comment | Possible. The repository is public. |
| T4 | Someone trying to identify the owner | Find or confirm a personal identifier | Possible. |
| T5 | A supplier of a rule or trace file | Hang a scan, or pass off false traces | Only if someone loads files from a stranger, which [SECURITY.md](https://github.com/NoLearningManJustExecute/agent-detection-gauntlet/blob/main/SECURITY.md) says not to do. |
| T6 | A compromised package or Action | Run code in CI or on a contributor's machine | Possible, as with any project with dependencies. |
| T7 | A reader who trusts too much | Deploy an export, or quote a number without its limits | Likely. Not malicious, and the harm is the same. |

## Abuse cases

| ID | Actor | Abuse | What stops or limits it | What is left |
|---|---|---|---|---|
| AC-1 | T1 | Tune a rule after seeing held-out results | C1, C2 | Rules were written by the person who wrote the attacks. Hashes prove rules did not change after registration, not what the author knew before it. |
| AC-2 | T1 | Read the held-out split without it showing | C3 | The firewall sees only `gauntlet` commands. Opening a file directly leaves no record. |
| AC-3 | T1, T3 | Change a golden number or a figure in a document | C4, C5 | Both run in CI and report after the fact. Nothing requires them to pass before `main` moves (R1). |
| AC-4 | T1, T5 | Edit or swap traces | C2, C6 | A trace that was false when recorded passes every check (R3). |
| AC-5 | T2 | Evade the published rules | None. Measuring this is the project. | Adaptive attackers are not measured ([limitations.md](limitations.md)). |
| AC-6 | T5 | A rule regex that backtracks forever | Nothing limits this. C7 stops unsafe YAML and bad structure, and regexes have no timeout. | Accepted (X1). |
| AC-7 | T5 | A trace that is huge or built to slow a regex | Nothing limits this. C8 rejects malformed input, and sets no size or time limit. | Accepted (X1). |
| AC-8 | T5, T7 | Attack text in a trace reaches a model or a person who acts on it | Traces are data to the engine and are never executed. [SECURITY.md](https://github.com/NoLearningManJustExecute/agent-detection-gauntlet/blob/main/SECURITY.md) warns about them. | A person or an AI assistant reading `datasets/` is exposed to working prompt injection text. Accepted (X2). |
| AC-9 | T3 | Read `LEAK_DENYLIST` from a pull request | C9, C10 | Workflow files are read from the change, so someone with write access could alter the gate. Only the owner has it. |
| AC-10 | T3 | Post a comment that makes the guard misbehave | C10 | Scanning stays on generic rules for non-owners and prints no fragment of a match. See X3 for the owner's own runs. |
| AC-11 | T4 | Find an identifier in a commit, report or path | C11, C12, C13 | The guard scans metadata and readable text in images and PDFs, not pixels, and lists them for manual review (R4). Hooks can be skipped locally, CI reports after a push, and a non-owner pull request meets the private list only at merge (R9). |
| AC-12 | T4 | Confirm a guessed identifier from a failed run | C10 | Accepted (X3). |
| AC-13 | T6 | Ship a malicious update of a dependency or Action | C14, C15 | A lockfile trusts what it saw when it was written (R5). |
| AC-14 | T7 | Load an export into a SIEM and trust it | Exports are labeled "converted, not live SIEM validated", and unconverted rules are listed with reasons ([export.md](export.md)). | No backend has run them. A reader can ignore a label (X4). |
| AC-15 | T7 | Quote a rate without its limits | Every rate has its numerator and denominator, C5, [limitations.md](limitations.md). | Nothing stops a quote out of context (X4). |
| AC-16 | T3, T5 | Inject markup into the dashboard through rule or catalog text | The dashboard and diagram generators escape text, and the dashboard has no scripts. | None known. |

## Security controls that exist

Each one is in the repository today, or is a GitHub setting where noted.

| ID | Control | Where | Abuse cases |
|---|---|---|---|
| C1 | Rule hashes are registered before scoring. `gauntlet validation verify` ties committed results to the frozen registration, and `validation score` refuses rules that differ. `scan`, `metrics` and `validation score --prereg` do not ask for that registration, and CI's verify step is what catches their use in committed results | `docs/preregistration.json`, `docs/preregistration-evasion.json`, `src/agent_detection_gauntlet/validation/prereg.py`, [methodology.md](methodology.md) | AC-1 |
| C2 | Registrations and the split manifest must equal their first committed copy, and results may not be deleted | `regression` and `corpus` jobs in `.github/workflows/ci.yml` | AC-1, AC-4 |
| C3 | Scoring commands refuse held-out input unless the read is declared, and log it first. Integrity tooling (`validate-traces`, `corpus verify`, `corpus card`) reads the split unlogged, by design. Log rows on the base must stay, in order | `src/agent_detection_gauntlet/firewall.py`, `docs/heldout-log.md`, `regression` job | AC-2 |
| C4 | A fresh score must match the golden files byte for byte. If the rule files no longer match those the baseline golden file records, `validation score --check` prints `skipped` and exits 0, and `validation verify` then fails if that golden file changed | `gauntlet validation score --check`, `gauntlet evasion score --check` | AC-3 |
| C5 | Every fraction and three-decimal rate in the six published files must exist somewhere in a results JSON, and a doc that names a technique near the word "covered" must match the JSON. This catches invented numbers, not a real number attached to the wrong claim | `gauntlet publish numbers`, `gauntlet coverage claims` | AC-3, AC-15 |
| C6 | Results record the hashes of the inputs they were scored from | `results/baseline/metrics.json`, `results/evasion/evasion.json` | AC-4 |
| C7 | Rule YAML uses a safe loader that rejects duplicate keys, then strict validation | `src/agent_detection_gauntlet/rules/loader.py` | AC-6 (structure only) |
| C8 | Trace, label and detection readers fail closed on malformed input and unknown `adg.*` attributes | `src/agent_detection_gauntlet/io/jsonl.py`, `src/agent_detection_gauntlet/schema/` | AC-4, AC-7 (structure only) |
| C9 | Within `ci.yml`, only the `leak-guard` job holds the private list, and a test enforces it. It installs nothing and runs the base branch's guard | `.github/workflows/ci.yml`, `tests/test_publish.py` | AC-9 |
| C10 | In pull request and comment scans, the private list runs only when the owner triggered the event. Everyone else gets a placeholder list and generic rules. The scheduled full scan and the release workflow, which run from a branch rather than for a pull request, also use the list | `.github/workflows/ci.yml`, `.github/workflows/pr-text.yml`, `leak-guard-full.yml`, `release.yml` | AC-9, AC-10, AC-12 |
| C11 | The leak guard blocks personal data, local paths, non-allowlisted emails and secret shapes in the tree, history and pull request text. The private list is salted hashes, kept out of the repository | `tools/leak_guard.py`, `tools/LEAK_GUARD.md`, `.githooks/`, `leak-guard-full.yml` | AC-11 |
| C12 | Paths in outputs are repository-relative, and a path outside the repository fails closed | `src/agent_detection_gauntlet/paths.py`, [metrics.md](metrics.md#paths-in-reports-and-logs) | AC-11 |
| C13 | Generated outputs are scanned with generic rules in the jobs that produce them | `pipeline`, `regression`, `coverage`, `dashboard-drift`, `engineering` jobs | AC-11 |
| C14 | Every package is locked with hashes, direct pins are exact, and Actions are pinned to commit SHAs | `requirements-lock.txt`, `pyproject.toml`, `tests/test_lockfile.py`, workflow files | AC-13 |
| C15 | `pip-audit` runs on the installed set, and Dependabot watches pip and Actions. GitHub secret scanning and push protection are on (setting) | `audit` job, `.github/dependabot.yml` | AC-13 |
| C16 | CI has read-only permissions by default and checks out with `persist-credentials: false`. The release workflow runs by hand, publishes nothing and keeps its bundle as an artifact | `.github/workflows/` | AC-9, AC-13 |
| C17 | Private vulnerability reporting is on (setting) | [SECURITY.md](https://github.com/NoLearningManJustExecute/agent-detection-gauntlet/blob/main/SECURITY.md) | All |

## Assumptions

- One owner holds write access, and that account and machine are not compromised.
- The tool runs locally, on files its operator chose, and is not exposed to a network.
- GitHub Actions, GitHub's secret handling and PyPI's hosting behave as documented.
- Traces reflect what the instrumented agent did. An agent or tool that lies to its telemetry is out of scope.
- `llama3.1:8b` at the recorded digest stands in for one model and nothing more.

## Residual risk

These are real and not closed. They are not accepted as fine, only stated.

- **R1. `main` has no branch protection or ruleset, and no check is required.** CI reports after a push rather
  than blocking it. "Never force push" and "merge only green" are my process, not something GitHub enforces.
  Commits are not signed.
- **R2. The firewall is self-policed.** It catches accidents and leaves a trail for honest use. It cannot stop or
  detect an author who reads a held-out file directly. CI cannot see a log row lost before it was committed, and that
  has happened: record 4 in [heldout-log.md](heldout-log.md) is three rows lost to a mistake.
- **R3. Trace provenance is trust on first sight.** Hashes prove traces did not change after they were pinned. They
  say nothing about whether a run happened as recorded.
- **R4. Text scanning cannot see pixels.** The guard reads image metadata and readable text, but a username drawn in a
  screenshot or a recording passes it. Images and PDFs need a person to look at them, every time.
- **R5. Supply chain.** The lockfile pins what existed when it was written. A package that was already malicious then
  stays pinned. `pip-audit` knows only reported issues. `setuptools` is an exact pin but is not hash-checked,
  and `ubuntu-latest` still floats.
- **R6. Salted hashes are guessable.** Anyone holding the private list and a candidate word could test it. The list
  stays out of the repository and in a CI secret for that reason.
- **R7. Single author.** One person wrote attacks, rules and scoring. Audits by separate sessions help, and they are not
  independent replication.
- **R8. `release.yml` holds the private list after running the dispatched ref's code.** It installs the package and runs
  tests before its guard steps. Only someone with write access can dispatch it, so dispatch it only from a trusted ref.
- **R9. The leak guard is not a pre-push wall.** Hooks can be skipped, and only a local setup runs them. CI sees a commit
  once it is on GitHub. A Dependabot or fork pull request is checked against the private list only on the push when it
  merges, by which point a hit is already public.

## Accepted risk

I have decided not to fix these. Each has its reason.

- **X1. Slow regexes and large files.** Rules have no regex timeout and readers have no size limit. Rules and traces are
  trusted local input, and a hung local scan harms nobody else. Do not load files from strangers.
- **X2. Working attack text in the corpus.** It is the data under study. Removing it removes the study.
- **X3. A guess on a pull request can show as a failed run.** A run the owner triggers scans the whole pull request,
  including others' comments, so a planted guess could fail when the owner next pushes or comments. The run prints
  a rule and location, never a value. Closing it needs a per-author filter in the guard, and the guard stays
  byte-identical across three repositories ([LEAK_GUARD.md](https://github.com/NoLearningManJustExecute/agent-detection-gauntlet/blob/main/tools/LEAK_GUARD.md)).
- **X4. Readers can misuse this.** I label exports and limits. I cannot police what happens after that. This is a
  research tool, not a product, and it has no live monitoring.
- **X5. The rules are public, so attackers can read them.** Publishing them is how the result can be checked.

## Out of scope

The agent's own security and its guardrails (the source lab), Ollama and the model, the host operating system,
GitHub's internals, and any SIEM an export might be loaded into.
