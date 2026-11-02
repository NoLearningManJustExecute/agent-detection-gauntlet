# Held-out access log

Appended by every `gauntlet` command that scores held-out data, before it reads any trace.
Integrity tooling that only parses the split is not logged; see methodology.md.
Do not edit the rows by hand. Bug records go above the table. CI's regression check logs on
its own discarded runner.

## Bug records

**1. `family_member_in_other_split` removed more than its registered wording.**

- Bug: the registration defines this set-aside as a group whose parent or sibling is in dev. The
  scorer also removed authored groups whose seeded child is in dev. Found by the pre-merge audit,
  after the first scoring run.
- Fix: scorer only, in commit `63cc20c`, with tests. No rule changed. The broader check stays as a
  separate row, `any_relative_in_other_split`, marked not registered.
- Before: 28 traces removed, 0 groups with traces left, recall null (0/0) on every tier.
- After: 19 traces removed, 4 groups with traces left, recall content 5/9, sequence 2/9, behavior
  3/9, all tiers 8/9.
- Reason for the re-run: the published row did not measure what was registered. Every other section
  of `results/baseline/metrics.json` is identical before and after, including all pooled, per-class,
  guardrail, provenance and tier-comparison numbers.

**2. `split_chunks` cut lab addresses inside their domain.**

- Bug: a 16-character fragment could end inside an address's domain, which reads as an address on
  a domain that does not exist. The leak guard blocked 6 such lines in the first
  generated input file, which was never committed, pushed or run. No trace or result existed.
- Fix: mutation tooling only, with a test. A fragment that would cut a domain ends right after the
  `@`. No rule changed. See the erratum in preregistration.md.
- Before and after: no metric existed before. The second `evasion mutate` row below is the rerun.

**3. The exporter refused text the model wrote.**

- Bug: the export's leak guard blocked two things in model output: a dash character in 3
  `llm.response` events of AC07-S24-M05, and an address the model garbled onto a made-up domain that
  is not reserved, in 6 `tool.call` and 6 `tool.result` events of AC05-S05-M06. Event counts are at
  K=24, before dedupe, guardrails off. Nothing identified anyone. Nothing had been exported or scored.
- Fix: exporter redaction only, in source lab commit `6375199355d2f9ff719befd187e55e85d22d3211`, with tests. The dash becomes a hyphen.
  The address keeps its text with `.invalid` appended, so it is still a distinct address outside the
  allowlist. No rule changed, and the runs were not repeated. Labels come from the run log, which
  is unchanged, so no verdict moved. Corpus exports already pass the same patterns, so the corpus
  is unaffected.
- Before and after: no metric existed before. The export ran once redaction was in place.

## Access log

| Time (UTC) | Commit | Command | Inputs |
|---|---|---|---|
| 2026-11-02T15:47:12Z | 39ec151f2409 | validation score | datasets/corpus/heldout/k16, datasets/corpus/heldout/k24, datasets/corpus/heldout/k48 |
| 2026-11-02T15:47:41Z | 39ec151f2409 | validation score --check | datasets/corpus/heldout/k16, datasets/corpus/heldout/k24, datasets/corpus/heldout/k48 |
| 2026-11-02T16:02:41Z | 63cc20c936a7 | validation score | datasets/corpus/heldout/k16, datasets/corpus/heldout/k24, datasets/corpus/heldout/k48 |
| 2026-11-02T16:03:07Z | 63cc20c936a7 | validation score --check | datasets/corpus/heldout/k16, datasets/corpus/heldout/k24, datasets/corpus/heldout/k48 |
| 2026-11-02T18:00:19Z | cad51af5fa53 | evasion mutate | split heldout of the corpus labels |
| 2026-11-02T18:02:26Z | cad51af5fa53 | evasion mutate | split heldout of the corpus labels |
