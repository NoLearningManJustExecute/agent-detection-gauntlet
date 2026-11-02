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

## Access log

| Time (UTC) | Commit | Command | Inputs |
|---|---|---|---|
| 2026-11-02T15:47:12Z | 39ec151f2409 | validation score | datasets/corpus/heldout/k16, datasets/corpus/heldout/k24, datasets/corpus/heldout/k48 |
| 2026-11-02T15:47:41Z | 39ec151f2409 | validation score --check | datasets/corpus/heldout/k16, datasets/corpus/heldout/k24, datasets/corpus/heldout/k48 |
| 2026-11-02T16:02:41Z | 63cc20c936a7 | validation score | datasets/corpus/heldout/k16, datasets/corpus/heldout/k24, datasets/corpus/heldout/k48 |
| 2026-11-02T16:03:07Z | 63cc20c936a7 | validation score --check | datasets/corpus/heldout/k16, datasets/corpus/heldout/k24, datasets/corpus/heldout/k48 |
