# Held-out access log

Appended by every `gauntlet` command that reads held-out data, before it reads any trace.
Do not edit the rows by hand. CI's regression check logs on its own discarded runner.

| Time (UTC) | Commit | Command | Inputs |
|---|---|---|---|
| 2026-11-02T15:47:12Z | 39ec151f2409 | validation score | datasets/corpus/heldout/k16, datasets/corpus/heldout/k24, datasets/corpus/heldout/k48 |
| 2026-11-02T15:47:41Z | 39ec151f2409 | validation score --check | datasets/corpus/heldout/k16, datasets/corpus/heldout/k24, datasets/corpus/heldout/k48 |
