# Contributing

## Setup

```sh
python3.12 -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
git config core.hooksPath .githooks
```

The last line turns on the repository's git hooks for your clone. Run it once.

## Checks

```sh
ruff check . && ruff format --check .
mypy --strict src tests tools
pytest --cov
python tools/leak_guard.py --all
```

CI runs all of these. Every job must pass before a change is merged.

## Leak guard

`tools/leak_guard.py` blocks personal data, absolute local paths and secrets. How it works, the
history baseline and the CI layout are in [tools/LEAK_GUARD.md](tools/LEAK_GUARD.md).

- Hooks: run `git config core.hooksPath .githooks` once per clone.
- Private list: if the guard warns that no private denylist was found, point the clone at it
  once with `git config leakguard.denylist <path to the list>`.
- Before every push: `python tools/leak_guard.py --all`.
- The CI `pipeline` job also runs `--text` on every generated output.
- To remove metadata from a PNG before committing it: `python tools/leak_guard.py --strip-png FILE`.

## Paths in outputs

Every path written into reports, logs and error messages is relative to the repository root with
`/` separators. An input outside the root fails closed unless `--external-basename` is given.
See [docs/metrics.md](docs/metrics.md#paths-in-reports-and-logs).

## Commits

One branch and one pull request per phase. Commits are authored as the repository owner and end
with the trailer line used throughout the history.
