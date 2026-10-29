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

`tools/leak_guard.py` keeps personal data, absolute local paths and secrets out of the
repository, its history, pull request text and generated outputs. It uses the Python standard
library only.

### Scopes

| Flag | Scans |
| --- | --- |
| `--tree` | Every tracked file and every untracked file that is not ignored, including file names. |
| `--history` | Every commit reachable from any ref: author and committer names and emails, the full message and every added line. Every annotated tag: name, tagger and message. Every reachable blob the text diff does not show (binary, UTF-16, or hidden by a diff attribute), and every image blob. |
| `--text FILE` | One file. Use it for a pull request body before posting it, and for generated outputs. |
| `--pr` | In CI: the current pull request's title, body, reviews, review comments and comments, read with the GitHub REST API. |
| `--all` | `--tree` and `--history`. |

Exit codes: `0` clean, `1` at least one hit, `2` a setup or usage problem.

### Generic rules

These patterns contain nothing personal and live in the guard itself:

- Absolute paths: Windows drive paths (a drive letter, a colon, then a slash or backslash, not
  preceded by a letter, so web addresses do not match), UNC paths, macOS and Linux home
  directories (the CI runner's home directory is accepted only inside `.github/`), the Windows
  user profile variable, and a tilde followed by a folder.
- Email addresses, except the GitHub noreply domains, `noreply` and `support` at github.com,
  example.com, example.net, example.org, and domains ending in `.example`, `.test` or `.invalid`.
- Forbidden strings: assistant vendor domains, generated-by footers, session identifiers, and
  em and en dash characters.
- Secrets: private key headers and common token prefixes (GitHub, API keys, Slack, AWS access
  key ids).

A generic hit prints the file, line, rule name and the match with its middle masked. A file
whose own name holds a match or a private identifier is shown as `<path withheld ...>` with a
short digest instead of its name. Text files with a UTF-16 or UTF-32 byte order mark are decoded;
other binary files are listed as not scanned.

### Private denylist

Private identifiers are stored only as salted SHA-256 hashes, so no personal text sits in any
file. The guard lowercases the scanned text, hashes every window of 1 up to `maxwords` whole
words with the salt, and blocks on any listed hash. It never prints the matching text, only
`private identifier (hash #N)`.

Hash file format:

```text
salt <hex>
maxwords <n>
hash <sha256 hex>
```

The hash of an identifier is the SHA-256 of the salt, a newline, and the identifier trimmed and
lowercased. Lines starting with `#` are comments. Personal email addresses are never stored,
even as hashes: the generic email rule blocks every address outside the allowlisted domains.

The guard loads the list from, in order: the file named by `LEAK_DENYLIST_FILE`, the text of
`LEAK_DENYLIST`, or a private file kept outside the repository next to it. In CI the list comes
from the `LEAK_DENYLIST` repository secret. With no list, the guard prints a warning and exits
`2` when `CI=true`, or continues with generic rules only when run locally.

### Allowlist

`.leakguard-allow` lists exact strings that are known to be safe for generic rules, one per line
as `<exact string> # <reason>`. An entry accepts a generic match when it equals the match or the
whole trimmed line holding it. The reason is required. The allowlist can never hold a private
identifier (the guard refuses to start if it does) and never affects denylist hits.

### Hooks and CI

`.githooks/pre-commit` runs `--tree` and `.githooks/pre-push` runs `--all`. Hooks are a local
safety net and can be skipped. CI is the enforcement: the `leak-guard` job runs `--all` on the
full history and `--pr` on pull requests, and the `pipeline` job runs `--text` on every
generated output. The `PR text guard` workflow runs `--pr` again whenever a comment or review is
posted or edited.

## Paths in outputs

Every path written into reports, logs and error messages is relative to the repository root with
`/` separators. An input outside the root fails closed unless `--external-basename` is given.
See [docs/metrics.md](docs/metrics.md#paths-in-reports-and-logs).

## Commits

One branch and one pull request per phase. Commits are authored as the repository owner and end
with the trailer line used throughout the history.
