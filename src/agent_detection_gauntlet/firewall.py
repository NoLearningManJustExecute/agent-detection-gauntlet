"""The held-out firewall: commands refuse held-out inputs unless scoring is declared.

Rules are written and baselines fitted without access to the held-out split. `scan` and
`metrics` read it only when GAUNTLET_SCORING_HELDOUT=1 is set, and every such run is appended to
docs/heldout-log.md before any trace is read. Rule fixtures and baseline fits never read it.

An input is checked by what it would actually read: a directory is expanded the way the trace
loader expands it, so the answer does not depend on the working directory or on --root.

What the firewall protects is held-out attack content reaching detection work: rule authoring,
human review, and scoring before rules are frozen and pre-registered. Opaque byte-level access by
privacy and integrity tooling is allowed and is not a breach. The leak guard, schema validation,
manifest and label parsing, and lint may read held-out bytes, because they pattern-match or parse
without surfacing attack content to whoever writes the rules. Privacy scanning is mandatory and
covers every file. Folder names alone carry no attack content.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from agent_detection_gauntlet.errors import GauntletError, InputError
from agent_detection_gauntlet.io.jsonl import expand_paths, write_text
from agent_detection_gauntlet.paths import find_repo_root, repo_relative, repo_root, shown_path

HELDOUT_ENV = "GAUNTLET_SCORING_HELDOUT"
CORPUS_DIR = Path("datasets/corpus")
HELDOUT_PREFIX = "heldout/"
MANIFEST_NAME = "SPLIT_MANIFEST.json"
LOG_PATH = Path("docs/heldout-log.md")
LOG_HEADER = (
    "# Held-out access log\n\n"
    "Appended by every `gauntlet` command that scores held-out data, before it reads any trace.\n"
    "Integrity tooling that only parses the split is not logged; see methodology.md.\n"
    "Do not edit the rows by hand. Bug records go above the table. CI's regression check logs on\n"
    "its own discarded runner.\n\n"
    "| Time (UTC) | Commit | Command | Inputs |\n"
    "|---|---|---|---|\n"
)


def _package_checkout() -> Path:
    return find_repo_root(Path(__file__).resolve().parent)


def _pinned_heldout_hashes(paths: Iterable[Path]) -> frozenset[str]:
    """Hashes of the held-out files, so a copy elsewhere is still recognized.

    The manifest is looked for at the repository root, at the checkout this package runs from,
    and above each input, so the answer does not depend on where the command was started.
    """
    roots = [repo_root(), _package_checkout()]
    for path in paths:
        resolved = path.resolve()
        roots += [resolved, *resolved.parents]
    pinned: set[str] = set()
    for manifest in dict.fromkeys(root / CORPUS_DIR / MANIFEST_NAME for root in roots):
        if not manifest.is_file():
            continue
        try:
            files = json.loads(manifest.read_bytes()).get("files", {})
            pinned.update(
                str(digest) for name, digest in files.items() if name.startswith(HELDOUT_PREFIX)
            )
        except (ValueError, AttributeError, TypeError) as exc:
            raise InputError(manifest, "split manifest is not valid; refusing to continue") from exc
    return frozenset(pinned)


def _in_heldout(resolved: Path) -> bool:
    parts = [part.casefold() for part in resolved.parts]
    return any(parts[i : i + 2] == ["corpus", "heldout"] for i in range(len(parts) - 1))


def _is_heldout_path(path: Path, pinned: frozenset[str]) -> bool:
    if _in_heldout(path.resolve()):
        return True
    if not path.exists():
        return False
    try:
        files = expand_paths([path])
    except InputError:
        return False  # A directory with no trace files reads nothing.
    return any(
        _in_heldout(file.resolve()) or hashlib.sha256(file.read_bytes()).hexdigest() in pinned
        for file in files
    )


def heldout_inputs(paths: Sequence[Path]) -> list[Path]:
    pinned = _pinned_heldout_hashes(paths)
    return [path for path in paths if _is_heldout_path(path, pinned)]


def refuse_heldout(paths: Sequence[Path], purpose: str) -> None:
    """For inputs that must never be held-out, whatever the environment says."""
    flagged = heldout_inputs(paths)
    if flagged:
        names = ", ".join(shown_path(path) for path in flagged)
        raise GauntletError(f"{purpose} must not read held-out data: {names}")


def refuse_output(path: Path) -> None:
    """An output must not land in the frozen split or overwrite the access log."""
    resolved = path.resolve()
    is_log = [part.casefold() for part in resolved.parts[-2:]] == list(LOG_PATH.parts)
    if _in_heldout(resolved) or is_log:
        raise GauntletError(f"refusing to write {shown_path(path)}: it is firewall-protected")


def _short_commit(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _log_root(anchors: Sequence[Path]) -> Path:
    """The checkout that holds the data being read, wherever the command was started."""
    candidates = [find_repo_root(path) for path in anchors]
    for root in (*candidates, repo_root(), _package_checkout()):
        if (root / ".git").exists():
            return root
    return repo_root()


def _append_log(command: str, flagged: Sequence[Path], anchors: Sequence[Path]) -> None:
    root = _log_root([*flagged, *anchors])
    names = [repo_relative(path, root) or shown_path(path) for path in flagged]
    inputs = ", ".join(names) or "split heldout of the corpus labels"
    path = root / LOG_PATH
    existing = path.read_text(encoding="utf-8") if path.is_file() else LOG_HEADER
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_text(path, existing + f"| {stamp} | {_short_commit(root)} | {command} | {inputs} |\n")


def require_clearance(
    command: str,
    paths: Sequence[Path],
    *,
    scoring_split: bool = False,
    anchors: Sequence[Path] = (),
) -> bool:
    """Refuse held-out inputs unless declared, and log a declared read before it happens.

    Returns whether a declared read was logged. ``anchors`` say which checkout a read of the
    labelled split belongs to, when no input path is flagged.
    """
    flagged = heldout_inputs(paths)
    if not flagged and not scoring_split:
        return False
    if os.environ.get(HELDOUT_ENV) != "1":
        names = [shown_path(path) for path in flagged] or ["split heldout of the corpus labels"]
        raise GauntletError(
            f"{command} refuses held-out input ({', '.join(names)}); held-out scoring needs "
            f"{HELDOUT_ENV}=1 and is logged in {LOG_PATH.as_posix()}"
        )
    _append_log(command, flagged, anchors)
    return True
