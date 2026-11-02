"""The held-out firewall: commands refuse held-out inputs unless scoring is declared.

Rules are written and baselines fitted without access to the held-out split. `scan` and
`metrics` read it only when GAUNTLET_SCORING_HELDOUT=1 is set, and every such run is appended to
docs/heldout-log.md before anything is read. Rule fixtures and baseline fits never read it.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.io.jsonl import expand_paths, write_text
from agent_detection_gauntlet.paths import repo_root, shown_path

HELDOUT_ENV = "GAUNTLET_SCORING_HELDOUT"
CORPUS_DIR = Path("datasets/corpus")
HELDOUT_PREFIX = "heldout/"
MANIFEST_NAME = "SPLIT_MANIFEST.json"
LOG_PATH = Path("docs/heldout-log.md")
LOG_HEADER = (
    "# Held-out access log\n\n"
    "Appended by `gauntlet scan` and `gauntlet metrics` every time they read held-out data.\n"
    "Do not edit by hand.\n\n"
    "| Time (UTC) | Commit | Command | Inputs |\n"
    "|---|---|---|---|\n"
)


def _pinned_heldout_hashes() -> frozenset[str]:
    """Hashes of the held-out files, so a copy elsewhere is still recognized."""
    manifest = repo_root() / CORPUS_DIR / MANIFEST_NAME
    if not manifest.is_file():
        return frozenset()
    files = json.loads(manifest.read_bytes()).get("files", {})
    return frozenset(digest for name, digest in files.items() if name.startswith(HELDOUT_PREFIX))


def _is_heldout_path(path: Path, pinned: frozenset[str]) -> bool:
    resolved = path.resolve()
    parts = resolved.parts
    if any(parts[i : i + 2] == ("corpus", "heldout") for i in range(len(parts) - 1)):
        return True
    # A parent directory would expand to the held-out files beneath it.
    if resolved in (repo_root() / CORPUS_DIR / "heldout").resolve().parents:
        return True
    if not pinned or not path.exists():
        return False
    return any(
        hashlib.sha256(file.read_bytes()).hexdigest() in pinned for file in expand_paths([path])
    )


def heldout_inputs(paths: Sequence[Path]) -> list[Path]:
    pinned = _pinned_heldout_hashes()
    return [path for path in paths if _is_heldout_path(path, pinned)]


def refuse_heldout(paths: Sequence[Path], purpose: str) -> None:
    """For inputs that must never be held-out, whatever the environment says."""
    flagged = heldout_inputs(paths)
    if flagged:
        names = ", ".join(shown_path(path) for path in flagged)
        raise GauntletError(f"{purpose} must not read held-out data: {names}")


def _short_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=repo_root(),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _append_log(command: str, inputs: Sequence[str]) -> None:
    path = repo_root() / LOG_PATH
    existing = path.read_text(encoding="utf-8") if path.is_file() else LOG_HEADER
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"| {stamp} | {_short_commit()} | {command} | {', '.join(inputs)} |\n"
    write_text(path, existing + line)


def require_clearance(command: str, paths: Sequence[Path], *, scoring_split: bool = False) -> None:
    """Refuse held-out inputs unless declared, and log every declared read before it happens."""
    flagged = heldout_inputs(paths)
    if not flagged and not scoring_split:
        return
    names = [shown_path(path) for path in flagged] or ["split heldout of the corpus labels"]
    if os.environ.get(HELDOUT_ENV) != "1":
        raise GauntletError(
            f"{command} refuses held-out input ({', '.join(names)}); held-out scoring needs "
            f"{HELDOUT_ENV}=1 and is logged in {LOG_PATH.as_posix()}"
        )
    _append_log(command, names)
