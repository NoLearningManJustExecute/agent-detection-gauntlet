"""Repository-relative paths for everything the package writes or prints.

Reports, logs and error messages never carry an absolute local path. A path inside the
repository root is shown relative to it with ``/`` separators. A path outside it is shown by
file name only, marked as outside the repository.
"""

from __future__ import annotations

from pathlib import Path

_root_override: Path | None = None


def find_repo_root(start: Path | None = None) -> Path:
    """Nearest directory at or above ``start`` (default: the working directory) holding ``.git``.

    Falls back to ``start`` itself when no such directory exists, for example when the package
    runs outside a git checkout.
    """
    here = (start or Path.cwd()).resolve()
    for candidate in (here, *here.parents):
        if (candidate / ".git").exists():
            return candidate
    return here


def set_repo_root(root: Path | None) -> None:
    """Fix the root used by :func:`repo_root`. ``None`` restores discovery."""
    global _root_override
    _root_override = None if root is None else root.resolve()


def repo_root() -> Path:
    return _root_override if _root_override is not None else find_repo_root()


def repo_relative(path: Path, root: Path | None = None) -> str | None:
    """``path`` relative to the root with ``/`` separators, or None when it lies outside."""
    base = (root or repo_root()).resolve()
    try:
        relative = path.resolve().relative_to(base)
    except ValueError:
        return None
    return relative.as_posix() or "."


def shown_path(path: Path | str) -> str:
    """How a path appears in logs and error messages."""
    candidate = Path(path)
    relative = repo_relative(candidate)
    return relative if relative is not None else f"<outside repo>/{candidate.name}"
