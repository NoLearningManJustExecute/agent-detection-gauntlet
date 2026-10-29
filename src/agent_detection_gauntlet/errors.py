"""Exception types. Every user-facing failure is a GauntletError with a clear message."""

from __future__ import annotations

from pathlib import Path

from agent_detection_gauntlet.paths import shown_path


class GauntletError(Exception):
    """Base class for errors that the CLI reports and exits non-zero on."""


class InputError(GauntletError):
    """A problem with an input file, optionally pinned to a line number."""

    def __init__(self, path: Path | str, message: str, line: int | None = None) -> None:
        self.path = Path(path)
        self.line = line
        self.detail = message
        shown = shown_path(self.path)
        location = shown if line is None else f"{shown}:{line}"
        super().__init__(f"{location}: {message}")


class CatalogError(GauntletError):
    """The packaged mapping catalog is malformed."""


class MetricsInputError(GauntletError):
    """Detections, labels, traces and rules do not line up for scoring."""
