"""Load ground-truth label files."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from agent_detection_gauntlet.errors import InputError
from agent_detection_gauntlet.io.jsonl import read_jsonl
from agent_detection_gauntlet.paths import shown_path
from agent_detection_gauntlet.schema.labels import LabelRecord


def load_labels(paths: Sequence[Path]) -> dict[str, LabelRecord]:
    """Map trace_id to its label. A trace labeled twice is an error."""
    labels: dict[str, LabelRecord] = {}
    origin: dict[str, tuple[Path, int]] = {}
    for path in paths:
        if not path.is_file():
            raise InputError(path, "no such file")
        for line, record in read_jsonl(path, LabelRecord):
            if record.trace_id in labels:
                first_path, first_line = origin[record.trace_id]
                raise InputError(
                    path,
                    f"trace {record.trace_id!r} is already labeled at "
                    f"{shown_path(first_path)}:{first_line}",
                    line,
                )
            labels[record.trace_id] = record
            origin[record.trace_id] = (path, line)
    return labels
