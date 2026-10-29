"""Strict JSONL reading and canonical JSON writing.

Readers fail closed: malformed JSON, duplicate keys, NaN or Infinity, blank lines and schema
violations all raise InputError with the file and line number.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from agent_detection_gauntlet.errors import InputError


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def strict_json_loads(text: str) -> Any:
    """Parse JSON, rejecting duplicate keys and NaN or Infinity."""
    return json.loads(
        text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant
    )


def format_validation_error(error: ValidationError) -> str:
    parts = []
    for item in error.errors(include_url=False):
        location = ".".join(str(part) for part in item["loc"])
        message = item["msg"]
        parts.append(f"{location}: {message}" if location else message)
    return "; ".join(parts)


def read_jsonl[M: BaseModel](path: Path, model: type[M]) -> list[tuple[int, M]]:
    """Validate every line of a JSONL file against ``model``. Returns (line number, record)."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InputError(path, f"cannot read file: {exc.strerror or type(exc).__name__}") from exc
    records: list[tuple[int, M]] = []
    lines = raw.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    for number, line_bytes in enumerate(lines, start=1):
        try:
            line = line_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InputError(path, f"not valid UTF-8: {exc.reason}", number) from exc
        line = line.removesuffix("\r")
        if not line.strip():
            raise InputError(path, "blank line", number)
        try:
            strict_json_loads(line)
        except ValueError as exc:
            raise InputError(path, f"malformed JSON: {exc}", number) from exc
        try:
            record = model.model_validate_json(line)
        except ValidationError as exc:
            raise InputError(path, format_validation_error(exc), number) from exc
        records.append((number, record))
    return records


def canonical_json(value: Any) -> str:
    """Compact JSON with sorted keys. Equal values always produce equal text."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def pretty_json(value: Any) -> str:
    """Indented JSON with sorted keys and a trailing newline."""
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def write_text(path: Path, text: str) -> None:
    """Write UTF-8 text with LF line endings on every platform."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def write_jsonl(path: Path, records: Iterable[BaseModel]) -> None:
    lines = [canonical_json(record.model_dump(mode="json")) + "\n" for record in records]
    write_text(path, "".join(lines))


def expand_paths(paths: Sequence[Path], suffix: str = ".jsonl") -> list[Path]:
    """Expand directories to the sorted files with ``suffix`` beneath them."""
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            found = sorted(p for p in path.rglob(f"*{suffix}") if p.is_file())
            if not found:
                raise InputError(path, f"directory contains no {suffix} files")
            files.extend(found)
        elif path.is_file():
            files.append(path)
        else:
            raise InputError(path, "no such file or directory")
    seen: set[Path] = set()
    unique: list[Path] = []
    for file in files:
        resolved = file.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(file)
    return unique
