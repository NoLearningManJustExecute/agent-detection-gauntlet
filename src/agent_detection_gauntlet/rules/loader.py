"""Load rule files. YAML is parsed safely, duplicate keys are rejected, and the result is
validated through JSON in strict mode so YAML type surprises fail closed."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agent_detection_gauntlet.errors import InputError
from agent_detection_gauntlet.io.jsonl import format_validation_error
from agent_detection_gauntlet.rules.model import Rule

RULE_SUFFIXES: tuple[str, ...] = (".yaml", ".yml")


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that refuses mappings with repeated keys."""


def _construct_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in mapping:
            line = key_node.start_mark.line + 1
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r} on line {line}", key_node.start_mark
            )
        mapping[key] = loader.construct_object(value_node, deep=True)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _not_json(value: Any) -> Any:
    raise ValueError(
        f"value {value!r} of type {type(value).__name__} is not plain JSON data; quote it"
    )


def load_yaml_document(text: str, origin: str) -> str:
    """Parse one YAML mapping and return it re-encoded as JSON text.

    Raises ValueError for YAML errors, non-mapping documents, or values JSON cannot hold
    (for example unquoted dates).
    """
    try:
        # _UniqueKeyLoader subclasses SafeLoader, so no arbitrary Python objects are built.
        data = yaml.load(text, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("document must be a mapping")
    return json.dumps(data, default=_not_json, allow_nan=False)


@dataclass(frozen=True)
class LoadedRule:
    path: Path
    rule: Rule


def rule_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        raise InputError(directory, "rules directory does not exist")
    files = sorted(
        path for path in directory.iterdir() if path.is_file() and path.suffix in RULE_SUFFIXES
    )
    if not files:
        raise InputError(directory, "no rule files (*.yaml, *.yml) found")
    return files


def load_rule_file(path: Path) -> Rule:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(path, f"cannot read rule file: {exc}") from exc
    try:
        document = load_yaml_document(text, path.as_posix())
        return Rule.model_validate_json(document)
    except ValidationError as exc:
        raise InputError(path, format_validation_error(exc)) from exc
    except ValueError as exc:
        raise InputError(path, str(exc)) from exc
