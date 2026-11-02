"""Write the generated artifacts, NOT_CONVERTED.md and FIELD_MAPPINGS.md."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from agent_detection_gauntlet.export.convert import (
    FORMATS,
    HEADER,
    LABEL,
    RENDERERS,
    assumed_fields,
    conversion_gap,
)
from agent_detection_gauntlet.io.jsonl import write_text
from agent_detection_gauntlet.metrics.compute import sha256_file
from agent_detection_gauntlet.rules.loader import LoadedRule


@dataclass(frozen=True)
class ExportSummary:
    converted: dict[str, list[str]]
    not_converted: dict[str, list[str]]


def render_not_converted(rules: Sequence[LoadedRule]) -> str:
    lines = [
        "# Rules not converted",
        "",
        f"{HEADER} Label: {LABEL}.",
        "",
        "These rules or formats would need an approximation that looks equivalent to the native "
        "rule, so nothing is emitted for them. The native rule stays the only faithful form.",
        "",
        "| Rule | Format | Reason |",
        "|---|---|---|",
    ]
    for item in rules:
        gaps: dict[str, list[str]] = {}
        for target in FORMATS:
            gap = conversion_gap(item.rule, target)
            if gap:
                gaps.setdefault(gap, []).append(target)
        lines += [
            f"| {item.rule.id} | {', '.join(targets)} | {gap} |" for gap, targets in gaps.items()
        ]
    return "\n".join(lines) + "\n"


def render_field_mappings(rules: Sequence[LoadedRule]) -> str:
    fields: dict[str, str] = {}
    for item in rules:
        if any(conversion_gap(item.rule, target) is None for target in FORMATS):
            fields.update(assumed_fields(item.rule))
    lines = [
        "# Assumed field mappings",
        "",
        f"{HEADER} Label: {LABEL}.",
        "",
        "No SIEM schema was tested. Every generated query assumes one flat record per trace event, "
        "with these fields, computed at ingest exactly as docs/rule-format.md and docs/engine.md "
        "define them. A deployment without them will not match what the native rule matches.",
        "",
        "| Target field | Must hold |",
        "|---|---|",
    ]
    lines += [f"| `{name}` | {fields[name]} |" for name in sorted(fields)]
    return "\n".join(lines) + "\n"


def export_rules(rules: Sequence[LoadedRule], targets: Sequence[str], out: Path) -> ExportSummary:
    converted: dict[str, list[str]] = {}
    not_converted: dict[str, list[str]] = {}
    for target in targets:
        folder = out / target
        extension = FORMATS[target]
        if folder.is_dir():
            # A rule that stopped converting must not leave an old query behind.
            for stale in folder.glob(f"*.{extension}"):
                stale.unlink()
        for item in rules:
            if conversion_gap(item.rule, target) is not None:
                not_converted.setdefault(target, []).append(item.rule.id)
                continue
            text = RENDERERS[target](item.rule, sha256_file(item.path))
            write_text(folder / f"{item.rule.id}.{extension}", text)
            converted.setdefault(target, []).append(item.rule.id)
    write_text(out / "NOT_CONVERTED.md", render_not_converted(rules))
    write_text(out / "FIELD_MAPPINGS.md", render_field_mappings(rules))
    return ExportSummary(converted, not_converted)
