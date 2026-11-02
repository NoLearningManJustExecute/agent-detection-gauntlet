"""Write the generated artifacts, NOT_CONVERTED.md and FIELD_MAPPINGS.md."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.export.convert import (
    FORMATS,
    HEADER,
    LABEL,
    RENDERERS,
    SIGMA_REGEX_NOTE,
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
            f"| {item.rule.id} | {', '.join(targets)} | {gap.replace('|', chr(92) + '|')} |"
            for gap, targets in gaps.items()
        ]
    return "\n".join(lines) + "\n"


def render_field_mappings(rules: Sequence[LoadedRule]) -> str:
    fields: dict[str, str] = {}
    for item in rules:
        if not any(conversion_gap(item.rule, target) is None for target in FORMATS):
            continue
        for name, meaning in assumed_fields(item.rule).items():
            if fields.setdefault(name, meaning) != meaning:
                raise GauntletError(f"field {name} would have to hold two different things")
    lines = [
        "# Assumed field mappings",
        "",
        f"{HEADER} Label: {LABEL}.",
        "",
        "No SIEM schema was tested and no such ingest pipeline exists. Every generated query "
        "assumes one flat record per trace event, with these fields, computed at ingest exactly as "
        "docs/rule-format.md and docs/engine.md define them. A deployment without them will not "
        "match what the native rule matches, so for a rule with a derived field, converted means "
        "the test moved here and the normalization moved to that pipeline.",
        "",
        "| Target field | Must hold |",
        "|---|---|",
    ]
    lines += [f"| `{name}` | {fields[name]} |" for name in sorted(fields)]
    lines += [
        "",
        "What exactly means:",
        "",
        "- `nfkc` is Unicode NFKC. `casefold` is full Unicode case folding, not lowercasing.",
        "- `collapse_whitespace` splits on any Unicode whitespace, as Python's `str.split` does, "
        "and joins with single spaces.",
        "- A truncated value can miss. These fields assume no ingest size limit.",
        "- No conformance vectors exist yet to test a pipeline against.",
        f"- Sigma: {SIGMA_REGEX_NOTE}",
    ]
    return "\n".join(lines) + "\n"


def _remove_stale(out: Path, rules: Sequence[LoadedRule], targets: Sequence[str]) -> None:
    """A rule that stopped converting must not leave an old query behind, in any format."""
    for target, extension in FORMATS.items():
        current = {item.rule.id for item in rules if conversion_gap(item.rule, target) is None}
        folder = out / target
        if not folder.is_dir():
            continue
        for path in folder.glob(f"ADG-*.{extension}"):
            if target in targets or path.stem not in current:
                path.unlink()


def export_rules(rules: Sequence[LoadedRule], targets: Sequence[str], out: Path) -> ExportSummary:
    _remove_stale(out, rules, targets)
    converted: dict[str, list[str]] = {}
    not_converted: dict[str, list[str]] = {}
    for target in targets:
        for item in rules:
            if conversion_gap(item.rule, target) is not None:
                not_converted.setdefault(target, []).append(item.rule.id)
                continue
            text = RENDERERS[target](item.rule, sha256_file(item.path))
            write_text(out / target / f"{item.rule.id}.{FORMATS[target]}", text)
            converted.setdefault(target, []).append(item.rule.id)
    write_text(out / "NOT_CONVERTED.md", render_not_converted(rules))
    write_text(out / "FIELD_MAPPINGS.md", render_field_mappings(rules))
    return ExportSummary(converted, not_converted)
