"""Fail on prose that claims coverage the JSON does not support.

Scans every Markdown file in the repository for a technique ID within a short distance of the words
covered, coverage, covers or covering. Only a negation directly before the word cancels it: "not
covered" claims nothing, "not only covered" does. A technique covered only in one evasion column
may be claimed only if the nearby text names that column. Held-out and evasion folders are not read,
and the generated coverage doc is checked byte for byte instead.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from agent_detection_gauntlet.coverage.model import CoverageReport, PopulationName
from agent_detection_gauntlet.paths import shown_path

TECHNIQUE_ID = re.compile(
    r"(?<![\w.])(AML\.T\d{4}(?:\.\d{3})?|LLM\d{2}|ASI\d{2}|T\d{4}(?:\.\d{3})?)(?!\w)",
    re.IGNORECASE,
)
CLAIM_WORD = re.compile(r"\b(?:covered|coverage|covers|covering)\b", re.IGNORECASE)
NEGATION = re.compile(
    r"\b(?:not|not yet|no|never|without|nor|lacks?|zero|cannot|isn't|aren't|"
    r"(?:does not|doesn't|do not|don't) have)\s+$",
    re.IGNORECASE,
)
NEAR = 80
SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "out",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
}
SKIP_PREFIXES = ("datasets/corpus/heldout", "datasets/evasion")
COLUMN_WORDS: Mapping[PopulationName, str] = {
    "payload_mutations": "payload mutation",
    "attack_variants": "attack variant",
}


@dataclass(frozen=True)
class Claim:
    path: Path
    line: int
    technique: str


def _windows(text: str) -> Iterable[tuple[int, str, str]]:
    """Each (line, technique id, nearby text) with an unnegated claim word near the id."""
    text = text.replace(chr(0x2019), "'")
    words = [
        match.start()
        for match in CLAIM_WORD.finditer(text)
        if NEGATION.search(text[max(0, match.start() - 40) : match.start()]) is None
    ]
    for match in TECHNIQUE_ID.finditer(text):
        if any(match.start() - NEAR <= word <= match.end() + NEAR for word in words):
            nearby = text[max(0, match.start() - NEAR) : match.end() + NEAR]
            yield text.count("\n", 0, match.start()) + 1, match.group(1).upper(), nearby


def find_claims(text: str) -> Iterable[tuple[int, str]]:
    for line, technique, _ in _windows(text):
        yield line, technique


def docs_to_scan(root: Path, generated: Path) -> list[Path]:
    paths: list[Path] = []
    for path in sorted(root.rglob("*.md")):
        relative = path.relative_to(root)
        if SKIP_DIRS.intersection(relative.parts):
            continue
        if relative.as_posix().startswith(SKIP_PREFIXES):
            continue
        if path.resolve() != generated.resolve():
            paths.append(path)
    return paths


def _supported(technique: str, nearby: str, report: CoverageReport) -> bool:
    for item in report.techniques:
        if item.id != technique:
            continue
        for verdict in item.verdicts:
            if not verdict.covered:
                continue
            if verdict.population == "clean_heldout":
                return True
            if COLUMN_WORDS[verdict.population] in nearby.lower():
                return True
    return False


def unsupported_claims(paths: Iterable[Path], report: CoverageReport) -> list[Claim]:
    found: list[Claim] = []
    for path in paths:
        text = path.read_bytes().decode("utf-8")
        found += [
            Claim(path, line, technique)
            for line, technique, nearby in _windows(text)
            if not _supported(technique, nearby, report)
        ]
    return found


def render_claim(claim: Claim) -> str:
    return (
        f"{shown_path(claim.path)}:{claim.line}: {claim.technique} sits next to a coverage claim "
        "the coverage JSON does not support"
    )
