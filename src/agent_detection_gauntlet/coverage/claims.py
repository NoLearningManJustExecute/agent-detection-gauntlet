"""Fail on prose that claims coverage the JSON does not support.

Scans the README and docs for a technique ID within a short distance of the words covered or
coverage. A negated mention such as "not covered" claims nothing. The generated coverage doc is
checked byte for byte instead, so it is not scanned here.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from agent_detection_gauntlet.coverage.model import CoverageReport
from agent_detection_gauntlet.paths import shown_path

TECHNIQUE_ID = re.compile(
    r"(?<![\w.])(AML\.T\d{4}(?:\.\d{3})?|LLM\d{2}|ASI\d{2}|T\d{4}(?:\.\d{3})?)"
)
CLAIM_WORD = re.compile(r"\b(?:covered|coverage)\b", re.IGNORECASE)
NEGATION = re.compile(r"\b(?:not|no|never|without|nor|isn't|aren't)\b[^.\n|]{0,24}$", re.IGNORECASE)
NEAR = 80
TOP_LEVEL_DOCS = ("README.md", "ROADMAP.md", "CONTRIBUTING.md", "SECURITY.md")


@dataclass(frozen=True)
class Claim:
    path: Path
    line: int
    technique: str


def find_claims(text: str) -> Iterable[tuple[int, str]]:
    """Each (line, technique id) where an unnegated claim word sits near a technique id."""
    words = [
        match.start()
        for match in CLAIM_WORD.finditer(text)
        if NEGATION.search(text[max(0, match.start() - 40) : match.start()]) is None
    ]
    for match in TECHNIQUE_ID.finditer(text):
        if any(match.start() - NEAR <= word <= match.end() + NEAR for word in words):
            yield text.count("\n", 0, match.start()) + 1, match.group(1)


def docs_to_scan(root: Path, generated: Path) -> list[Path]:
    paths = [root / name for name in TOP_LEVEL_DOCS if (root / name).is_file()]
    paths += sorted((root / "docs").rglob("*.md")) if (root / "docs").is_dir() else []
    return [path for path in paths if path.resolve() != generated.resolve()]


def unsupported_claims(paths: Iterable[Path], report: CoverageReport) -> list[Claim]:
    supported = {
        technique.id
        for technique in report.techniques
        if any(verdict.covered for verdict in technique.verdicts)
    }
    found: list[Claim] = []
    for path in paths:
        text = path.read_bytes().decode("utf-8")
        found += [
            Claim(path, line, technique)
            for line, technique in find_claims(text)
            if technique not in supported
        ]
    return found


def render_claim(claim: Claim) -> str:
    return (
        f"{shown_path(claim.path)}:{claim.line}: {claim.technique} sits next to a coverage claim "
        "the coverage JSON does not support"
    )
