"""Fail on a published number that no committed results JSON holds.

Reads the three golden files, never a trace. Fractions and three-decimal rates must appear as such
in a JSON. "N percent" or "N points" must be some rate there, rounded, which is a coarse check,
since many rates exist. Plain counts in prose are not checked, since a bare integer could match
almost anything; the pre-public audit reads them. A token only has to exist somewhere in a JSON, so
this catches invented numbers, not a real number attached to the wrong claim, and it ignores signs.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.paths import shown_path

RESULT_FILES = (
    Path("results/baseline/metrics.json"),
    Path("results/evasion/evasion.json"),
    Path("results/coverage/coverage.json"),
)
PUBLISHED_FILES = (
    Path("README.md"),
    Path("docs/findings.md"),
    Path("docs/limitations.md"),
    Path("docs/demo.md"),
    Path("docs/index.html"),
    Path("docs/assets/demo-banner.svg"),
)
FRACTION = re.compile(r"(?<![\w./-])(\d+)/(\d+)(?![\w/])")
DECIMAL = re.compile(r"(?<![\w.])\d\.\d{3}(?!\d)")
PERCENT = re.compile(r"(?<![\w.])(\d{1,3}) (?:percent|points)\b")
TAG = re.compile(r"<[^>]+>")
NOT_PROSE = re.compile(r"<(style|script)\b.*?</\1>|https?://\S+", re.DOTALL)


@dataclass(frozen=True)
class Traceable:
    fractions: frozenset[str]
    decimals: frozenset[str]
    percents: frozenset[int]


@dataclass(frozen=True)
class Untraced:
    path: Path
    line: int
    token: str

    def render(self) -> str:
        return f"{shown_path(self.path)}:{self.line}: {self.token} is in no results JSON"


def load_results(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise GauntletError(f"no results at {shown_path(path)}")
    data: dict[str, Any] = json.loads(path.read_bytes().decode("utf-8"))
    return data


def _walk(node: Any) -> Iterable[Any]:
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def traceable(documents: Iterable[dict[str, Any]]) -> Traceable:
    fractions: set[str] = set()
    decimals: set[str] = set()
    percents: set[int] = set()
    for document in documents:
        for node in _walk(document):
            if isinstance(node, dict) and {"numerator", "denominator"} <= node.keys():
                fractions.add(f"{node['numerator']}/{node['denominator']}")
            if isinstance(node, dict) and {"detected", "count"} <= node.keys():
                fractions.add(f"{node['detected']}/{node['count']}")
            if isinstance(node, float | int) and not isinstance(node, bool) and abs(node) <= 1:
                decimals.add(f"{abs(node):.3f}")
                percents.add(round(abs(node) * 100))
    return Traceable(frozenset(fractions), frozenset(decimals), frozenset(percents))


def untraced_tokens(text: str, known: Traceable) -> Iterable[tuple[int, str]]:
    """Each (line, token) the results do not hold. Blanking keeps the line numbers."""
    prose = NOT_PROSE.sub(lambda match: re.sub(r"[^\n]", " ", match.group(0)), text)

    def line(position: int) -> int:
        return prose.count("\n", 0, position) + 1

    for match in FRACTION.finditer(prose):
        if match.group(0) not in known.fractions:
            yield line(match.start()), match.group(0)
    for match in DECIMAL.finditer(prose):
        if match.group(0) not in known.decimals:
            yield line(match.start()), match.group(0)
    # A count-up wraps its number in a tag, so percents read the text with tags removed.
    for match in PERCENT.finditer(TAG.sub(lambda tag: re.sub(r"[^\n]", "", tag.group(0)), prose)):
        if int(match.group(1)) not in known.percents:
            yield match.string.count("\n", 0, match.start()) + 1, match.group(0)


def check_published(root: Path) -> tuple[list[Path], list[Untraced]]:
    known = traceable(load_results(root / path) for path in RESULT_FILES)
    scanned = [root / path for path in PUBLISHED_FILES if (root / path).is_file()]
    if not scanned:
        raise GauntletError("no published document to check")
    problems = [
        Untraced(path, line, token)
        for path in scanned
        for line, token in untraced_tokens(path.read_text(encoding="utf-8"), known)
    ]
    return scanned, problems
