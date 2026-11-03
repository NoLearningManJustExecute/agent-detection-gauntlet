"""Build every generated public document from committed sources. Reads no trace."""

from __future__ import annotations

from pathlib import Path

from agent_detection_gauntlet.catalog import load_catalog
from agent_detection_gauntlet.publish.dashboard import render_dashboard
from agent_detection_gauntlet.publish.diagram import (
    DIAGRAM_SOURCE,
    DIAGRAM_SVG,
    load_diagram,
    render_diagram,
)
from agent_detection_gauntlet.publish.mappings import render_mappings
from agent_detection_gauntlet.publish.numbers import RESULT_FILES, load_results

DASHBOARD = Path("docs/dashboard.html")
MAPPINGS = Path("docs/mappings.md")


def outputs(root: Path) -> list[tuple[Path, str]]:
    documents = {path.as_posix(): load_results(root / path) for path in RESULT_FILES}
    sources = {path.as_posix(): (root / path).read_bytes() for path in RESULT_FILES}
    return [
        (root / DASHBOARD, render_dashboard(sources, documents)),
        (root / MAPPINGS, render_mappings(load_catalog())),
        (root / DIAGRAM_SVG, render_diagram(load_diagram(root / DIAGRAM_SOURCE))),
    ]


def is_current(path: Path, text: str) -> bool:
    return path.is_file() and path.read_bytes() == text.encode("utf-8")
