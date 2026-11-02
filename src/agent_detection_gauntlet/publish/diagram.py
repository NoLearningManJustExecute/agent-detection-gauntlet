"""Render the architecture diagram from its YAML source into a plain, static SVG."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, Field, ValidationError

from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.io.jsonl import format_validation_error
from agent_detection_gauntlet.paths import shown_path
from agent_detection_gauntlet.rules.loader import load_yaml_document
from agent_detection_gauntlet.schema.common import STRICT_MODEL, NonEmptyStr

DIAGRAM_SOURCE = Path("docs/assets/architecture.yaml")
DIAGRAM_SVG = Path("docs/assets/architecture.svg")
BOX_WIDTH = 210
BOX_GAP = 40
MARGIN = 24
TOP = 70
BOX_HEIGHT = 190
SANS = '"Segoe UI", Helvetica, Arial, sans-serif'


class Stage(BaseModel):
    model_config = STRICT_MODEL

    name: NonEmptyStr
    items: Annotated[list[NonEmptyStr], Field(min_length=1)]


class Diagram(BaseModel):
    model_config = STRICT_MODEL

    title: NonEmptyStr
    stages: Annotated[list[Stage], Field(min_length=2)]
    footer: NonEmptyStr


def load_diagram(path: Path) -> Diagram:
    if not path.is_file():
        raise GauntletError(f"no diagram source at {shown_path(path)}")
    origin = shown_path(path)
    try:
        document = load_yaml_document(path.read_text(encoding="utf-8"), origin)
        return Diagram.model_validate_json(document)
    except ValidationError as exc:
        raise GauntletError(f"{origin}: {format_validation_error(exc)}") from exc
    except ValueError as exc:
        raise GauntletError(f"{origin}: {exc}") from exc


def _stage(index: int, stage: Stage, last: bool) -> list[str]:
    x = MARGIN + index * (BOX_WIDTH + BOX_GAP)
    parts = [
        f'<rect class="box" x="{x}" y="{TOP}" width="{BOX_WIDTH}" height="{BOX_HEIGHT}" rx="10"/>',
        f'<text class="head" x="{x + 16}" y="{TOP + 34}">{escape(stage.name)}</text>',
    ]
    for row, item in enumerate(stage.items):
        y = TOP + 70 + row * 38
        parts.append(f'<text class="item" x="{x + 16}" y="{y}">{escape(item)}</text>')
    if not last:
        middle = TOP + BOX_HEIGHT // 2
        start, end = x + BOX_WIDTH + 4, x + BOX_WIDTH + BOX_GAP - 4
        parts.append(
            f'<line class="flow" x1="{start}" y1="{middle}" x2="{end - 8}" y2="{middle}"/>'
        )
        parts.append(
            f'<path class="tip" d="M{end - 10} {middle - 6} L{end} {middle} '
            f'L{end - 10} {middle + 6} Z"/>'
        )
    return parts


def render_diagram(diagram: Diagram) -> str:
    count = len(diagram.stages)
    width = MARGIN * 2 + count * BOX_WIDTH + (count - 1) * BOX_GAP
    height = TOP + BOX_HEIGHT + 60
    summary = " to ".join(stage.name for stage in diagram.stages)
    body = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" '
        f'height="{height}" role="img" aria-label="Pipeline: {escape(summary)}">',
        "<style>",
        ".bg{fill:#161e2b}.box{fill:#1e2735;stroke:#34414f}.flow{stroke:#8b5cf6;stroke-width:2}",
        ".tip{fill:#8b5cf6}",
        f".title{{fill:#e8eef5;font:700 20px {SANS}}}",
        f".head{{fill:#c4b5fd;font:700 17px {SANS}}}",
        f".item{{fill:#e8eef5;font:13px {SANS}}}",
        f".foot{{fill:#a9b6c4;font:13px {SANS}}}",
        "</style>",
        f'<rect class="bg" width="{width}" height="{height}" rx="14"/>',
        f'<text class="title" x="{MARGIN}" y="42">{escape(diagram.title)}</text>',
    ]
    for index, stage in enumerate(diagram.stages):
        body += _stage(index, stage, index == count - 1)
    body.append(
        f'<text class="foot" x="{MARGIN}" y="{TOP + BOX_HEIGHT + 34}">'
        f"{escape(diagram.footer)}</text>"
    )
    body.append("</svg>")
    return "\n".join(body) + "\n"
