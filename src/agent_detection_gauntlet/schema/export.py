"""Generate the JSON Schemas checked in under schemas/ and detect drift from the models."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel

from agent_detection_gauntlet.io.jsonl import pretty_json, write_text
from agent_detection_gauntlet.metrics.report import MetricsReport
from agent_detection_gauntlet.rules.model import Rule
from agent_detection_gauntlet.schema.detection import Detection
from agent_detection_gauntlet.schema.labels import LabelRecord
from agent_detection_gauntlet.schema.trace import TraceEvent

DRAFT = "https://json-schema.org/draft/2020-12/schema"

SCHEMA_MODELS: dict[str, tuple[type[BaseModel], str]] = {
    "trace-event.schema.json": (TraceEvent, "One line of a trace JSONL file."),
    "label.schema.json": (LabelRecord, "One line of a labels JSONL file."),
    "rule.schema.json": (Rule, "A detection rule (YAML source, validated as JSON)."),
    "detection.schema.json": (Detection, "One line of a detections JSONL file."),
    "metrics-report.schema.json": (MetricsReport, "The metrics report JSON document."),
}


def schema_documents() -> dict[str, str]:
    """Render every schema as deterministic JSON text."""
    documents: dict[str, str] = {}
    for name, (model, description) in SCHEMA_MODELS.items():
        schema: dict[str, Any] = {"$schema": DRAFT}
        schema.update(model.model_json_schema(mode="validation"))
        schema["description"] = description
        documents[name] = pretty_json(schema)
    return documents


def export_schemas(directory: Path) -> list[Path]:
    written: list[Path] = []
    for name, text in schema_documents().items():
        path = directory / name
        write_text(path, text)
        written.append(path)
    return written


def schema_drift(directory: Path) -> list[str]:
    """Names of schema files that are missing, stale, or unexpected in ``directory``."""
    expected = schema_documents()
    drift: list[str] = []
    for name, text in expected.items():
        path = directory / name
        if not path.is_file() or path.read_bytes() != text.encode("utf-8"):
            drift.append(name)
    if directory.is_dir():
        for path in sorted(directory.glob("*.json")):
            if path.name not in expected:
                drift.append(path.name)
    return sorted(drift)
