"""Shared builders for tests."""

from __future__ import annotations

import copy
import json
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from agent_detection_gauntlet.paths import set_repo_root
from agent_detection_gauntlet.rules.model import Rule
from agent_detection_gauntlet.schema.trace import Trace, TraceEvent, event_order_key

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_TRACES = REPO_ROOT / "datasets" / "fixtures" / "traces"
FIXTURE_LABELS = REPO_ROOT / "datasets" / "fixtures" / "labels.jsonl"
RULES_DIR = REPO_ROOT / "rules"

BASE_TIME = datetime(2026, 1, 15, 9, 0, tzinfo=UTC)


def event_dict(
    span_id: str,
    event_type: str,
    attributes: dict[str, Any] | None = None,
    *,
    trace_id: str = "t-1",
    seconds: float = 0,
    parent: str | None = None,
) -> dict[str, Any]:
    stamp = (BASE_TIME + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": "0.1",
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": parent,
        "timestamp": stamp,
        "event_type": event_type,
        "attributes": attributes or {},
    }


def make_event(*args: Any, **kwargs: Any) -> TraceEvent:
    return TraceEvent.model_validate_json(json.dumps(event_dict(*args, **kwargs)))


def make_trace(events: Iterable[TraceEvent], trace_id: str = "t-1") -> Trace:
    return Trace(trace_id=trace_id, events=tuple(sorted(events, key=event_order_key)))


def write_lines(path: Path, records: Iterable[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes("".join(json.dumps(record) + "\n" for record in records).encode())
    return path


SEQUENCE_RULE: dict[str, Any] = {
    "id": "ADG-9001",
    "title": "Test sequence rule",
    "version": "1.0.0",
    "status": "experimental",
    "tier": "sequence",
    "severity": "high",
    "description": "Untrusted retrieval flows into a send.",
    "hypothesis": "Provenance generalizes across payload wording.",
    "mappings": {
        "atlas": ["AML.T0051.001"],
        "owasp_llm": ["LLM01"],
        "owasp_agentic": ["ASI01"],
        "attack": [],
    },
    "telemetry": ["retrieval", "tool.call"],
    "logic": {
        "sequence": {
            "steps": [
                {
                    "name": "fetch",
                    "match": {
                        "event_types": ["retrieval"],
                        "where": {
                            "field": "attributes.adg.source.trust",
                            "op": "equals",
                            "value": "untrusted",
                        },
                    },
                    "bind": {"src": "span_id"},
                },
                {
                    "name": "send",
                    "match": {
                        "event_types": ["tool.call"],
                        "where": {
                            "field": "attributes.gen_ai.tool.name",
                            "op": "equals",
                            "value": "send_email",
                        },
                    },
                    "require": [{"op": "derives_from", "bound": "src"}],
                },
            ]
        }
    },
    "limitations": ["Test limitation."],
    "fixtures": {"tp": ["t-tp"], "fp": ["t-fp"]},
}


def rule_data(**overrides: Any) -> dict[str, Any]:
    data = copy.deepcopy(SEQUENCE_RULE)
    data.update(copy.deepcopy(overrides))
    return data


def make_rule(**overrides: Any) -> Rule:
    return Rule.model_validate_json(json.dumps(rule_data(**overrides)))


def write_rule(directory: Path, data: dict[str, Any], name: str | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name or f"{data['id']}.yaml")
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def taint_trace_events(
    trace_id: str, *, trust: str = "untrusted", linked: bool = True
) -> list[dict[str, Any]]:
    """retrieval -> llm.request -> llm.response -> tool.call send_email."""
    send_refs = ["s4"] if linked else ["s1"]
    return [
        event_dict("s1", "user.prompt", {"adg.source.trust": "trusted"}, trace_id=trace_id),
        event_dict("s2", "retrieval", {"adg.source.trust": trust}, trace_id=trace_id, seconds=1),
        event_dict(
            "s3", "llm.request", {"adg.content.ref": ["s1", "s2"]}, trace_id=trace_id, seconds=2
        ),
        event_dict("s4", "llm.response", {"adg.content.ref": ["s3"]}, trace_id=trace_id, seconds=3),
        event_dict(
            "s5",
            "tool.call",
            {"gen_ai.tool.name": "send_email", "adg.content.ref": send_refs},
            trace_id=trace_id,
            seconds=4,
        ),
    ]


@pytest.fixture
def fixture_dir(tmp_path: Path) -> Path:
    """A fixture trace directory holding a tp trace (t-tp) and an fp trace (t-fp)."""
    directory = tmp_path / "fixtures"
    write_lines(directory / "t-tp.jsonl", taint_trace_events("t-tp"))
    write_lines(directory / "t-fp.jsonl", taint_trace_events("t-fp", trust="trusted"))
    return directory


@pytest.fixture(autouse=True)
def _reset_repo_root() -> Iterator[None]:
    """Each test starts with root discovery, whatever an earlier test fixed."""
    set_repo_root(None)
    yield
    set_repo_root(None)
