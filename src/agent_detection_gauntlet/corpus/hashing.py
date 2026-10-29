"""Content hash of a trace that ignores ids and timestamps.

Two runs of one scenario at temperature 0 differ only in ids, timestamps and the
per-run seed; the hash makes them equal so they count once. Span ids are replaced by
their position in canonical order (parents and content references included), and the
attributes below, which name the run rather than describe it, are dropped.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from agent_detection_gauntlet.io.jsonl import canonical_json
from agent_detection_gauntlet.schema.trace import ATTR_CONTENT_REF, TraceEvent

IGNORED_ATTRIBUTES: tuple[str, ...] = (
    "gen_ai.conversation.id",
    "gen_ai.tool.call.id",
    "gen_ai.request.seed",
)
IGNORED_FIELDS: tuple[str, ...] = ("trace_id", "span_id", "timestamp")


def content_hash(events: Sequence[TraceEvent]) -> str:
    """SHA-256 over event types, structure and attributes; `events` in canonical order."""
    position = {event.span_id: index for index, event in enumerate(events)}
    body: list[list[Any]] = []
    for event in events:
        attributes = {
            key: value for key, value in event.attributes.items() if key not in IGNORED_ATTRIBUTES
        }
        refs = event.content_refs()
        if refs:
            attributes[ATTR_CONTENT_REF] = [position[ref] for ref in refs]
        parent = position.get(event.parent_span_id) if event.parent_span_id else None
        body.append([event.schema_version, event.event_type.value, parent, attributes])
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
