"""Load trace files into ordered, integrity-checked traces."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from agent_detection_gauntlet.errors import InputError
from agent_detection_gauntlet.io.jsonl import expand_paths, read_jsonl
from agent_detection_gauntlet.schema.trace import (
    Trace,
    TraceEvent,
    event_order_key,
    integrity_problems,
)


@dataclass(frozen=True)
class TraceSet:
    """Traces in trace_id order, plus the files they came from."""

    traces: tuple[Trace, ...]
    files: tuple[Path, ...]

    @property
    def event_count(self) -> int:
        return sum(len(trace.events) for trace in self.traces)

    def trace_ids(self) -> list[str]:
        return [trace.trace_id for trace in self.traces]


def load_traces(paths: Sequence[Path]) -> TraceSet:
    """Read every event, group by trace_id, sort by (timestamp, span_id), check integrity.

    A trace may span several files. Any problem raises InputError naming the file and line.
    """
    files = expand_paths(paths)
    grouped: dict[str, list[tuple[TraceEvent, Path, int]]] = {}
    for file in files:
        records = read_jsonl(file, TraceEvent)
        if not records:
            raise InputError(file, "file contains no events")
        for line, event in records:
            grouped.setdefault(event.trace_id, []).append((event, file, line))

    traces: list[Trace] = []
    for trace_id in sorted(grouped):
        located = sorted(grouped[trace_id], key=lambda item: event_order_key(item[0]))
        events = tuple(item[0] for item in located)
        problems = integrity_problems(events)
        if problems:
            index, message = problems[0]
            _, file, line = located[index]
            raise InputError(file, f"trace {trace_id!r}: {message}", line)
        traces.append(Trace(trace_id=trace_id, events=events))
    return TraceSet(traces=tuple(traces), files=tuple(files))
