from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_detection_gauntlet.errors import InputError
from agent_detection_gauntlet.io.jsonl import expand_paths, read_jsonl, write_jsonl
from agent_detection_gauntlet.io.labels import load_labels
from agent_detection_gauntlet.io.traces import load_traces
from agent_detection_gauntlet.schema.trace import TraceEvent
from tests.conftest import FIXTURE_LABELS, FIXTURE_TRACES, event_dict, write_lines


def good_line(span: str = "s1", **kwargs: object) -> str:
    return json.dumps(event_dict(span, "session.start", **kwargs))  # type: ignore[arg-type]


def write_raw(path: Path, text: str | bytes) -> Path:
    path.write_bytes(text.encode() if isinstance(text, str) else text)
    return path


def test_malformed_line_reports_line_number(tmp_path: Path) -> None:
    path = write_raw(tmp_path / "t.jsonl", good_line() + "\n{not json\n")
    with pytest.raises(InputError) as info:
        read_jsonl(path, TraceEvent)
    assert info.value.line == 2
    assert "malformed JSON" in str(info.value)
    assert str(info.value).startswith("<outside repo>/t.jsonl:2:")


def test_bad_enum_reports_line_number(tmp_path: Path) -> None:
    bad = json.dumps(event_dict("s2", "tool.invoke"))
    path = write_raw(tmp_path / "t.jsonl", good_line() + "\n" + good_line("s3") + "\n" + bad)
    with pytest.raises(InputError, match=r"t\.jsonl:3: event_type") as info:
        read_jsonl(path, TraceEvent)
    assert info.value.line == 3


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('{"a": 1, "a": 2}', "duplicate key"),
        ('{"a": NaN}', "NaN is not valid JSON"),
        ("   ", "blank line"),
    ],
)
def test_strict_json_rules(tmp_path: Path, text: str, message: str) -> None:
    path = write_raw(tmp_path / "t.jsonl", text + "\n")
    with pytest.raises(InputError, match=message):
        read_jsonl(path, TraceEvent)


def test_invalid_utf8(tmp_path: Path) -> None:
    path = write_raw(tmp_path / "t.jsonl", b"\xff\xfe\n")
    with pytest.raises(InputError, match="not valid UTF-8"):
        read_jsonl(path, TraceEvent)


def test_crlf_line_endings_accepted(tmp_path: Path) -> None:
    path = write_raw(tmp_path / "t.jsonl", good_line() + "\r\n")
    assert len(read_jsonl(path, TraceEvent)) == 1


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="cannot read file"):
        read_jsonl(tmp_path / "absent.jsonl", TraceEvent)


def test_expand_paths(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(InputError, match=r"no \.jsonl files"):
        expand_paths([empty])
    with pytest.raises(InputError, match="no such file"):
        expand_paths([tmp_path / "missing"])
    file = write_raw(tmp_path / "a.jsonl", good_line() + "\n")
    assert expand_paths([file, tmp_path, file]) == [file]


def test_load_traces_groups_and_orders_across_files(tmp_path: Path) -> None:
    write_lines(
        tmp_path / "b.jsonl",
        [
            event_dict("s3", "session.end", trace_id="t-1", seconds=5, parent="s1"),
            event_dict("x1", "session.start", trace_id="t-0"),
        ],
    )
    write_lines(
        tmp_path / "a.jsonl",
        [
            event_dict("s2", "user.prompt", trace_id="t-1", seconds=1, parent="s1"),
            # Same timestamp as s2: span_id breaks the tie.
            event_dict("s1", "session.start", trace_id="t-1", seconds=1),
        ],
    )
    trace_set = load_traces([tmp_path])
    assert trace_set.trace_ids() == ["t-0", "t-1"]
    assert [e.span_id for e in trace_set.traces[1].events] == ["s1", "s2", "s3"]
    assert trace_set.event_count == 4
    assert [p.name for p in trace_set.files] == ["a.jsonl", "b.jsonl"]


def test_load_traces_reports_integrity_location(tmp_path: Path) -> None:
    path = write_lines(
        tmp_path / "t.jsonl",
        [
            event_dict("s1", "session.start"),
            event_dict("s2", "user.prompt", {"adg.content.ref": ["s9"]}, seconds=1),
        ],
    )
    with pytest.raises(InputError, match=r"t\.jsonl:2: trace 't-1'.*'s9' is not a span"):
        load_traces([path])


def test_load_traces_rejects_duplicate_spans_across_files(tmp_path: Path) -> None:
    write_lines(tmp_path / "a.jsonl", [event_dict("s1", "session.start")])
    write_lines(tmp_path / "b.jsonl", [event_dict("s1", "session.end", seconds=1)])
    with pytest.raises(InputError, match="duplicate span_id"):
        load_traces([tmp_path])


def test_load_traces_rejects_empty_file(tmp_path: Path) -> None:
    path = write_raw(tmp_path / "t.jsonl", "")
    with pytest.raises(InputError, match="contains no events"):
        load_traces([path])


def test_fixture_traces_load() -> None:
    trace_set = load_traces([FIXTURE_TRACES])
    assert len(trace_set.traces) == 9
    assert all(t.trace_id.startswith("syn-") for t in trace_set.traces)


def test_load_labels(tmp_path: Path) -> None:
    labels = load_labels([FIXTURE_LABELS])
    assert len(labels) == 9
    assert {label.source.value for label in labels.values()} == {"synthetic"}
    duplicate = tmp_path / "dup.jsonl"
    line = FIXTURE_LABELS.read_text(encoding="utf-8").splitlines()[0]
    write_raw(duplicate, f"{line}\n{line}\n")
    with pytest.raises(InputError, match=r"dup\.jsonl:2: trace 'syn-0001' is already labeled"):
        load_labels([duplicate])
    with pytest.raises(InputError, match="no such file"):
        load_labels([tmp_path / "missing.jsonl"])


def test_write_jsonl_is_canonical(tmp_path: Path) -> None:
    records = [record for _, record in read_jsonl(FIXTURE_TRACES / "syn-0001.jsonl", TraceEvent)]
    out = tmp_path / "nested" / "out.jsonl"
    write_jsonl(out, records)
    assert out.read_bytes() == (FIXTURE_TRACES / "syn-0001.jsonl").read_bytes()
