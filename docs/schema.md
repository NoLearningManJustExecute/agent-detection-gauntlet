# Data formats

This document describes the three line-oriented file formats the pipeline reads and writes:
traces, labels and detections. The models live in `src/agent_detection_gauntlet/schema/`.
Generated JSON Schemas for every format are committed under `schemas/` (see
[JSON Schemas](#json-schemas)).

## OpenTelemetry GenAI conventions: pinned version

Attribute names follow the OpenTelemetry GenAI semantic conventions wherever a name exists.

- **Pinned to:** `open-telemetry/semantic-conventions` **v1.41.1**, released 2026-05-11. This
  is the last core release that defines the GenAI attributes as active.
  Registry page:
  <https://github.com/open-telemetry/semantic-conventions/blob/v1.41.1/docs/registry/attributes/gen-ai.md>
- **Since v1.42.0** (2026-06-12) the GenAI conventions live in a dedicated repository,
  `open-telemetry/semantic-conventions-genai`. As of 2026-10-28 that repository had no tagged
  release. The attribute names used here are unchanged there.
- **Stability:** every GenAI attribute has stability `development`. The conventions are still
  experimental and may change. The `schema_version` field lets the trace format move when they
  do.

These facts were checked against the primary sources on 2026-10-28.

## Traces

A trace is one agent session. Each line of a trace file is one JSON object describing one
event.

### Core fields

Every field is required. Unknown top-level keys are rejected and no type coercion is done.

| Field | Type | Rules |
| --- | --- | --- |
| `schema_version` | string | Must be `"0.1"`. |
| `trace_id` | string | Identifier: `^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`. |
| `span_id` | string | Identifier, same pattern. Unique within the trace. |
| `parent_span_id` | string or null | Required key. `null` for a root event, otherwise an identifier of another span in the same trace. Must not equal `span_id`. |
| `timestamp` | string | RFC 3339 in UTC: `YYYY-MM-DDTHH:MM:SS`, optional fraction of 1 to 6 digits, then `Z` or `+00:00`. Other offsets are rejected. |
| `event_type` | string | One of the event types below. |
| `attributes` | object | OpenTelemetry GenAI attributes plus `adg.*` extensions. May be empty. |

### Event types

| `event_type` | Meaning | Content-bearing |
| --- | --- | --- |
| `session.start` | The trace begins. | no |
| `user.prompt` | A user message enters the agent. | yes |
| `retrieval` | Content is fetched from a data source. | yes |
| `llm.request` | A request is sent to the model. | yes |
| `llm.response` | The model responds. | yes |
| `tool.call` | The agent invokes a tool. | yes |
| `tool.result` | A tool returns. | yes |
| `guardrail.action` | A guardrail makes a decision. | no |
| `session.end` | The trace ends. | no |

Only content-bearing events may carry provenance attributes (see below).

### GenAI attributes

These attribute names come from the pinned conventions. All are optional. The ones marked
"string" must be strings when present; the reader rejects any other type.

| Attribute | Type | Meaning |
| --- | --- | --- |
| `gen_ai.operation.name` | string | The operation. Fixtures use `chat`, `retrieval` and `execute_tool`. |
| `gen_ai.request.model` | string | Model name requested. |
| `gen_ai.response.model` | string | Model name that produced the response. |
| `gen_ai.provider.name` | string | The model provider. |
| `gen_ai.conversation.id` | string | Identifier of the conversation the trace belongs to. |
| `gen_ai.agent.name` | string | Name of the agent. |
| `gen_ai.data_source.id` | string | Identifier of the data source a retrieval read from. |
| `gen_ai.tool.name` | string | Name of the tool invoked. |
| `gen_ai.tool.call.id` | string | Identifier that links a `tool.call` to its `tool.result`. |
| `gen_ai.tool.call.arguments` | any JSON | Arguments passed to the tool. |
| `gen_ai.tool.call.result` | any JSON | Value returned by the tool. |

Other attribute keys that do not start with `adg.` are accepted with any JSON value and are not
checked further. Every attribute key must be non-empty and must not have leading or trailing
whitespace.

### `adg.*` extensions

Where the conventions have no attribute, the schema uses the `adg.` prefix. The set is closed:
**any `adg.*` key not listed here is rejected**, so a typo fails closed instead of being
silently ignored.

| Attribute | Allowed on | Value |
| --- | --- | --- |
| `adg.source.trust` | content-bearing events | One of `trusted`, `untrusted`, `unknown`. **Required on `retrieval` events.** |
| `adg.data.labels` | content-bearing events | Non-empty list without repeats, drawn from `secret`, `pii`, `internal`, `public`. |
| `adg.content.ref` | content-bearing events | Non-empty list without repeats of span ids (identifier pattern). Each names an earlier event in the same trace whose content this event's content derives from. Must not contain the event's own `span_id`. |
| `adg.content.text` | content-bearing events | String. The text content of the event. |
| `adg.guardrail.decision` | `guardrail.action` only | One of `allow`, `block`, `redact`, `flag`. |

The first four are the provenance attributes. Placing any of them on a non-content-bearing
event (`session.start`, `guardrail.action`, `session.end`) is an error.

`adg.content.ref` is the provenance chain. The engine follows it transitively for the
`derives_from` requirement (see [engine.md](engine.md)).

### Example event

One line from the synthetic fixtures:

```json
{"attributes":{"adg.content.text":"Forecast: light rain tomorrow, high of 12C.","adg.data.labels":["public"],"adg.source.trust":"untrusted","gen_ai.data_source.id":"web","gen_ai.operation.name":"retrieval"},"event_type":"retrieval","parent_span_id":"s01","schema_version":"0.1","span_id":"s03","timestamp":"2026-01-15T09:20:04Z","trace_id":"syn-0003"}
```

### Files, ordering and integrity

`gauntlet validate-traces` (and every command that loads traces) applies these rules. Any
failure stops the run with an error of the form `path:line: message`.

File handling:

- Arguments may be files or directories. A directory is searched recursively for `*.jsonl`
  files, in sorted order. A directory with no `*.jsonl` files is an error. A file named twice is
  read once.
- Files must be UTF-8. Lines end in LF; a trailing CR is stripped. A single final newline is
  allowed.
- A blank or whitespace-only line is an error.
- A file with no events is an error.

Per line:

- The line must be valid JSON. Duplicate keys in any object are rejected. `NaN`, `Infinity`
  and `-Infinity` are rejected.
- The object must validate against the core fields and attribute rules above.

Per trace:

- Events are grouped by `trace_id`. **A trace may span several files.**
- Events are put in canonical order: sorted by `(timestamp, span_id)`. Ties on timestamp are
  broken by comparing `span_id` as a string. File order and line order do not matter.
- `span_id` values must be unique within the trace.
- A non-null `parent_span_id` must name a span in the same trace, and following parent links
  must never loop back to the starting span. A parent does not have to come earlier in canonical
  order, because parent and child can share a timestamp.
- Every entry in `adg.content.ref` must name a span in the same trace that comes **earlier in
  canonical order**. A reference to a later event, or to an event at the same timestamp with a
  larger `span_id`, is an error.

When a trace has several problems, the error names the first one, at the file and line of the
event involved.

## Labels

Ground truth lives in a separate JSONL file, one object per trace. Labels are never stored
inside traces. **The engine never reads labels**; only the `metrics` stage does.

Labels files use the same strict JSONL reader as traces (UTF-8, no blank lines, no duplicate
keys, no `NaN`, errors reported as `path:line`).

| Field | Type | Rules |
| --- | --- | --- |
| `schema_version` | string | Must be `"0.1"`. |
| `trace_id` | string | Identifier pattern. |
| `label` | string | `malicious` or `benign`. |
| `attack_class` | string or null | Non-blank string for malicious, `null` for benign. |
| `attack_succeeded` | bool or null | `true` or `false` for malicious, `null` for benign. Must be a JSON boolean. |
| `mutation` | string or null | The evasion mutation applied, or `null` for an unmutated run. Non-blank when present. Must be `null` for benign. |
| `guardrails` | string | `on` or `off`. |
| `split` | string | `dev` or `heldout`. |
| `source` | string | Where the trace came from: `synthetic`, `rag-attack-lab` or `agent-risk-framework`. |

All keys are required, including those whose value is `null`. Unknown keys are rejected.

Consistency rules:

- A `malicious` label needs a non-null `attack_class` and a non-null `attack_succeeded`.
- A `benign` label must have `attack_class`, `attack_succeeded` and `mutation` all `null`.
- A trace may be labeled only once across all labels input. A second label for the same
  `trace_id` is an error that names the first location.

How `metrics` maps labels to outcome buckets is described in [metrics.md](metrics.md).

## Detections

`gauntlet scan` writes one detection record per rule hit, one JSON object per line.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | `"0.1"`. |
| `rule_id` | string | Rule id, `ADG-` followed by four digits. |
| `rule_version` | string | Rule version (semantic version). |
| `trace_id` | string | Trace the hit is in. |
| `tier` | string | Rule tier: `content`, `sequence` or `behavior`. |
| `severity` | string | Rule severity: `low`, `medium`, `high` or `critical`. |
| `matched_span_ids` | list of strings | Non-empty. The events that make up the hit (order described in [engine.md](engine.md)). |
| `first_timestamp` | string | Earliest timestamp among the matched events, RFC 3339 UTC with `Z`. |
| `last_timestamp` | string | Latest timestamp among the matched events. Must not be before `first_timestamp`. |

Records contain no wall-clock values. Each line is compact JSON with sorted keys, lines end in
LF, and records are sorted by `(trace_id, rule_id, rule_version, first_timestamp,
last_timestamp, matched_span_ids)`. Running the same rules over the same traces gives the same
bytes.

## JSON Schemas

`gauntlet export-schemas` writes JSON Schema (draft 2020-12) documents generated from the models
to `schemas/`:

| File | Describes |
| --- | --- |
| `trace-event.schema.json` | One line of a trace file |
| `label.schema.json` | One line of a labels file |
| `rule.schema.json` | A rule (YAML source, validated as JSON) |
| `detection.schema.json` | One line of a detections file |
| `metrics-report.schema.json` | The metrics report |

`gauntlet export-schemas --check` regenerates the schemas in memory and fails if any committed
file is missing, out of date, or not one of the expected files.

The JSON Schemas describe the shape of a single record. Several rules are enforced only by the
reader: the `adg.*` attribute checks, the string type of GenAI attributes, the label consistency
rules, and all cross-event rules (unique span ids, parent existence, content reference order).
Use `gauntlet validate-traces` for a full check.
