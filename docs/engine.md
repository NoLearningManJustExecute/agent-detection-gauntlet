# Engine semantics

This document specifies exactly what the detection engine does. The code is in
`src/agent_detection_gauntlet/engine/`: `fields.py` (field resolution and equality),
`conditions.py` (operators and normalization), `primitives.py` (`match`, `sequence`,
`threshold`, `baseline`) and `executor.py` (running rules and building detection records). Rule syntax is in
[rule-format.md](rule-format.md).

The engine reads rules and traces. **It never reads labels.** `gauntlet scan` has no labels
argument, and nothing in the engine package imports the label model.

## Inputs

Traces reach the engine already validated and in canonical order: events sorted by
`(timestamp, span_id)` (see [schema.md](schema.md)). Every index, "earlier", "later" and
"first" below refers to that order. Each rule is evaluated on each trace independently; no state
crosses traces.

## Field resolution

A field reference resolves against one event:

| Reference | Value |
| --- | --- |
| `event_type` | The event type string, for example `"tool.call"`. |
| `span_id` | The span id. |
| `parent_span_id` | The parent span id, or missing for a root event. |
| `attributes.<key>` | `attributes[<key>]` using the full key, or missing if absent. |
| `attributes.<key>#<path>` | Format 1.1. Follows dot-separated object keys and list indexes inside the value. Missing if the path reaches nothing. |
| `attributes.<key>#*` | Format 1.1. Every string inside the value joined with newlines, object keys in sorted order and list items in order. Missing if there are none. Numbers and booleans are not included. |

**A JSON `null` counts as missing.** An attribute present with value `null` behaves exactly like
an absent attribute. Because of this, the rule model rejects `null` as an operand (for `equals`,
and as an entry of an `in` list): it could never match. Use `exists` to test for absence.

## JSON equality

`equals`, `in`, list `contains`, and the sequence `equals` and `contains` requirements compare
values with JSON equality:

- A boolean equals only a boolean of the same value. **A boolean never equals a number**, so
  `true` does not equal `1`.
- Numbers compare numerically, so `1` equals `1.0`.
- Strings compare exactly (after normalization, where the operator applies it).
- Lists are equal when they have the same length and are equal element by element, in order.
- Objects are equal when they have the same set of keys and equal values for each key.
- `null` equals only `null`.
- Values of different JSON types are never equal.

## Normalization

`normalize` steps run in the listed order. They apply only to string values:

- `casefold`: Unicode case folding.
- `nfkc`: Unicode NFKC normalization.
- `collapse_whitespace`: split on any whitespace and rejoin with single spaces, which also trims
  both ends.

Where normalization applies:

| Operator | Event value | Rule value |
| --- | --- | --- |
| `equals` | strings, and strings inside lists, normalized | same |
| `in` | strings, and strings inside lists, normalized | each entry normalized the same way |
| `contains` | normalized if a string; if a list, each string item is normalized | normalized |
| `startswith` | normalized | normalized |
| `regex` | normalized | used as written (see below) |
| `exists` | not applicable | not applicable |

Normalization reaches strings inside lists (at any depth) but not values inside objects. For
`regex`, the subject is normalized and the pattern is not, so the rule model requires the
pattern to be in normalized form already: a pattern that changes under its own `normalize` steps
(for example one with uppercase letters under `casefold`) is rejected when the rule loads.

## Operators

Every operator except `exists` is false when the field is missing.

| `op` | String field | List field | Other types (number, boolean, object) |
| --- | --- | --- | --- |
| `equals` | JSON equality with `value` | JSON equality with `value` (whole list) | JSON equality with `value` |
| `in` | true if JSON-equal to any entry of `value` | true if the whole list is JSON-equal to an entry | true if JSON-equal to any entry |
| `contains` | substring test; `value` must be a string, otherwise false | true if any item is JSON-equal to `value` | false |
| `startswith` | prefix test | false | false |
| `regex` | `re.search`: matches anywhere unless the pattern is anchored | false | false |
| `exists` | `value: true` is true when the field is present and not null; `value: false` is true when it is missing or null | same | same |

Notes:

- `contains` on an object never looks inside it. To reach a key inside
  `gen_ai.tool.call.arguments`, use a value path (`#<key>`) or `#*`.
- `regex` uses Python's `re` module with no flags. Compiled patterns are cached.

## Condition combinators

- `all`: true when every child is true. Children are evaluated in order and evaluation stops at
  the first false child.
- `any`: true when at least one child is true. Evaluation stops at the first true child.
- `not`: true when the child is false. Because comparisons are false on a missing field,
  `not` of a comparison is true when the field is missing.

An event matches an event match spec when its `event_type` is in `event_types` and, if `where`
is present, the condition is true.

## `match`

`match` emits **one hit per matching event**. Each hit has one span. A trace with three matching
events produces three detections.

## `sequence`

A sequence with steps `S1 ... Sn` produces hits whose events are a tuple of event indices
`i1 < i2 < ... < in`, strictly increasing in canonical order, where event `ik` matches step `Sk`
and all constraints below hold. Events between matched events are allowed and ignored.

**One hit per candidate final event.** Every event that matches the last step's event match is a
candidate final event. For each candidate, the engine searches for an assignment of the earlier
steps. It emits at most one hit per candidate, so a trace where two sends follow one untrusted
retrieval yields two detections, one per send.

**Lexicographically smallest assignment.** For a given final event, the earlier steps take the
lexicographically smallest tuple of indices that satisfies every constraint. The search is a
depth-first backtracking search that tries indices in increasing order for each step, so the
first assignment found is the smallest. In practice this picks the earliest qualifying first
step, then the earliest qualifying second step after it, and so on, backing up only when a later
constraint fails.

**`within_events`.** The span from the first matched event to the last matched event, inclusive,
counts at most `within_events` events. That is, `in - i1 + 1 <= within_events`. Every event in
that range counts, whether it matches a step or not.

**`within_seconds`.** The timestamp of the last matched event minus the timestamp of the first
matched event is at most `within_seconds`. The bound is inclusive.

**`bind`.** When a step's event is chosen, each entry `name: field` captures the value of
`field` on that event. Any JSON value can be bound. **If a bound field is missing (or null) on
the event, the step does not hold for that event** and the search moves on. Bindings belong to
the candidate assignment being explored; backtracking discards them.

**`require`.** A step's requirements are checked on the step's candidate event, using values
bound by earlier steps in the same assignment. They are checked before the step's own bindings
are captured. All requirements must hold.

| `op` | Holds when |
| --- | --- |
| `equals` | `field` on the current event is present and JSON-equal to the bound value. |
| `contains` | `field` on the current event is present and either a string that contains the bound value as a substring (the bound value must be a string), or a list with an item JSON-equal to the bound value. False for other types. |
| `derives_from` | The bound value is a string, and it is the span id of an event this event's content derives from. |

No normalization is applied in requirements.

**`derives_from`.** The engine builds, once per trace, the set of ancestors of every event by
following `adg.content.ref` transitively: an event's ancestors are every span it references,
plus every ancestor of those spans. Because the trace loader guarantees that each reference
points to an earlier event, one pass in canonical order computes the full closure. **The set does
not include the event itself.** An event with no `adg.content.ref` has no ancestors, so a missing
link anywhere in the chain breaks derivation.

`derives_from` is usually paired with a `bind` of `span_id` in an earlier step, as in ADG-0001.

**`first_occurrence`.** Format 1.1. Before the search, a step with `first_occurrence` keeps only
the events that match the step and are the first such event in the trace with their value of that
field. Values compare by canonical JSON, as in `threshold` `distinct`. An event without the field
is dropped. A later step's window or requirements do not change which event is first, so a trace
that used the tool before the source event never fires on that tool.

## `threshold`

`threshold` evaluates once per trace and emits **at most one detection per trace**.

1. Collect the events that match `match`, in canonical order.
2. Without `distinct`, the count is the number of those events, and all of them are cited.
3. With `distinct`, events whose `distinct` field is missing or null are ignored. The count is
   the number of distinct values among the remaining events, where two values are the same when
   their canonical JSON encodings (sorted keys, compact) are identical after whole floats are
   turned into integers. Every remaining event is cited, including repeats of the same value.
4. The rule fires when at least one event is cited and `count op value` holds: `gte` is `>=`,
   `gt` is `>`, `eq` is `==`.

Distinct counting agrees with JSON equality: `1` and `1.0` are one value, while `true` and `1`
are two. No normalization is applied, so strings that differ only in case are distinct.

Only `gte`, `gt` and `eq` with `value >= 1` are allowed because a detection must cite at least
one event. Comparisons such as "fewer than N" or "exactly 0" would fire on the absence of events
and leave nothing to point at. Absence-based logic is out of scope for this version.

## `baseline`

`baseline` compares a trace with a statistic fitted on dev benign traces. The engine reads the
`fitted` block in the rule and never reads labels; only `gauntlet fit-baselines` does, and that
code lives outside the engine package.

**`chain_length`** counts the events that match `match`. The fit takes the nearest-rank percentile
of that count over the population: the smallest count with at least `percentile` percent of traces
at or below it, including traces with a count of zero. A trace fires when its count is strictly
above the fitted threshold. At most one detection per trace, citing every counted event. A trace
with no matching event cannot fire.

**`rare_transition`** walks the events that match `match` and have a string `key`, forming pairs of
consecutive keys. The first event pairs with `<start>`, so a first call has a transition too. The
fit counts every pair over the population. A pair fires when its count is below
`max_rate * total`, where `total` is the sum of the fitted counts, so a pair never seen fires
whenever any count exists. One detection per firing pair, citing both events, or the one event when
the pair starts at `<start>`.

Fitting is deterministic: integer counts, traces in `trace_id` order, sorted output. The fitted
values are part of the rule file, so they are covered by anything that hashes the rule.

## Detection records

For every hit the executor writes a record (format in [schema.md](schema.md#detections)):

- `rule_id`, `rule_version`, `tier`, `severity` come from the rule.
- `trace_id` is the trace the hit is in.
- `matched_span_ids` lists the span ids of the hit's events in hit order: one span for `match`;
  one span per step, in step order, for `sequence` (which is also canonical order, since indices
  strictly increase); all cited events in canonical order for `threshold`; the events named above
  for `baseline`.
- `first_timestamp` and `last_timestamp` are the earliest and latest timestamps among those
  events.

## Determinism

The same rules and traces always produce the same detections file, byte for byte.

- Traces are processed in `trace_id` order and events in canonical order.
- Rule files are loaded in sorted file name order. Duplicate rule ids are rejected before
  scanning.
- The sequence search order is fixed, so the chosen assignment is always the same.
- Records are deduplicated on the key `(trace_id, rule_id, rule_version, first_timestamp,
  last_timestamp, matched_span_ids)`, keeping the first, and written sorted by that key.
- Records contain no wall-clock time, no random values and no host-specific data. Output is
  compact JSON with sorted keys and LF line endings.

## Complexity

- Every event is tested against every step's event match once per rule, so building the
  candidate table costs `steps x events` condition evaluations.
- The ancestor table for `derives_from` is built once per trace, on first use, and shared by all
  rules.
- The sequence search runs once per candidate final event. Without requirements or binds that
  fail, the first candidate for each step succeeds and the search is close to linear. In the
  worst case, when requirements keep failing, the backtracking explores up to roughly
  `events^(steps - 1)` assignments per final event, so `events^steps` per trace. This is
  acceptable for traces of tens to hundreds of events and two or three steps. `within_events`
  and `within_seconds` reduce the search space.
- `match`, `threshold` and `baseline` are linear in the number of events.
- `regex` cost depends on the pattern. Python's `re` has no backtracking limit; see
  [SECURITY.md](../SECURITY.md).
