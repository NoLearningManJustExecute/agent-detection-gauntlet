# Rule format

Rules are YAML files in `rules/`. The YAML file is the source of truth for a rule. The model is
in `src/agent_detection_gauntlet/rules/model.py`, and the generated JSON Schema is
`schemas/rule.schema.json`. How the engine evaluates the logic is specified in
[engine.md](engine.md).

## Files and parsing

- One rule per file. Files ending in `.yaml` or `.yml` directly inside the rules directory are
  loaded, in sorted order. Subdirectories are not searched. A directory with no rule files is an
  error.
- The file name (without suffix) must equal the rule `id`, for example `rules/ADG-0001.yaml`.
- YAML is parsed with a safe loader that builds only plain data. Duplicate keys in any mapping
  are rejected. The document must be a mapping.
- The parsed document must be plain JSON data. Values YAML would turn into other types, such as
  an unquoted date, are rejected with a message asking to quote them. `.nan` and `.inf` are
  rejected.
- The result is validated strictly: unknown keys are rejected at every level and no type
  coercion is done. For example `version: 1.0` is a YAML float and fails; write
  `version: "1.0.0"` or `version: 1.0.0`.

## Top-level fields

All fields are required, except `format_version` and `fitted`.

| Field | Type | Constraints |
| --- | --- | --- |
| `format_version` | string | Optional. `1.0` (the default) or `1.1`. Value paths, `first_occurrence` and `baseline` logic need `1.1`. A rule without this field keeps meaning what it always did. |
| `id` | string | `^ADG-[0-9]{4}$`. Unique across the rules directory. |
| `title` | string | Non-empty, not whitespace only. |
| `version` | string | Semantic version: `MAJOR.MINOR.PATCH`, numbers without leading zeros, optional `-prerelease` and `+build`. |
| `status` | string | `experimental`, `test` or `stable`. |
| `tier` | string | `content`, `sequence` or `behavior`. |
| `severity` | string | `low`, `medium`, `high` or `critical`. |
| `description` | string | Non-empty, not whitespace only. What the rule detects. |
| `hypothesis` | string | Non-empty, not whitespace only. Why the rule should work, stated so it can be tested. |
| `mappings` | object | See [Mappings](#mappings). |
| `telemetry` | list of event types | Non-empty, no repeats. Must include every event type the logic uses. May list more. |
| `logic` | object | Exactly one of `match`, `sequence`, `threshold`, `baseline`. See [Logic](#logic). |
| `limitations` | list of strings | Non-empty. Each entry non-empty and not whitespace only. |
| `fixtures` | object | `tp` and `fp`, see [Fixtures](#fixtures). |
| `fitted` | object | Baseline logic only, written by `gauntlet fit-baselines`. See [`baseline`](#baseline). Always the last key in the file. |

Event types are the trace `event_type` values: `session.start`, `user.prompt`, `retrieval`,
`llm.request`, `llm.response`, `tool.call`, `tool.result`, `guardrail.action`, `session.end`.

## Logic

`logic` holds exactly one key.

### Event match

The primitives select events with the same structure:

```yaml
event_types: [<event type>, ...]   # non-empty, no repeats
where: <condition>                 # optional
```

An event matches when its `event_type` is in `event_types` and, if `where` is present, the
condition holds.

### `match`

```yaml
logic:
  match:
    event_types: [tool.call]
    where: <condition>
```

Fires once per matching event.

### `sequence`

```yaml
logic:
  sequence:
    steps:                       # at least 2
      - name: <name>             # unique among steps
        match: <event match>
        bind:                    # optional: name -> field reference
          <name>: <field>
        require:                 # optional
          - op: equals | contains | derives_from
            bound: <name>        # a name bound by an earlier step
            field: <field>       # required for equals and contains, forbidden for derives_from
        first_occurrence: <field>  # optional, format 1.1
    within_events: <int>         # optional, >= 2 and >= number of steps
    within_seconds: <number>     # optional, > 0
```

Constraints:

- `steps` has at least two entries. Step names match `^[a-z][a-z0-9_]{0,63}$` and are unique.
- Bind names match the same pattern. A name may be bound only once across all steps.
- Each `require` entry must name, in `bound`, a value bound by an **earlier** step. A step
  cannot require a value it binds itself.
- `equals` and `contains` need a `field`. `derives_from` takes no `field`: it follows
  `adg.content.ref` from the current event.
- `within_events` is an integer of at least 2 and at least the number of steps.
- `within_seconds` is a number greater than 0.
- With `first_occurrence`, an event holds the step only if no earlier event matching the step's
  `match` has the same value of that field. An event without the field does not hold the step.

### `threshold`

```yaml
logic:
  threshold:
    match: <event match>
    distinct: <field>      # optional
    op: gte | gt | eq
    value: <int>           # >= 1
```

Counts matching events in a trace (or distinct values of `distinct` among them) and compares the
count with `value`. `op` is limited to `gte`, `gt` and `eq`, and `value` is at least 1; the
reason is given in [engine.md](engine.md#threshold).

### `baseline`

Format 1.1. Compares a trace with a statistic fitted on dev benign traces.

```yaml
logic:
  baseline:
    statistic: chain_length | rare_transition
    match: <event match>
    percentile: <int>      # chain_length only, 1 to 100
    key: <field>           # rare_transition only
    max_rate: <number>     # rare_transition only, above 0 and at most 1
fitted:                    # written by the command, never by hand
  command: gauntlet fit-baselines --rules rules --traces datasets/corpus/dev/k24 --labels ...
  population: dev benign
  traces: <int>
  threshold: <int>         # chain_length
  transitions:             # rare_transition: counts of each pair of consecutive keys
    <start> -> read_file: <int>
```

`gauntlet fit-baselines` computes `fitted` and rewrites only that block of the rule file. It
reads the labels to select benign traces, accepts dev traces only, and refuses held-out paths
whatever the environment says. `gauntlet fit-baselines --check` fails when a rule's `fitted` block
is out of date. A baseline rule with no `fitted` block fails validation.

## Conditions

A condition is one of four forms.

```yaml
all: [<condition>, ...]   # non-empty; true when every child is true
any: [<condition>, ...]   # non-empty; true when at least one child is true
not: <condition>          # true when the child is false
field: <field>            # a field comparison
op: <operator>
value: <JSON value>
normalize: [<step>, ...]  # optional
```

A mapping with an `all`, `any` or `not` key is that combinator (checked in that order) and must
not contain other keys. Any other mapping is a field comparison.

### Field references

| Reference | Resolves to |
| --- | --- |
| `event_type` | The event type string. |
| `span_id` | The event's span id. |
| `parent_span_id` | The parent span id (missing for a root event). |
| `attributes.<key>` | The attribute whose full key is `<key>`, for example `attributes.gen_ai.tool.name` or `attributes.adg.source.trust`. |
| `attributes.<key>#<path>` | Format 1.1. A value inside a structured attribute, for example `attributes.gen_ai.tool.call.arguments#to` or `...#items.0.name`. |
| `attributes.<key>#*` | Format 1.1. Every string inside the value, joined with newlines: object keys in sorted order, list items in order. Missing if there are none. |

`<key>` is the whole attribute key as written in the trace, and may hold dots, which is why a path
starts after `#`. A path is dot-separated object keys and list indexes made of letters, digits,
`_` and `-`. A path that reaches nothing is missing. `attributes.gen_ai.tool.call.arguments`
without a path returns the whole arguments object. `trace_id` and `timestamp` cannot be
referenced. `<key>` must be non-empty with no leading or trailing whitespace. A JSON `null` value
counts as missing. Since format 1.1, `#` in a field reference always starts a path, so an attribute
whose key holds `#` cannot be referenced; a format 1.0 rule with such a reference is rejected
rather than silently changing meaning. No trace in this repository has such a key.

### Operators

| `op` | Allowed `value` |
| --- | --- |
| `equals` | Any JSON value except `null`. |
| `in` | A non-empty list with no `null` entries. |
| `contains` | A non-empty string, a number or a boolean. Not a list, object, `null` or empty string. |
| `regex` | A non-empty string that compiles with Python's `re` module and is unchanged by the condition's `normalize` steps. |
| `startswith` | A non-empty string. |
| `exists` | `true` or `false`. `normalize` is not allowed. |

Exact behavior on strings, lists and other types is in [engine.md](engine.md#operators).

### Normalization

`normalize` is a list of steps, without repeats, applied **in the listed order** to string
values:

| Step | Effect |
| --- | --- |
| `casefold` | Unicode case folding. |
| `nfkc` | Unicode NFKC normalization. |
| `collapse_whitespace` | Split on any whitespace and join with single spaces. Also trims both ends. |

Order matters. `[nfkc, casefold]` and `[casefold, nfkc]` can give different results for some
characters. Prefer `[nfkc, casefold]`.

A `regex` pattern must be unchanged by its own `normalize` steps. Under `casefold` this rules out
uppercase letters, including the escapes `\S`, `\W`, `\D` and `\B` (casefold would turn them into
their lowercase opposites). Write `[^\s]` instead of `\S`, and so on.

## Mappings

`mappings` must contain all four keys. Each is a list, may be empty, and must not repeat an ID.

| Key | Framework | ID format |
| --- | --- | --- |
| `atlas` | MITRE ATLAS | `AML.T` + 4 digits, optional `.` + 3 digits (`^AML\.T[0-9]{4}(\.[0-9]{3})?$`) |
| `owasp_llm` | OWASP Top 10 for LLM Applications | `LLM` + 2 digits (`^LLM[0-9]{2}$`) |
| `owasp_agentic` | OWASP Top 10 for Agentic Applications | `ASI` + 2 digits (`^ASI[0-9]{2}$`) |
| `attack` | MITRE ATT&CK | `T` + 4 digits, optional `.` + 3 digits (`^T[0-9]{4}(\.[0-9]{3})?$`) |

`attack` is used only when the agent performs a host action.

### Catalog

Every mapping ID must appear in the catalog shipped with the package:
`src/agent_detection_gauntlet/catalog/atlas.yaml`, `owasp_llm.yaml`, `owasp_agentic.yaml` and
`attack.yaml`. Each file has an `entries` list. Each entry has:

| Field | Rules |
| --- | --- |
| `id` | Must match the family's ID format. Unique within the file. |
| `name` | Non-empty. |
| `url` | Starts with `https://`. |
| `version` | Non-empty string. The framework version the entry was taken from. |
| `verified` | Boolean, default `false`. `true` only after the entry is checked against the primary source. |

A malformed catalog file stops validation with an error.

During validation:

- A mapping ID **not in the catalog** is an **error**.
- A mapping ID in the catalog with `verified: false` is a **warning**. Warnings do not fail
  validation.

All current catalog entries are unverified. Verification against the primary sources is
scheduled for Phase 7, so every rule currently produces one warning per mapping ID.

`gauntlet rules-doc` renders [detections.md](detections.md) from the rule files, and CI fails when
the two disagree.

## Fixtures

```yaml
fixtures:
  tp: [<trace id>, ...]   # the rule must fire on each of these
  fp: [<trace id>, ...]   # the rule must not fire on any of these
```

Both lists are required, non-empty, use the trace identifier pattern, and do not repeat an ID.
A trace may not be in both lists. The traces are looked up in the fixture trace set (default
`datasets/fixtures/traces` and `datasets/corpus/dev/k24`, overridable with `--fixtures`). Fixtures
are never held-out: a held-out path given to `--fixtures` is refused, whatever the environment
says.

## Validator checks

`gauntlet validate-rules <directory>` runs these checks. `scan` and `metrics` run the same
checks first and refuse to continue if any error is found.

1. The rules directory exists and contains at least one `.yaml` or `.yml` file.
2. Each file is readable as UTF-8, parses as YAML without duplicate keys, is a mapping, and
   holds only plain JSON data.
3. Each file validates against the rule model: every field constraint above, plus these
   cross-field checks:
   - features of format 1.1 need `format_version: "1.1"`;
   - `fitted` is present only on baseline logic and fits its statistic;
   - every event type used in `logic` is listed in `telemetry`;
   - `fixtures.tp` and `fixtures.fp` do not overlap;
   - sequence step names are unique, bind names are bound once, every `require` names a value
     bound by an earlier step, `within_events` is at least the number of steps;
   - `derives_from` has no `field`, `equals` and `contains` have one;
   - each field condition's `value` fits its operator and each `regex` compiles.
4. The file name matches the rule id.
5. Rule ids are unique across the directory.
6. A baseline rule has been fitted.
7. Every mapping ID is in the catalog (error otherwise), and is verified (warning otherwise).
8. The fixture traces load cleanly under the full trace rules in [schema.md](schema.md).
9. Every `tp` and `fp` trace id exists among the fixture traces.
10. The rule produces at least one hit on every `tp` trace and no hit on any `fp` trace.

Problems are printed to standard error as `error: <path>: <message>` or
`warning: <path>: <message>`. The command exits with status 1 if there is at least one error.

## Worked example: ADG-0001

`rules/ADG-0001.yaml`:

```yaml
id: ADG-0001
title: Untrusted retrieved content flows into an external send tool call
version: 0.1.1
status: experimental
tier: sequence
severity: high
description: >-
  Fires when a retrieval marked untrusted is followed, in the same trace, by a tool call to an
  external-send sink whose content derives from that retrieval. Derivation follows the
  adg.content.ref provenance chain transitively, so the retrieved text can pass through model
  requests and responses before it reaches the tool arguments.
hypothesis: >-
  Indirect prompt injection that causes harm needs two things in the same session: attacker
  controlled text entering the context through retrieval, and the agent acting on it through a
  tool that reaches outside the trust boundary. The rule keys on that provenance path rather than
  on the wording of the injected text, so it should hold up under paraphrase, translation,
  encoding, and other payload mutations that leave the data flow unchanged.
mappings:
  atlas:
    - AML.T0051.001
  owasp_llm:
    - LLM01
  owasp_agentic:
    - ASI01
  attack: []
telemetry:
  - retrieval
  - tool.call
logic:
  sequence:
    steps:
      - name: untrusted_retrieval
        match:
          event_types:
            - retrieval
          where:
            field: attributes.adg.source.trust
            op: equals
            value: untrusted
        bind:
          retrieved_span: span_id
      - name: external_send
        match:
          event_types:
            - tool.call
          where:
            field: attributes.gen_ai.tool.name
            op: in
            value:
              - send_email
              - http_post
              - post_message
              - upload_file
            normalize:
              - nfkc
              - casefold
        require:
          - op: derives_from
            bound: retrieved_span
limitations:
  - >-
    Depends on instrumentation recording adg.content.ref. A missing link hides the flow and the
    rule misses. Coarse provenance that marks every output as derived from all prior context
    makes the rule fire on any send after an untrusted retrieval.
  - >-
    The sink list is a fixed set of tool names. Renamed tools, new send tools, and indirect
    channels such as writing to a shared file that another process sends are not covered.
  - >-
    The rule cannot judge intent. A user who deliberately forwards untrusted content, such as a
    public article, produces the same data flow and the rule fires.
  - >-
    The rule fires whether or not the send succeeded or was blocked downstream by a guardrail.
fixtures:
  tp:
    - syn-0001
    # plus a dev trace
  fp:
    - syn-0002
    - syn-0003
    # plus dev traces, including hard negatives
```

How it reads:

- **Step `untrusted_retrieval`** selects `retrieval` events whose `adg.source.trust` attribute
  equals `untrusted`, and binds that event's `span_id` to the name `retrieved_span`.
- **Step `external_send`** selects `tool.call` events whose `gen_ai.tool.name`, after NFKC
  normalization and then case folding, is one of four sink names. The values in the list are
  normalized the same way before comparison.
- **The `derives_from` requirement** holds only if the tool call's content derives, through one
  or more `adg.content.ref` links, from the bound retrieval span. In fixture `syn-0001` the chain
  is tool call `s06` to response `s05` to request `s04` to retrieval `s03`.
- **`telemetry`** lists both event types the steps use. Omitting either would fail validation.
- **Fixtures:** `syn-0001` has the full chain and must fire. `syn-0002` has the same flow but a
  trusted retrieval. `syn-0003` has an untrusted retrieval and a send, but the send does not
  derive from the retrieval. Neither may fire. The rule also names dev traces, listed in the file.
- **Mappings** reference one ID per framework family that applies. No host action occurs, so
  `attack` is empty. All three IDs are currently unverified catalog entries, so validation
  prints three warnings.
