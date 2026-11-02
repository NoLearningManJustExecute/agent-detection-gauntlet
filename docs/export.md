# Exporting rules

The YAML files in `rules/` are the source of truth. Sigma, KQL, SPL and ES|QL files are build
artifacts, labeled "converted, not live SIEM validated". They are never committed and never edited
by hand.

```sh
gauntlet export --format sigma|kql|spl|esql|all --out dist/rules/
gauntlet lint-rules rules
```

`dist/rules/<format>/` holds one file per converted rule. `dist/rules/NOT_CONVERTED.md` lists every
rule and format with nothing emitted, and why. `dist/rules/FIELD_MAPPINGS.md` lists the fields the
queries assume. CI builds them on every change; the release workflow bundles them on a tag.

## What converts

A rule converts only if the target can state the same test on the same data. No approximation is
emitted, even a close one, because a query that looks equivalent and is not is worse than none.

- **Sequence rules** do not convert. Those with `bind` or `require` follow content references across
  events, those with `first_occurrence` need per-trace memory, and the rest are ordered within a
  trace with no time bound. A Sigma temporal correlation needs a timespan. KQL has forms that might
  state some of these, but none has been checked to search steps as the engine does.
- **Baseline rules** do not convert. Fitted rules stay native by policy.
- **Threshold logic** does not convert. No rule uses it today. It counts over a whole trace, and a
  Sigma correlation needs a timespan.
- **Single-event rules** convert when each of their conditions holds in the target:
  - A regex passes an allowlist: printable ASCII literals, a few escaped punctuation marks, ASCII
    character classes, greedy repeats, groups, alternation and a leading `^`. Anything else is
    refused, including a form no rule uses today.
  - That excludes `\b`, `\w`, `\d`, `\s` and their opposites. Python applies them to Unicode text
    and each target defines them its own way, so the same text could decide differently.
  - ES|QL `RLIKE` takes Lucene syntax and is always anchored. The search is kept by wrapping the
    pattern in `.*`, so this one regex is not the native text unchanged. A pattern using
    `^ < > @ # & ~ "` does not convert, and neither does a field without collapsed whitespace,
    because how that dot treats a newline is unchecked.
  - KQL cannot tell a missing string field from an empty one, so field existence does not convert.
  - Negation does not convert, because the targets treat a missing field differently.
  - Equality with empty text, or with a value its own normalization would change, does not convert.

## What the field mappings assume

No SIEM schema was tested and no such pipeline exists. Query languages cannot apply NFKC or collapse
whitespace at search time, and cannot join every string inside a JSON value. So a converted rule
names a field that an ingest pipeline must compute exactly as [rule-format.md](rule-format.md)
defines it, such as `adg.content.text__nfkc_casefold_collapse_whitespace` or
`gen_ai.tool.call.arguments__all_strings`. For those rules, converted means the regex moved to the
query and the normalization moved to a pipeline nobody has built. Each generated file names its
required fields, and `FIELD_MAPPINGS.md` says what each must hold, including that a non-string value
leaves a regex field absent.

Sigma regexes assume an unanchored search in PCRE style, and the Sigma files say so. A backend that
anchors them or uses Lucene syntax is not faithful. No Sigma backend has been run.

## What is checked

A round-trip test parses each generated Sigma file with a pinned Sigma library, forces its condition
to parse, and compares every regex with the native rule. Another test pins the exact condition and
filter text of every generated file against the native logic. That shows the files say what was
meant and that the Sigma is valid. It does not show that any SIEM or backend runs them correctly.
