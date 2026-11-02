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
  trace with no time bound, where a temporal correlation needs a timespan and a grouping field.
- **Baseline rules** do not convert. They need fitted values and per-trace state.
- **Threshold logic** does not convert. No rule uses it today, and it counts over a whole trace with
  no time bound.
- **Single-event rules** convert when each of their conditions holds in the target:
  - A regex using `\b`, `\w`, `\d` or `\s` and their opposites does not convert. Python applies them
    to Unicode text and the targets do not, so the same text could decide differently.
  - ES|QL `RLIKE` takes Lucene syntax and is always anchored. The search is kept by wrapping the
    pattern, and a pattern using `^ $ . \ < > @ # & ~ "` does not convert.
  - KQL cannot tell a missing string field from an empty one, so field existence does not convert.
  - Negation does not convert, because the targets treat a missing field differently.

## What the field mappings assume

No SIEM schema was tested. Query languages cannot apply NFKC or collapse whitespace at search time,
and cannot join every string inside a JSON value. So a converted rule names a field that an ingest
pipeline must compute exactly as [rule-format.md](rule-format.md) defines it, such as
`adg.content.text__nfkc_casefold_collapse_whitespace` or
`gen_ai.tool.call.arguments.__all_strings`. The regex itself is the native one, unchanged. A
deployment without those fields will not match what the native rule matches.

Sigma output is checked by a round-trip test that parses each file with a pinned Sigma library and
compares the regex with the native rule. That shows the file is valid Sigma. It does not show that
any backend runs it correctly, and KQL, SPL and ES|QL output has no such check.
