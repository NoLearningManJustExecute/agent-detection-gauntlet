"""Render the results dashboard: one static HTML file, no network, no script, no timestamp."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from html import escape
from typing import Any

PAYLOAD_ORDER = (
    "homoglyph",
    "zero_width",
    "fullwidth",
    "split_chunks",
    "base64_bare",
    "base64_decode",
    "all_payload_mutations",
)
TIERS = ("content", "sequence", "behavior")
POPULATION_TITLES = {
    "clean_heldout": "Clean held-out attacks",
    "payload_mutations": "Payload mutations",
    "attack_variants": "Attack variants (small-N)",
}
REASONS = {
    "recall_too_low": "recall too low",
    "no_successful_attacks": "no successful attacks",
    "not_attempted": "no attacks run",
}
STYLE = """
:root {
  --bg: #f6f7fb; --panel: #ffffff; --line: #d8dee8; --fg: #1a2230; --muted: #566273;
  --accent: #6d3fe0; --down: #c4314b; --flat: #1f8a4c;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #161e2b; --panel: #1e2735; --line: #34414f; --fg: #e8eef5; --muted: #a9b6c4;
    --accent: #a78bfa; --down: #f7768e; --flat: #5ad46a;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 24px 16px 48px; background: var(--bg); color: var(--fg);
  font: 15px/1.5 "Segoe UI", Helvetica, Arial, sans-serif;
}
main { max-width: 1080px; margin: 0 auto; }
h1 { font-size: 26px; margin: 0 0 8px; }
h2 { font-size: 19px; margin: 32px 0 8px; color: var(--accent); }
p { margin: 8px 0; }
.note { color: var(--muted); font-size: 13px; }
.wrap { overflow-x: auto; background: var(--panel); border: 1px solid var(--line);
  border-radius: 8px; margin: 12px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { padding: 7px 10px; border-bottom: 1px solid var(--line); text-align: left;
  vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
td.num, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
tr:last-child td { border-bottom: 0; }
.bar-row { display: grid; grid-template-columns: 90px 1fr 170px; gap: 10px; align-items: center;
  padding: 6px 12px; }
.track { height: 14px; background: var(--line); border-radius: 7px; overflow: hidden; }
.fill { height: 100%; background: var(--down); }
.fill.flat { background: var(--flat); }
.covered { color: var(--flat); font-weight: 600; }
ul.note .mono { overflow-wrap: anywhere; }
a { color: var(--accent); }
@media (max-width: 560px) { .bar-row { grid-template-columns: 70px 1fr 56px; } }
""".strip()


def rate(cell: Mapping[str, Any] | None) -> str:
    if cell is None:
        return "null"
    fraction = f"{cell['numerator']}/{cell['denominator']}"
    if cell["value"] is None:
        return f"null ({fraction})"
    interval = cell.get("ci95")
    text = f"{fraction} = {cell['value']:.3f}"
    return f"{text} [{interval['lower']:.3f}, {interval['upper']:.3f}]" if interval else text


def short_rate(cell: Mapping[str, Any]) -> str:
    fraction = f"{cell['numerator']}/{cell['denominator']}"
    if cell["value"] is None:
        return f"null ({fraction})"
    return f"{fraction} = {cell['value']:.3f}"


def change(paired: Mapping[str, Any]) -> str:
    if paired["delta"] is None:
        return "null"
    interval = paired["ci95"]
    return f"{paired['delta']:+.3f} [{interval['lower']:+.3f}, {interval['upper']:+.3f}]"


def _table(headers: Iterable[str], rows: Iterable[Iterable[str]]) -> str:
    head = "".join(f"<th>{escape(cell)}</th>" for cell in headers)
    body = "".join(
        "<tr>" + "".join(f'<td class="num">{escape(cell)}</td>' for cell in row) + "</tr>"
        for row in rows
    )
    table = f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
    return f'<div class="wrap">{table}</div>'


def _section(evasion: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    section = next(item for item in evasion["sections"] if item["name"] == name)
    arm: Mapping[str, Any] = next(a for a in section["arms"] if a["guardrails"] == "off")
    return arm


def _tier(arm: Mapping[str, Any], tier: str) -> Mapping[str, Any]:
    cell: Mapping[str, Any] = next(c for c in arm["table"]["per_tier"] if c["name"] == tier)
    return cell


def _bars(evasion: Mapping[str, Any]) -> str:
    pooled = _section(evasion, "all_payload_mutations")
    rows = []
    for tier in TIERS:
        paired = _tier(pooled, tier)["paired"]
        width = min(100.0, abs(paired["delta"]) * 100)
        # Red only when the interval excludes zero.
        kind = "fill" if paired["ci95"]["upper"] < 0 else "fill flat"
        rows.append(
            f'<div class="bar-row"><span>{tier}</span><div class="track"><div class="{kind}" '
            f'style="width:{width:.1f}%"></div></div><span class="mono">{paired["delta"]:+.3f}'
            "</span></div>"
        )
    return f'<div class="wrap">{"".join(rows)}</div>'


def _evasion_table(evasion: Mapping[str, Any]) -> str:
    rows = []
    for name in PAYLOAD_ORDER:
        arm = _section(evasion, name)
        row = [name, short_rate(arm["attack_success"]["runs"])]
        cells = [_tier(arm, tier) for tier in TIERS]
        cells.append(arm["table"]["all_tiers"])
        for cell in cells:
            paired = cell["paired"]
            row.append(f"{short_rate(paired['mutated'])}; base {short_rate(paired['baseline'])}")
            row[-1] += f"; {change(paired)}"
        rows.append(row)
    headers = ["Mutation", "Attack success, runs", "Content", "Sequence", "Behavior", "All tiers"]
    return _table(headers, rows)


def _baseline_tables(baseline: Mapping[str, Any]) -> str:
    pooled = baseline["pooled"]
    tiers = [
        [cell["tier"], rate(cell["rates"]["recall"]), rate(cell["rates"]["fpr"])]
        for cell in pooled["per_tier"]
    ]
    combined = pooled["all_tiers"]["rates"]
    tiers.append(["all tiers", rate(combined["recall"]), rate(combined["fpr"])])
    rules = [
        [cell["rule_id"], cell["tier"], rate(cell["rates"]["recall"]), rate(cell["rates"]["fpr"])]
        for cell in pooled["per_rule"]
    ]
    return _table(["Tier", "Recall", "FPR"], tiers) + _table(
        ["Rule", "Tier", "Recall", "FPR"], rules
    )


def _verdict(verdict: Mapping[str, Any]) -> str:
    best = verdict["best_rule"]
    detail = f"{best['rule_id']} {short_rate(best['recall'])}" if best else "no rule"
    if verdict["covered"]:
        return f"covered: {detail}"
    return f"not covered, {REASONS.get(verdict['reason'], verdict['reason'])}: {detail}"


def _coverage_table(coverage: Mapping[str, Any]) -> str:
    rows = []
    for technique in coverage["techniques"]:
        by_population = {item["population"]: item for item in technique["verdicts"]}
        rows.append(
            [
                technique["id"],
                technique["name"],
                "yes" if technique["verified"] else "no",
                *[_verdict(by_population[name]) for name in POPULATION_TITLES],
            ]
        )
    return _table(["Technique", "Name", "ID verified", *POPULATION_TITLES.values()], rows)


def render_dashboard(
    sources: Mapping[str, bytes], documents: Mapping[str, Mapping[str, Any]]
) -> str:
    """Sources are the raw JSON bytes by repo-relative path, for the hashes in the footer."""
    baseline = documents["results/baseline/metrics.json"]
    evasion = documents["results/evasion/evasion.json"]
    coverage = documents["results/coverage/coverage.json"]
    thresholds = coverage["thresholds"]
    hashes = "".join(
        f"<li><span class='mono'>{escape(path)}</span> sha256 "
        f"<span class='mono'>{hashlib.sha256(raw).hexdigest()}</span></li>"
        for path, raw in sources.items()
    )
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>Gauntlet results</title>",
            f"<style>\n{STYLE}\n</style></head><body><main>",
            "<h1>Results dashboard</h1>",
            "<p><a href='index.html'>Back to the project page</a></p>",
            "<p>Generated by <span class='mono'>gauntlet publish build</span> from the committed "
            "results JSON. Every rate shows its numerator and denominator. Null means the "
            "denominator is zero. Brackets are 95% intervals: Wilson on a rate, a percentile "
            "bootstrap over variant groups on a change.</p>",
            "<h2>Recall change under payload mutation, pooled, guardrails off</h2>",
            "<p class='note'>Mutated recall minus the recall of the same base scenarios. "
            "Read with the table below: recall here is over attacks that still succeeded.</p>",
            _bars(evasion),
            "<h2>Each mutation, by tier</h2>",
            "<p class='note'>Guardrails off. The base64 rows are null because no attack "
            "succeeded: base64 broke the attack, it did not evade a rule.</p>",
            _evasion_table(evasion),
            "<h2>Clean held-out attacks</h2>",
            f"<p class='note'>{baseline['population']['malicious_succeeded']} succeeded attack "
            f"traces, {baseline['population']['benign']} benign traces, "
            "both guardrail arms.</p>",
            _baseline_tables(baseline),
            "<h2>Per-technique detail</h2>",
            f"<p class='note'>Registered bar for one rule: recall at or above "
            f"{thresholds['min_heldout_recall']} and FPR at or below {thresholds['max_fpr']}, "
            "on point estimates. It tests rules alone, not the combined system. The attack "
            "variants column rests on few traces. OWASP LLM IDs use the 2025 numbers. AML.T0057 "
            "is absent from ATLAS 2026.10, so it stays unverified. See docs/mappings.md.</p>",
            _coverage_table(coverage),
            "<h2>Inputs</h2>",
            f"<ul class='note'>{hashes}</ul>",
            "</main></body></html>",
            "",
        ]
    )
