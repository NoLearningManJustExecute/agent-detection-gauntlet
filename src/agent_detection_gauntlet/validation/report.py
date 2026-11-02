"""Render docs/results-baseline.md from the results JSON. Every number comes from that file."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from agent_detection_gauntlet.metrics.report import Confusion, Rate, RuleMetrics, TierMetrics
from agent_detection_gauntlet.validation.model import (
    BaselineResults,
    CombinedMetrics,
    FiredCell,
    PairedDifference,
    Preregistration,
    RecallCell,
    RecallTable,
    Section,
)
from agent_detection_gauntlet.validation.score import ANY_RELATIVE


def _table(header: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return "\n".join(lines)


def _rate(rate: Rate) -> str:
    fraction = f"{rate.numerator}/{rate.denominator}"
    if rate.value is None:
        return f"null ({fraction})"
    if rate.ci95 is None:
        return f"{fraction} = {rate.value:.3f}"
    return f"{fraction} = {rate.value:.3f} [{rate.ci95.lower:.3f}, {rate.ci95.upper:.3f}]"


def _signed(value: float | None) -> str:
    return "null" if value is None else f"{value:+.3f}"


def _counts(c: Confusion) -> str:
    return f"{c.tp} / {c.fp} / {c.tn} / {c.fn}"


def _scored_cells(item: RuleMetrics | TierMetrics | CombinedMetrics) -> list[object]:
    rates = item.rates
    return [
        _counts(item.confusion),
        _rate(rates.recall),
        _rate(rates.fpr),
        _rate(rates.precision),
        _rate(rates.f1),
        f"{item.attack_failed.detected}/{item.attack_failed.count}",
    ]


def _pooled_rows(section: Section) -> list[list[object]]:
    rows: list[list[object]] = [[t.tier.value, *_scored_cells(t)] for t in section.per_tier]
    rows.append(["all tiers", *_scored_cells(section.all_tiers)])
    return rows


def _rule_rows(section: Section) -> list[list[object]]:
    return [[r.rule_id, r.tier.value, *_scored_cells(r)] for r in section.per_rule]


POOLED_HEADER = ["Tier", "TP / FP / TN / FN", "Recall", "FPR", "Precision", "F1", "Failed fired"]
RULE_HEADER = ["Rule", "Tier", *POOLED_HEADER[1:]]


def _cells(table: RecallTable) -> list[RecallCell]:
    return [*table.per_tier, table.all_tiers]


def _class_rows(results: BaselineResults) -> list[list[object]]:
    rows: list[list[object]] = []
    for item in results.per_class:
        flags = [
            name
            for name, on in (("small-N", item.small_n), ("underpowered", item.below_floor))
            if on
        ]
        rows.append(
            [
                item.attack_class,
                item.succeeded_traces,
                item.succeeded_groups,
                *(_rate(cell.recall) for cell in _cells(item.table)),
                ", ".join(flags) or "none",
            ]
        )
    return rows


def _class_rule_rows(results: BaselineResults) -> list[list[object]]:
    rows: list[list[object]] = []
    for item in results.per_class:
        fired = [cell for cell in item.table.per_rule if cell.recall.numerator]
        summary = ", ".join(
            f"{cell.name} {cell.recall.numerator}/{cell.recall.denominator}" for cell in fired
        )
        rows.append([item.attack_class, item.succeeded_traces, summary or "none"])
    return rows


def _paired_row(a: str, b: str, measure: str, paired: PairedDifference) -> list[object]:
    interval = (
        "null" if paired.ci95 is None else f"[{paired.ci95.lower:+.3f}, {paired.ci95.upper:+.3f}]"
    )
    return [
        f"{a} minus {b}",
        measure,
        _rate(paired.a),
        _rate(paired.b),
        _signed(paired.difference),
        interval,
        f"{paired.a_only} / {paired.b_only} / {paired.both} / {paired.neither}",
        paired.groups,
    ]


def _fired_rows(cells: Iterable[FiredCell]) -> list[list[object]]:
    return [[cell.name, _rate(cell.fired)] for cell in cells]


def _provenance_rows(results: BaselineResults) -> list[list[object]]:
    rows: list[list[object]] = []
    for run in results.provenance_sensitivity:
        cells: list[tuple[str, RuleMetrics | TierMetrics]] = [("sequence tier", run.tier)]
        cells += [(rule.rule_id, rule) for rule in run.per_rule]
        rows += [
            [run.k, name, _counts(c.confusion), _rate(c.rates.recall), _rate(c.rates.fpr)]
            for name, c in cells
        ]
    return rows


def _relative_note(results: BaselineResults) -> list[str]:
    total = results.population.malicious_succeeded_groups
    return [
        f"{item.set_aside_groups} of {total} succeeded groups have a parent, sibling or seeded "
        "child in the other split, so higher recall in a row here is not evidence against "
        "inflation from those relatives.\n"
        for item in results.set_asides
        if item.name == ANY_RELATIVE
    ]


def _summary(results: BaselineResults) -> list[str]:
    population = results.population
    all_tiers = results.pooled.all_tiers.rates
    tiers = results.pooled.per_tier
    top = max((tier.rates.recall.numerator for tier in tiers), default=0)
    leaders = [tier.tier.value for tier in tiers if tier.rates.recall.numerator == top]
    recall_lines = [
        f"  - {tier.tier.value}: recall {_rate(tier.rates.recall)}, FPR {_rate(tier.rates.fpr)}"
        for tier in tiers
    ]
    return [
        f"**Measured.** {len(results.rules)} frozen rules on the {results.split.value} split: "
        f"{population.malicious_succeeded} traces where an attack succeeded "
        f"({population.malicious_succeeded_groups} variant groups), {population.benign} benign "
        f"traces ({population.benign_groups} groups), and {population.attack_failed} traces where "
        "an attack was tried and failed, which are in neither denominator.",
        "",
        "Pooled, all tiers combined: recall "
        f"{_rate(all_tiers.recall)}, FPR {_rate(all_tiers.fpr)}, F1 {_rate(all_tiers.f1)}.",
        "",
        *recall_lines,
        "",
        f"Highest recall point estimate: {', '.join(leaders)}. Read this with the paired "
        "comparison below, not on its own.",
        "",
        "**Not measured.** Evasion (Phase 4). Other models or agent frameworks. Real alert volume, "
        "since precision here depends on the mix of traces in this corpus. Live SIEM behavior. "
        "Whether these rules would fire the same way on traces from outside the source lab.",
    ]


LIMITATIONS = [
    "**Single model.** One local model, llama3.1:8b. Results may not transfer.",
    "**Single-author corpus.** One author wrote the attacks, the benign tasks and the rules. The "
    "split guards against fitting to specific traces, not against a shared view of what attacks "
    "look like.",
    "**Variant-group splits.** Whole groups go to one split, but a group's parent, siblings or "
    "seeded children can sit across the split, and they share the attack's mechanism and target. "
    "The set-aside table states how many held-out groups this touches. It cannot measure what "
    "that does to recall, because rules were written against the dev relatives of those groups.",
    "**Overlap-based provenance.** Content references come from verbatim overlap of at least K "
    "characters. Paraphrased data flow is missed. The sensitivity table shows the K dependence.",
    "**Temperature-0 determinism.** Runs of one input mostly repeat, and repeats are removed, so "
    "more runs would not add independent evidence; a few inputs do produce more than one distinct "
    "trace. Distinct inputs are the unit of independence. Wilson intervals treat traces as "
    "independent and run narrower than the group structure justifies; the group count sits beside "
    "them.",
    "**Small samples.** Few groups per class, and few successes with guardrails on. Per-class and "
    "guardrails-on figures are wide and are read as such.",
    "**Precision depends on the corpus mix.** The share of attacks here is a property of the "
    "corpus, not of any deployment.",
    "**Framework mappings** were checked in Phase 7. See [mappings.md](mappings.md).",
]


def render_results(results: BaselineResults, plan: Preregistration) -> str:
    w: list[str] = []
    w += [
        "# Baseline validation results",
        "",
        "Generated by `gauntlet validation report` from `" + plan.results_path + "`. Do not edit "
        "by hand; CI fails when this file and the JSON disagree. Every number below is in the "
        "JSON. Method: [preregistration.md](preregistration.md).",
        "",
        "Rate cells read numerator/denominator = value [Wilson 95% interval]. F1 has no interval. "
        "Null means the denominator is zero. Failed fired counts traces from the `attack_failed` "
        "bucket that a rule or tier fired on; they are in no rate.",
        "",
        "## Summary",
        "",
        *_summary(results),
        "",
        "## Pooled across attack classes (primary)",
        "",
        "Per tier. A tier fires if any rule in it fires.",
        "",
        _table(POOLED_HEADER, _pooled_rows(results.pooled)),
        "",
        "Per rule.",
        "",
        _table(RULE_HEADER, _rule_rows(results.pooled)),
        "",
        "## Paired tier comparison",
        "",
        "Rate of a minus rate of b on the same traces. The interval is a percentile bootstrap over "
        "variant groups. Counts read fired by a only / b only / both / neither, in traces.",
        "",
        _table(
            [
                "Comparison",
                "Measure",
                "a",
                "b",
                "Difference",
                "Group 95% interval",
                "Counts",
                "Groups",
            ],
            [
                row
                for item in results.tier_comparison
                for row in (
                    _paired_row(item.a.value, item.b.value, "recall", item.recall),
                    _paired_row(item.a.value, item.b.value, "FPR", item.fpr),
                )
            ],
        ),
        "",
    ]
    for item in results.tier_comparison[:1]:
        if item.recall.ci95 is not None:
            w += [
                f"Resamples: {item.recall.ci95.resamples}. Seed: {item.recall.ci95.seed}.",
                "",
            ]
    w += ["## Guardrails on and off", ""]
    for arm in results.by_guardrails:
        p = arm.population
        w += [
            f"### Guardrails {arm.guardrails.value}",
            "",
            f"{p.malicious_succeeded} succeeded traces ({p.malicious_succeeded_groups} groups), "
            f"{p.benign} benign ({p.benign_groups} groups), {p.attack_failed} attack_failed.",
            "",
            _table(POOLED_HEADER, _pooled_rows(arm.section)),
            "",
            _table(RULE_HEADER, _rule_rows(arm.section)),
            "",
        ]
    tier_names = (
        [cell.name for cell in _cells(results.per_class[0].table)] if results.per_class else []
    )
    w += [
        "## Per class (secondary)",
        "",
        "Recall only: benign traces have no class. Small-N flags a recall denominator below "
        f"{plan.small_n_below}. Underpowered flags a class below the corpus group floor, which "
        "feeds pooled metrics only.",
        "",
        _table(
            ["Class", "Succeeded traces", "Succeeded groups", *tier_names, "Flags"],
            _class_rows(results),
        ),
        "",
        "Rules that fired on a class, with counts over its succeeded traces. Every rule and every "
        "interval is in the JSON.",
        "",
        _table(["Class", "Succeeded traces", "Rules with hits"], _class_rule_rows(results)),
        "",
        "## attack_failed bucket",
        "",
        f"{results.attack_failed.total} traces, in no rate.",
        "",
        _table(
            ["Class", "Guardrails off", "Guardrails on", "Total", "Groups"],
            [
                [c.attack_class, c.guardrails_off, c.guardrails_on, c.total, c.groups]
                for c in results.attack_failed.by_class
            ],
        ),
        "",
        "## Provenance sensitivity",
        "",
        "The sequence tier and its rules on each content-reference export.",
        "",
        _table(
            ["K", "Name", "TP / FP / TN / FN", "Recall", "FPR"],
            _provenance_rows(results),
        ),
        "",
        "## Set-aside sensitivity",
        "",
        "Recall with some succeeded traces removed. Null means nothing was left to score. Groups "
        "touched counts groups that lost at least one trace; a group can lose some traces and keep "
        "others. A row marked not registered was added after scoring and is not part of the "
        "registered analysis.",
        "",
        *_relative_note(results),
        _table(
            [
                "Set aside",
                "Traces removed",
                "Groups touched",
                "Groups with traces left",
                *tier_names,
            ],
            [
                [
                    item.name if item.registered else f"{item.name} (not registered)",
                    item.set_aside_traces,
                    item.set_aside_groups,
                    item.remaining_groups,
                    *(_rate(cell.recall) for cell in _cells(item.table)),
                ]
                for item in results.set_asides
            ],
        ),
        "",
        "## Ineffective classes",
        "",
        f"{', '.join(results.ineffective.classes)} never succeeded at baseline and are out of "
        f"every recall denominator. In this split they have {results.ineffective.traces} traces "
        f"and {results.ineffective.succeeded_traces} successes. They carry a malicious label, so "
        "a rule firing on one is not a false positive under the formula; this table is where it "
        "would show. Each class has one group and those groups are all in the dev split, so null "
        "here means no traces, not that no rule fired on them anywhere.",
        "",
        _table(
            ["Name", "Fired"],
            _fired_rows(
                [
                    results.ineffective.all_tiers,
                    *results.ineffective.per_tier,
                    *results.ineffective.per_rule,
                ]
            ),
        ),
        "",
        "## Limitations",
        "",
        *(f"- {item}" for item in LIMITATIONS),
        "",
    ]
    return "\n".join(w)
