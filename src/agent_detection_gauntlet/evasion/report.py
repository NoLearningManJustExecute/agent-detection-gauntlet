"""Render docs/results-evasion.md from the results JSON. Every number comes from that file."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from agent_detection_gauntlet.evasion.model import (
    ArmSection,
    EvasionPlan,
    EvasionResults,
    EvasionRow,
    EvasionSection,
    PairedDelta,
)
from agent_detection_gauntlet.metrics.report import Rate
from agent_detection_gauntlet.schema.labels import Guardrails
from agent_detection_gauntlet.validation.score import ALL_TIERS


def _table(header: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return "\n".join(lines)


def _rate(rate: Rate) -> str:
    fraction = f"{rate.numerator}/{rate.denominator}"
    if rate.value is None:
        return f"null ({fraction})"
    assert rate.ci95 is not None
    return f"{fraction} = {rate.value:.3f} [{rate.ci95.lower:.3f}, {rate.ci95.upper:.3f}]"


def _short(rate: Rate) -> str:
    fraction = f"{rate.numerator}/{rate.denominator}"
    return f"null ({fraction})" if rate.value is None else f"{fraction} = {rate.value:.3f}"


def _signed(value: float | None) -> str:
    return "null" if value is None else f"{value:+.3f}"


def _bounds(delta: PairedDelta) -> str:
    if delta.ci95 is None:
        return "null"
    return f"[{delta.ci95.lower:+.3f}, {delta.ci95.upper:+.3f}]"


def _delta_cell(row: EvasionRow) -> str:
    """Recall under the variation, its paired baseline, and the change with its group interval."""
    paired = row.paired
    return (
        f"{_short(paired.mutated)}; base {_short(paired.baseline)}; "
        f"change {_signed(paired.delta)} {_bounds(paired)}"
    )


def _arm(section: EvasionSection, guardrails: Guardrails) -> ArmSection:
    return next(arm for arm in section.arms if arm.guardrails is guardrails)


def _success_rows(sections: Sequence[EvasionSection], guardrails: Guardrails) -> list[list[object]]:
    rows: list[list[object]] = []
    for section in sections:
        arm = _arm(section, guardrails)
        success = arm.attack_success
        rows.append(
            [
                section.name,
                _rate(success.runs),
                _short(success.inputs),
                _short(success.paired.baseline),
                _signed(success.paired.delta),
                _bounds(success.paired),
                arm.population.succeeded_traces,
                arm.population.succeeded_groups,
                arm.population.attack_failed_traces,
            ]
        )
    return rows


SUCCESS_HEADER = [
    "Mutation",
    "Attack success, runs",
    "Inputs with a success",
    "Base, runs",
    "Change",
    "Group 95% interval",
    "Succeeded traces",
    "Groups",
    "attack_failed traces",
]


def _tier_row(section: EvasionSection, guardrails: Guardrails) -> list[object]:
    arm = _arm(section, guardrails)
    return [
        section.name,
        *[_delta_cell(row) for row in arm.table.per_tier],
        _delta_cell(arm.table.all_tiers),
    ]


def _rule_rows(section: EvasionSection, guardrails: Guardrails) -> list[list[object]]:
    arm = _arm(section, guardrails)
    rows: list[list[object]] = []
    for row in arm.table.per_rule:
        rows.append(
            [
                row.name,
                _rate(row.recall),
                _short(row.paired.baseline),
                _signed(row.paired.delta),
                _bounds(row.paired),
                f"{row.attack_failed.detected}/{row.attack_failed.count}",
            ]
        )
    return rows


def _summary(results: EvasionResults, sections: Sequence[EvasionSection]) -> list[str]:
    lines = [
        f"**Measured.** {len(results.rules)} frozen rules on {results.raw_runs} live runs "
        f"({results.unique_traces} unique traces, {results.error_runs} error runs), against the "
        "same attacks' Phase 3 traces. Pooled, guardrails off:\n",
    ]
    for section in sections:
        if not section.pooled:
            continue
        arm = _arm(section, Guardrails.OFF)
        lines.append(
            f"- **{section.name}**: attack success {_rate(arm.attack_success.runs)} of runs; "
            f"{arm.population.succeeded_traces} succeeded traces in "
            f"{arm.population.succeeded_groups} groups."
        )
        for row in (*arm.table.per_tier, arm.table.all_tiers):
            lines.append(f"  - {row.name}: {_delta_cell(row)}")
    lines.append(
        "\n**Not measured.** Paraphrase and translation evasion, spent seeding the corpus. Prompt "
        "splitting across separate messages. False positives under mutation: benign traces are "
        "not mutated. Other models or agent frameworks. Live SIEM behavior.\n"
    )
    return lines


def render_results(results: EvasionResults, plan: EvasionPlan) -> str:
    payload = [s for s in results.sections if s.category == "payload_mutation"]
    variants = [s for s in results.sections if s.category == "attack_variant"]
    tiers = [row.name for row in results.sections[0].arms[0].table.per_tier]
    tier_header = ["Mutation", *tiers, ALL_TIERS]
    lines = [
        "# Evasion results",
        "",
        "Generated by `gauntlet evasion report` from `results/evasion/evasion.json`. Do not edit "
        "by "
        "hand; CI fails when this file and the JSON disagree. Every number below is in the JSON. "
        "Method: [preregistration.md](preregistration.md), evasion section. Baseline: "
        "[results-baseline.md](results-baseline.md).",
        "",
        "Rate cells read numerator/denominator = value, with a Wilson 95% interval in brackets "
        "where "
        "shown. A change is the evasion rate minus the baseline rate of the same base scenarios, "
        "both over traces where the attack succeeded, with a percentile bootstrap over variant "
        "groups (over classes for attack variants). Null means the denominator is zero: nothing "
        "succeeded, so there is no recall to read. A pooled baseline counts a base trace once per "
        "pairing, so read its change and interval rather than its fraction.",
        "",
        "## Summary",
        "",
        *_summary(results, results.sections),
        "## Attack success per mutation class",
        "",
        "Oracle-confirmed successes. A mutation that mostly breaks the attack is not an evasion "
        "win; "
        "its recall below rests on the few attacks that survived.",
        "",
        "### Guardrails off",
        "",
        _table(SUCCESS_HEADER, _success_rows(results.sections, Guardrails.OFF)),
        "",
        "### Guardrails on",
        "",
        _table(SUCCESS_HEADER, _success_rows(results.sections, Guardrails.ON)),
        "",
        "## Recall per tier under each mutation class (primary)",
        "",
        "Guardrails off. A tier fires if any rule in it fires. Each cell: recall over the traces "
        "that "
        "succeeded and could be paired; the same base scenarios at baseline; the change and its "
        "group interval.",
        "",
        "### Payload mutations",
        "",
        _table(tier_header, [_tier_row(s, Guardrails.OFF) for s in payload]),
        "",
        "### Attack variants",
        "",
        _table(tier_header, [_tier_row(s, Guardrails.OFF) for s in variants]),
        "",
        "## Recall per rule under each mutation class",
        "",
        "Guardrails off. Failed fired counts `attack_failed` traces the rule fired on; they are "
        "in no "
        "rate.",
        "",
    ]
    rule_header = ["Rule", "Recall", "Base", "Change", "Group 95% interval", "Failed fired"]
    for section in results.sections:
        lines += [
            f"### {section.name}",
            "",
            _table(rule_header, _rule_rows(section, Guardrails.OFF)),
            "",
        ]
    lines += [
        "## Guardrails on (secondary)",
        "",
        "Few bases succeed with guardrails on, so most evasion traces have nothing to pair with. "
        "Unpaired traces are in the recall column only.",
        "",
    ]
    rows = []
    for section in results.sections:
        arm = _arm(section, Guardrails.ON)
        for row in (*arm.table.per_tier, arm.table.all_tiers):
            rows.append(
                [
                    section.name,
                    row.name,
                    _rate(row.recall),
                    row.paired.unpaired_traces,
                    _short(row.paired.baseline),
                    _signed(row.paired.delta),
                    _bounds(row.paired),
                    f"{row.attack_failed.detected}/{row.attack_failed.count}",
                ]
            )
    lines += [
        _table(
            [
                "Mutation",
                "Name",
                "Recall",
                "Unpaired",
                "Base",
                "Change",
                "Group 95% interval",
                "Failed fired",
            ],
            rows,
        ),
        "",
        "## Per class under each mutation (secondary)",
        "",
        "Guardrails off. Small-N flags a recall denominator below "
        f"{plan.small_n_below}. Underpowered flags a class below the corpus group floor.",
        "",
    ]
    names = [cell.name for cell in results.per_class[0].cells] if results.per_class else []
    class_rows = []
    for item in results.per_class:
        flags = [
            flag
            for flag, on in (("small-N", item.small_n), ("underpowered", item.below_floor))
            if on
        ]
        class_rows.append(
            [
                item.mutation,
                item.attack_class,
                item.succeeded_traces,
                item.succeeded_groups,
                item.attack_failed_traces,
                *[_rate(cell.recall) for cell in item.cells],
                ", ".join(flags),
            ]
        )
    lines += [
        _table(["Mutation", "Class", "Succeeded", "Groups", "Failed", *names, "Flags"], class_rows),
        "",
        "## Offline text mutations (content rules only)",
        "",
        "Labeled offline: no model ran. The payload event of each base's captured guardrails-off "
        "trace has its text mutated in memory, and only content rules are scored, on the same "
        "traces "
        "on both sides. It says what the rule does to the text, not whether the attack would still "
        "work. It is not comparable with the live rows above, where the agent's behavior changes "
        "too.",
        "",
    ]
    offline_rows = [
        [
            section.mutation,
            row.name,
            _short(row.original),
            _short(row.offline),
            _signed(row.delta),
            "null" if row.ci95 is None else f"[{row.ci95.lower:+.3f}, {row.ci95.upper:+.3f}]",
            row.groups,
        ]
        for section in results.offline
        for row in section.rows
    ]
    lines += [
        _table(
            ["Mutation", "Name", "Original", "Offline", "Change", "Group 95% interval", "Groups"],
            offline_rows,
        ),
        "",
        "## Provenance sensitivity",
        "",
        "The sequence tier at each content-reference K, guardrails off. Base is the same base "
        "scenarios at that K.",
        "",
        _table(
            ["Mutation", "K", "Recall", "Base"],
            [[x.mutation, x.k, _short(x.recall), _short(x.baseline)] for x in results.provenance],
        ),
        "",
        "## False positives",
        "",
        "Benign traces are not mutated and no rule changed, so this restates Phase 3 on the "
        "held-out "
        "benign traces. It does not measure false positives under mutation.",
        "",
        _table(["Name", "FPR"], [[x.name, _rate(x.fpr)] for x in results.benign_fpr]),
        "",
        "## Disjointness",
        "",
        "Recomputed from the committed files. At generation, every mutated payload was also "
        f"compared with {results.disjointness.corpus_payloads_checked_at_generation} corpus and "
        "attack-variant payloads, and none matched.",
        "",
        _table(
            ["Check", "Found"],
            [
                [
                    "Bases outside the held-out split",
                    len(results.disjointness.bases_outside_heldout),
                ],
                [
                    "Evasion inputs equal to a base payload",
                    results.disjointness.inputs_matching_corpus_payloads,
                ],
                [
                    "Evasion traces with the content hash of a corpus trace",
                    results.disjointness.traces_matching_corpus_hashes,
                ],
                ["Corpus labels with a mutation", results.disjointness.corpus_labels_with_mutation],
            ],
        ),
        "",
        "## Limitations",
        "",
        "- **Survivors only.** Recall is measured on attacks that still worked. Where few "
        "survive, the "
        "row rests on few attacks and the attack-success table is the larger part of the finding.",
        "- **Single model.** One local model, llama3.1:8b. What it does with encoded or mangled "
        "text "
        "says little about another model, so attack success here may not transfer.",
        "- **Single author.** One author wrote the attacks, the variants and the rules.",
        "- **Few groups.** The bases come from few variant groups, and mutations of one base are "
        "correlated, so the group intervals are the figures to read and they are wide. Attack "
        "variants resample over four classes, which is coarser still.",
        "- **Paraphrase and translation are not measured here.** They seeded the corpus, so the "
        "rules "
        "were written against dev relatives of those wordings.",
        "- **Splitting is within one message.** The agent takes one user message per run.",
        "- **Mechanical mutations.** Generated by fixed code, not by an adaptive attacker. An "
        "attacker "
        "who can see the rules could do better than these numbers show.",
        "- **Overlap-based provenance.** Content references need verbatim overlap, so a mutated "
        "payload breaks links by construction and the sequence tier depends on the K in use.",
        "- **False positives are not re-measured.** Benign traces were not mutated.",
        "- **Framework mappings are unverified** against primary sources until Phase 7.",
        "",
    ]
    return "\n".join(lines)
