"""Render docs/coverage.md from the coverage JSON. Every number comes from that file."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from agent_detection_gauntlet.coverage.model import (
    CoverageReport,
    Population,
    PopulationName,
    Reason,
    RuleEvidence,
    Technique,
    Verdict,
)
from agent_detection_gauntlet.metrics.report import Rate

FAMILY_TITLES = {
    "atlas": "MITRE ATLAS",
    "owasp_llm": "OWASP LLM",
    "owasp_agentic": "OWASP Agentic",
    "attack": "MITRE ATT&CK",
}
POPULATION_TITLES: dict[PopulationName, str] = {
    "clean_heldout": "Clean held-out attacks",
    "payload_mutations": "Payload mutations",
    "attack_variants": "Attack variants",
}
_ORDER: tuple[PopulationName, ...] = ("clean_heldout", "payload_mutations", "attack_variants")


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


def _fraction(rate: Rate) -> str:
    return f"{rate.numerator}/{rate.denominator}"


def _evidence(item: RuleEvidence) -> str:
    return f"{item.rule_id} recall {_rate(item.recall)}, FPR {_fraction(item.fpr)}"


def _verdict_of(technique: Technique, name: PopulationName) -> Verdict:
    return next(verdict for verdict in technique.verdicts if verdict.population == name)


def _reason(technique: Technique, verdict: Verdict) -> str:
    if verdict.reason is Reason.FPR_TOO_HIGH:
        return "FPR too high"
    if verdict.reason is Reason.RECALL_TOO_LOW:
        return "recall too low"
    if technique.ineffective_only:
        return "no successful attacks to detect"
    return "no successful attacks of that technique here"


def _cell(technique: Technique, name: PopulationName) -> str:
    verdict = _verdict_of(technique, name)
    if verdict.covered:
        return f"**covered**: {_evidence(verdict.best_rule)}"
    return f"not covered, {_reason(technique, verdict)}; best {_evidence(verdict.best_rule)}"


def _ids(techniques: Iterable[Technique]) -> str:
    return ", ".join(technique.id for technique in techniques) or "none"


def _covered(report: CoverageReport, name: PopulationName) -> list[Technique]:
    return [item for item in report.techniques if _verdict_of(item, name).covered]


def _population(report: CoverageReport, name: PopulationName) -> Population:
    return next(item for item in report.populations if item.name == name)


def _summary(report: CoverageReport) -> list[str]:
    total = len(report.techniques)
    lines = [
        "## Summary",
        "",
        f"**Measured.** {total} techniques are mapped by {len(report.rules)} frozen rules. A "
        "technique is covered only if at least one rule mapped to it has, on the pooled rows of "
        f"that population, recall at or above {report.thresholds.min_heldout_recall} and FPR at or "
        f"below {report.thresholds.max_fpr}, compared on point estimates. The thresholds are the "
        "ones pre-registered before any held-out result existed, unchanged.",
        "",
    ]
    for name in _ORDER:
        population = _population(report, name)
        covered = _covered(report, name)
        best = max(
            population.rules,
            key=lambda item: -1.0 if item.recall.value is None else item.recall.value,
        )
        lines.append(
            f"- **{POPULATION_TITLES[name]}** ({population.succeeded_traces} succeeded traces, "
            f"{population.succeeded_groups} groups): {len(covered)} of {total} covered "
            f"({_ids(covered)}). Highest rule recall: {_evidence(best)}."
        )
    lines += [
        "",
        "**Not measured.** Whether these thresholds are the right bar. Other models or agent "
        "frameworks. Live SIEM behavior. False positives under mutation: benign traces are not "
        "mutated, so the FPR is the same in every column. Per-rule recall per class under evasion: "
        "the Phase 4 per-class rows hold tiers only, so evasion has no per-technique rule counts, "
        "and no held-out data was read to make them.",
        "",
    ]
    return lines


def _main_table(report: CoverageReport) -> list[str]:
    lines = [
        "## Coverage",
        "",
        "Each column is judged alone. Payload mutations and attack variants are the two reserved "
        "Phase 4 categories, kept separate as registered, with guardrails off, their primary "
        "arm. Cells show the rule that decides the verdict, with Wilson 95% intervals on recall. "
        "The clean column pools both guardrail arms, as Phase 3 reports it.",
        "",
    ]
    rows = [
        [
            f"{FAMILY_TITLES[item.family]} {item.id}",
            item.name,
            ", ".join(item.rules),
            *(_cell(item, name) for name in _ORDER),
        ]
        for item in report.techniques
    ]
    header = ["Technique", "Name", "Mapped rules", *(POPULATION_TITLES[name] for name in _ORDER)]
    lines += [_table(header, rows), ""]
    return lines


def _no_attacks(report: CoverageReport) -> list[str]:
    ineffective = [item for item in report.techniques if item.ineffective_only]
    untied = [item for item in report.techniques if not item.classes]
    lines = [
        "## Techniques with no successful attacks to detect",
        "",
        f"Tied only to an ineffective class ({', '.join(report.ineffective_classes)}): "
        f"{_ids(ineffective)}. These are never covered and are not gaps to close. The model did "
        "not act on those attacks, so there was nothing to detect. Rules mapped to them can still "
        "fire on other classes' attacks, and the counts above show that.",
        "",
        "Tied to no class: "
        f"{_ids(untied)}. The source threat model files no attack class under these IDs, so they "
        "have no counts of their own and are judged on the pooled rows alone.",
        "",
    ]
    return lines


def _technique_counts(report: CoverageReport) -> list[str]:
    rows: list[list[object]] = []
    for item in report.techniques:
        verdict = _verdict_of(item, "clean_heldout")
        rows.extend(
            [
                f"{FAMILY_TITLES[item.family]} {item.id}",
                ", ".join(item.classes),
                verdict.own_succeeded_traces,
                count.rule_id,
                _rate(count.recall),
            ]
            for count in item.clean_technique_counts
        )
    return [
        "## Per-technique counts on clean held-out attacks",
        "",
        "Recall of each mapped rule on the succeeded traces of the technique's own classes only. "
        "These counts do not decide any verdict above: the registered bar is on pooled results. "
        "Own classes come from the class map, and most denominators are below 10.",
        "",
        _table(["Technique", "Own classes", "Own succeeded traces", "Rule", "Recall"], rows),
        "",
    ]


def _rule_tables(report: CoverageReport) -> list[str]:
    lines = ["## Per-rule evidence", ""]
    for name in _ORDER:
        population = _population(report, name)
        lines += [
            f"### {POPULATION_TITLES[name]}",
            "",
            f"Source: {population.source}.",
            "",
            _table(
                ["Rule", "Tier", "Recall", "FPR", "Meets recall", "Meets FPR"],
                [
                    [
                        item.rule_id,
                        item.tier.value,
                        _rate(item.recall),
                        _rate(item.fpr),
                        "yes" if item.meets_recall else "no",
                        "yes" if item.meets_fpr else "no",
                    ]
                    for item in population.rules
                ],
            ),
            "",
        ]
    return lines


def _attacked_without_rule(report: CoverageReport) -> list[str]:
    return [
        "## Attacked, with no rule mapped",
        "",
        "IDs as the source threat model writes them, for classes that exist here. No rule may "
        "reference them because they are not in this repository's catalog, so they are not in the "
        "table above. A class can still be detected by a rule mapped to another technique.",
        "",
        _table(
            ["ID", "Classes", "Succeeded traces, clean held-out"],
            [
                [item.id, ", ".join(item.classes), item.clean_succeeded_traces]
                for item in report.attacked_without_rule
            ],
        ),
        "",
    ]


def _limitations(report: CoverageReport) -> list[str]:
    return [
        "## Limitations",
        "",
        "- **Pooled recall sets a high bar for a single rule.** The denominator holds every "
        "succeeded attack of every class, and rules are built for one mechanism each. That is the "
        "registered reading, applied as written.",
        "- **Small attack variant population.** Few variants succeeded, in few classes, so a "
        "verdict in that column rests on a handful of traces. Read its interval, not the verdict "
        "alone.",
        "- **The class map is an input, not a measurement.** It comes from the source threat model "
        f"at commit `{report.class_map_source_commit}` and was keyed into this repository's "
        "vocabulary for this phase, after results were seen. It can only remove a verdict, never "
        "grant one, but it decides which reason a technique shows and which counts it gets.",
        "- **The reason depends on how the source files a class.** It files tool-description "
        "attacks under IDs this catalog lacks, while the rules here map tool-metadata text to "
        "indirect injection. An attack variant counts under the class whose objective it pursues, "
        "not the technique its delivery uses. So a technique shown with no successful attacks can "
        "still have rules firing on related attacks.",
        "- **Two OWASP LLM numberings.** This repository's catalog and the source threat model "
        "number OWASP LLM differently, so the class map matches LLM03 and LLM06 by title. Rule "
        "files are frozen and keep their IDs. Phase 7 checks every ID against the primary source.",
        "- **Framework mappings are unverified** until Phase 7. A rule's mapping is its author's "
        "claim about the technique it detects, and coverage inherits that claim.",
        "- **Single model and single-author corpus**, as in the baseline and evasion reports.",
        "",
    ]


def render_coverage(report: CoverageReport) -> str:
    lines = [
        "# Coverage",
        "",
        "Generated by `gauntlet coverage build` from `results/coverage/coverage.json`. Do not edit "
        "by hand; CI fails when this file, the JSON and the golden results disagree. Thresholds: "
        "[preregistration.md](preregistration.md). Results: "
        "[results-baseline.md](results-baseline.md), [results-evasion.md](results-evasion.md).",
        "",
        "Rate cells read numerator/denominator = value [Wilson 95% interval]. Null means the "
        "denominator is zero.",
        "",
        *_summary(report),
        *_main_table(report),
        *_no_attacks(report),
        *_technique_counts(report),
        *_attacked_without_rule(report),
        *_rule_tables(report),
        *_limitations(report),
    ]
    return "\n".join(lines).rstrip("\n") + "\n"
