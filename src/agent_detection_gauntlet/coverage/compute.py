"""Compute coverage from rule mappings and pooled golden results. Reads no trace.

A technique is covered on a population only when at least one rule mapped to it reaches the
pre-registered recall and FPR on that population's pooled rows. The class map decides only whether
a technique has attacks of its own to detect: it can remove a verdict, never grant one.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from pydantic import BaseModel, ValidationError

from agent_detection_gauntlet.catalog import FAMILIES, Catalog
from agent_detection_gauntlet.coverage.model import (
    AttackedWithoutRule,
    CoverageReport,
    InputRef,
    Population,
    PopulationName,
    Reason,
    RuleEvidence,
    Technique,
    TechniqueCount,
    Verdict,
)
from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.evasion.model import Category, EvasionResults, EvasionSection
from agent_detection_gauntlet.io.jsonl import format_validation_error
from agent_detection_gauntlet.metrics.compute import make_rate, sha256_file
from agent_detection_gauntlet.metrics.report import Rate
from agent_detection_gauntlet.rules.loader import LoadedRule, load_yaml_document
from agent_detection_gauntlet.schema.common import STRICT_MODEL, NonEmptyStr
from agent_detection_gauntlet.schema.labels import Guardrails
from agent_detection_gauntlet.validation.model import BaselineResults, Preregistration

COVERAGE_JSON = Path("results/coverage/coverage.json")
COVERAGE_DOC = Path("docs/coverage.md")
CATALOG_DIR = "src/agent_detection_gauntlet/catalog"
CLASS_MAP_FILE = "attack_classes.yaml"
SECTIONS: dict[PopulationName, tuple[str, Category]] = {
    "payload_mutations": ("all_payload_mutations", "payload_mutation"),
    "attack_variants": ("all_attack_variants", "attack_variant"),
}


class ClassMapEntry(BaseModel):
    model_config = STRICT_MODEL

    atlas: list[NonEmptyStr]
    owasp_llm: list[NonEmptyStr]
    owasp_agentic: list[NonEmptyStr]
    attack: list[NonEmptyStr]
    not_in_catalog: list[NonEmptyStr]


class ClassMap(BaseModel):
    model_config = STRICT_MODEL

    source_commit: NonEmptyStr
    classes: dict[str, ClassMapEntry]


def _class_map_text() -> str:
    return (
        resources.files("agent_detection_gauntlet.catalog")
        .joinpath(CLASS_MAP_FILE)
        .read_text(encoding="utf-8")
    )


def parse_class_map(text: str, catalog: Catalog) -> ClassMap:
    """Parse the class map and hold it to the catalog: a typo must not hide a technique."""
    try:
        parsed = ClassMap.model_validate_json(load_yaml_document(text, CLASS_MAP_FILE))
    except ValidationError as exc:
        raise GauntletError(f"{CLASS_MAP_FILE}: {format_validation_error(exc)}") from exc
    except ValueError as exc:
        raise GauntletError(f"{CLASS_MAP_FILE}: {exc}") from exc
    known = {mapping_id for family in catalog.families.values() for mapping_id in family}
    for name, entry in parsed.classes.items():
        for family in FAMILIES:
            for mapping_id in getattr(entry, family):
                if catalog.lookup(family, mapping_id) is None:
                    raise GauntletError(f"{CLASS_MAP_FILE}: {name}: {mapping_id} not in {family}")
        for mapping_id in entry.not_in_catalog:
            if mapping_id in known:
                raise GauntletError(f"{CLASS_MAP_FILE}: {name}: {mapping_id} is in the catalog")
    return parsed


@dataclass(frozen=True)
class Inputs:
    """The frozen files coverage is computed from, already read."""

    plan: Preregistration
    plan_sha256: str
    baseline: BaselineResults
    baseline_sha256: str
    evasion: EvasionResults
    rules: Sequence[LoadedRule]
    catalog: Catalog
    class_map: ClassMap
    input_refs: list[InputRef]


def check_inputs(inputs: Inputs) -> None:
    """Refuse results that do not belong together or do not match the rule files."""
    if inputs.baseline.preregistration_sha256 != inputs.plan_sha256:
        raise GauntletError("the baseline results name a different registration")
    if inputs.evasion.baseline_results_sha256 != inputs.baseline_sha256:
        raise GauntletError("the evasion results name a different baseline")
    current = {item.rule.id: sha256_file(item.path) for item in inputs.rules}
    for name, scored in (("baseline", inputs.baseline.rules), ("evasion", inputs.evasion.rules)):
        if current != {rule.id: rule.sha256 for rule in scored}:
            raise GauntletError(f"the rule files differ from the rules in the {name} results")
    expected = set(inputs.plan.ineffective_classes)
    expected |= {section.attack_class for section in inputs.baseline.per_class}
    expected |= {row.attack_class for row in inputs.evasion.per_class}
    missing = sorted(expected - set(inputs.class_map.classes))
    if missing:
        raise GauntletError(f"{CLASS_MAP_FILE} has no entry for: {', '.join(missing)}")


def _evidence(rule: LoadedRule, recall: Rate, fpr: Rate, plan: Preregistration) -> RuleEvidence:
    thresholds = plan.coverage
    return RuleEvidence(
        rule_id=rule.rule.id,
        tier=rule.rule.tier,
        recall=recall,
        fpr=fpr,
        meets_recall=recall.value is not None and recall.value >= thresholds.min_heldout_recall,
        meets_fpr=fpr.value is not None and fpr.value <= thresholds.max_fpr,
    )


def _clean_population(inputs: Inputs) -> Population:
    metrics = {item.rule_id: item for item in inputs.baseline.pooled.per_rule}
    population = inputs.baseline.population
    return Population(
        name="clean_heldout",
        source="results/baseline/metrics.json: pooled.per_rule, both guardrail arms",
        succeeded_traces=population.malicious_succeeded,
        succeeded_groups=population.malicious_succeeded_groups,
        succeeded_by_class={
            section.attack_class: section.succeeded_traces for section in inputs.baseline.per_class
        },
        rules=[
            _evidence(
                item,
                metrics[item.rule.id].rates.recall,
                metrics[item.rule.id].rates.fpr,
                inputs.plan,
            )
            for item in inputs.rules
        ],
    )


def _section(evasion: EvasionResults, name: str) -> EvasionSection:
    return next(section for section in evasion.sections if section.name == name)


def _evasion_population(inputs: Inputs, name: PopulationName) -> Population:
    section_name, category = SECTIONS[name]
    arm = next(
        arm
        for arm in _section(inputs.evasion, section_name).arms
        if arm.guardrails is Guardrails.OFF
    )
    rows = {row.name: row for row in arm.table.per_rule}
    fprs = {cell.name: cell.fpr for cell in inputs.evasion.benign_fpr}
    mutations = {
        section.name
        for section in inputs.evasion.sections
        if section.category == category and not section.pooled
    }
    by_class: dict[str, int] = {}
    for row in inputs.evasion.per_class:
        if row.mutation in mutations:
            by_class[row.attack_class] = by_class.get(row.attack_class, 0) + row.succeeded_traces
    return Population(
        name=name,
        source=f"results/evasion/evasion.json: {section_name}, guardrails off; "
        "FPR from benign_fpr, the same held-out benign traces, not mutated",
        succeeded_traces=arm.population.succeeded_traces,
        succeeded_groups=arm.population.succeeded_groups,
        succeeded_by_class=by_class,
        rules=[
            _evidence(item, rows[item.rule.id].recall, fprs[item.rule.id], inputs.plan)
            for item in inputs.rules
        ],
    )


def _best(evidence: Sequence[RuleEvidence]) -> RuleEvidence:
    def key(item: RuleEvidence) -> tuple[float, float, str]:
        recall = -1.0 if item.recall.value is None else item.recall.value
        fpr = 2.0 if item.fpr.value is None else item.fpr.value
        return (-recall, fpr, item.rule_id)

    return min(evidence, key=key)


def _verdict(
    population: Population,
    rule_ids: Sequence[str],
    classes: Sequence[str],
    ineffective_only: bool,
) -> Verdict:
    evidence = [item for item in population.rules if item.rule_id in rule_ids]
    own = sum(population.succeeded_by_class.get(name, 0) for name in classes) if classes else None
    passing = [item for item in evidence if item.meets_recall and item.meets_fpr]
    reason: Reason | None = None
    if ineffective_only or own == 0:
        # Nothing of this technique succeeded here, so a rule passing on other attacks says
        # nothing about it.
        passing = []
        reason = Reason.NO_SUCCESSFUL_ATTACKS
    elif not passing:
        reason = (
            Reason.FPR_TOO_HIGH
            if any(item.meets_recall for item in evidence)
            else Reason.RECALL_TOO_LOW
        )
    return Verdict(
        population=population.name,
        covered=bool(passing),
        covering_rules=[item.rule_id for item in passing],
        reason=reason,
        own_succeeded_traces=own,
        best_rule=_best(passing or evidence),
    )


def _clean_counts(
    inputs: Inputs, rule_ids: Sequence[str], classes: Sequence[str]
) -> list[TechniqueCount]:
    sections = [item for item in inputs.baseline.per_class if item.attack_class in classes]
    if not sum(section.succeeded_traces for section in sections):
        return []
    counts: list[TechniqueCount] = []
    for rule_id in rule_ids:
        cells = [
            cell for section in sections for cell in section.table.per_rule if cell.name == rule_id
        ]
        counts.append(
            TechniqueCount(
                rule_id=rule_id,
                recall=make_rate(
                    sum(cell.recall.numerator for cell in cells),
                    sum(cell.recall.denominator for cell in cells),
                ),
            )
        )
    return counts


def _classes_by_technique(class_map: ClassMap) -> Mapping[tuple[str, str], list[str]]:
    tied: dict[tuple[str, str], list[str]] = {}
    for name, entry in class_map.classes.items():
        for family in FAMILIES:
            for mapping_id in getattr(entry, family):
                tied.setdefault((family, mapping_id), []).append(name)
    return tied


def build_coverage(inputs: Inputs) -> CoverageReport:
    check_inputs(inputs)
    populations = [
        _clean_population(inputs),
        _evasion_population(inputs, "payload_mutations"),
        _evasion_population(inputs, "attack_variants"),
    ]
    ineffective = set(inputs.plan.ineffective_classes)
    tied = _classes_by_technique(inputs.class_map)
    techniques: list[Technique] = []
    for family in FAMILIES:
        ids = sorted(
            {
                mapping_id
                for item in inputs.rules
                for mapping_id in getattr(item.rule.mappings, family)
            }
        )
        for mapping_id in ids:
            rule_ids = [
                item.rule.id
                for item in inputs.rules
                if mapping_id in getattr(item.rule.mappings, family)
            ]
            classes = sorted(tied.get((family, mapping_id), []))
            ineffective_only = bool(classes) and set(classes) <= ineffective
            entry = inputs.catalog.lookup(family, mapping_id)
            if entry is None:
                raise GauntletError(f"{mapping_id} is mapped by a rule but not in the catalog")
            techniques.append(
                Technique(
                    family=family,
                    id=mapping_id,
                    name=entry.name,
                    verified=entry.verified,
                    rules=rule_ids,
                    classes=classes,
                    ineffective_only=ineffective_only,
                    verdicts=[
                        _verdict(population, rule_ids, classes, ineffective_only)
                        for population in populations
                    ],
                    clean_technique_counts=_clean_counts(inputs, rule_ids, classes),
                )
            )
    outside: dict[str, list[str]] = {}
    for name, map_entry in inputs.class_map.classes.items():
        for mapping_id in map_entry.not_in_catalog:
            outside.setdefault(mapping_id, []).append(name)
    clean_by_class = populations[0].succeeded_by_class
    return CoverageReport(
        schema_version="1.0",
        thresholds=inputs.plan.coverage,
        class_map_source_commit=inputs.class_map.source_commit,
        ineffective_classes=sorted(ineffective),
        inputs=inputs.input_refs,
        rules=inputs.baseline.rules,
        populations=populations,
        techniques=techniques,
        attacked_without_rule=[
            AttackedWithoutRule(
                id=mapping_id,
                classes=sorted(classes),
                clean_succeeded_traces=sum(clean_by_class.get(name, 0) for name in classes),
            )
            for mapping_id, classes in sorted(outside.items())
        ],
    )


def load_class_map(catalog: Catalog) -> ClassMap:
    return parse_class_map(_class_map_text(), catalog)
