"""Choose the held-out bases and generate the mutated scenario file the source lab runs.

The bases come from labels alone: a plain or seeded held-out scenario with an oracle-confirmed
success in the baseline arm. A scenario that never worked cannot be paired with a baseline, and the
authored `-OBF` twins already use reserved encodings. Everything the source lab needs for a run is
in the `scenarios` list. `bases` keeps each unmutated payload, so the file can be regenerated and
checked without the source repository.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agent_detection_gauntlet.errors import GauntletError
from agent_detection_gauntlet.evasion.model import BaseScenario
from agent_detection_gauntlet.evasion.mutations import PAYLOAD_MUTATIONS, mutate, scenario_id
from agent_detection_gauntlet.schema.labels import LabelRecord, Split
from agent_detection_gauntlet.schema.trace import (
    ATTR_CONTENT_TEXT,
    ATTR_SOURCE_TRUST,
    EventType,
    TraceEvent,
)

OBFUSCATED_SUFFIX = "-OBF"
BASELINE_ARM = "baseline"
SCENARIO_FIELDS: tuple[str, ...] = ("channel", "oracle", "workspace_files", "outside_files")


ATTR_DATA_SOURCE = "gen_ai.data_source.id"
TOOL_DEFINITION = "mcp.tool_definition"
UNTRUSTED = "untrusted"


def is_payload_event(event: TraceEvent, mcp: bool) -> bool:
    """The event a payload enters by: an untrusted tool definition, or else the user prompt."""
    if mcp:
        return (
            event.event_type is EventType.RETRIEVAL
            and event.attributes.get(ATTR_DATA_SOURCE) == TOOL_DEFINITION
            and event.attributes.get(ATTR_SOURCE_TRUST) == UNTRUSTED
        )
    return event.event_type is EventType.USER_PROMPT


def event_payload(event: TraceEvent) -> str | None:
    """The attack text an event carries: a prompt, or an untrusted tool's description."""
    text = event.attributes.get(ATTR_CONTENT_TEXT)
    if not isinstance(text, str):
        return None
    if is_payload_event(event, False):
        return text
    return text.partition(": ")[2] or text if is_payload_event(event, True) else None


def select_bases(
    labels: Mapping[str, LabelRecord], ineffective: Iterable[str] = ()
) -> list[BaseScenario]:
    skip = set(ineffective)
    bases: dict[str, BaseScenario] = {}
    for label in labels.values():
        if (
            label.split is Split.HELDOUT
            and label.attack_succeeded
            and label.condition == BASELINE_ARM
            and label.scenario_id is not None
            and not label.scenario_id.endswith(OBFUSCATED_SUFFIX)
            and label.attack_class is not None
            and label.attack_class not in skip
            and label.variant_group is not None
        ):
            bases[label.scenario_id] = BaseScenario(
                scenario_id=label.scenario_id,
                variant_group=label.variant_group,
                attack_class=label.attack_class,
            )
    return [bases[name] for name in sorted(bases)]


def normalized_payload(text: str) -> str:
    return " ".join(text.split())


def payload_of(item: Mapping[str, Any]) -> str:
    """The part of an attack a mutation rewrites: the tool description or the user prompt."""
    mcp = item.get("mcp")
    return str(mcp["description"]) if mcp else str(item["user_prompt"])


@dataclass(frozen=True)
class SourceCatalogs:
    """Scenario items from the source lab's catalog files, by id."""

    corpus: dict[str, dict[str, Any]]
    attack_variants: dict[str, dict[str, Any]]

    def known_payloads(self) -> set[str]:
        items = (*self.corpus.values(), *self.attack_variants.values())
        return {normalized_payload(payload_of(item)) for item in items}


def _mutated_item(item: Mapping[str, Any], base: BaseScenario, name: str) -> dict[str, Any]:
    mutated = mutate(name, payload_of(item), base.scenario_id)
    out: dict[str, Any] = {
        "scenario_id": scenario_id(base.scenario_id, name),
        "derived_from": base.scenario_id,
        "transform": name,
        "variant_group": base.variant_group,
        "user_prompt": item["user_prompt"],
    }
    for field in (*SCENARIO_FIELDS, "doc_index"):
        if field in item:
            out[field] = item[field]
    if item.get("mcp"):
        out["mcp"] = {**item["mcp"], "description": mutated}
    else:
        out["user_prompt"] = mutated
    return out


def build_inputs(
    bases: Sequence[BaseScenario], catalogs: SourceCatalogs, source_commit: str
) -> dict[str, Any]:
    missing = sorted(b.scenario_id for b in bases if b.scenario_id not in catalogs.corpus)
    if missing:
        raise GauntletError(f"bases are not in the source catalogs: {missing}")
    scenarios = [
        _mutated_item(catalogs.corpus[base.scenario_id], base, name)
        for base in bases
        for name in PAYLOAD_MUTATIONS
    ]
    known = catalogs.known_payloads()
    overlap = sorted(
        s["scenario_id"] for s in scenarios if normalized_payload(payload_of(s)) in known
    )
    if overlap:
        raise GauntletError(f"evasion inputs repeat a corpus payload: {overlap}")
    return {
        "version": 1,
        "description": (
            "Payload mutations of the held-out scenarios that succeed at baseline. Generated by "
            "`gauntlet evasion mutate`; do not edit by hand. Held-out data: not for rule work."
        ),
        "source_commit": source_commit,
        "bases": {
            base.scenario_id: {
                "attack_class": base.attack_class,
                "variant_group": base.variant_group,
                "payload": payload_of(catalogs.corpus[base.scenario_id]),
            }
            for base in bases
        },
        "corpus_payloads_checked": len(known),
        "scenarios": scenarios,
    }


def check_inputs_file(doc: Mapping[str, Any], bases: Sequence[BaseScenario]) -> list[str]:
    """Problems in a generated file: wrong bases, or a payload the mutations do not reproduce."""
    problems: list[str] = []
    recorded = doc.get("bases", {})
    expected = {b.scenario_id: b for b in bases}
    if set(recorded) != set(expected):
        problems.append("the mutated scenario file does not hold the registered bases")
    scenarios = {s["scenario_id"]: s for s in doc.get("scenarios", [])}
    wanted = {scenario_id(b, name): (b, name) for b in expected for name in PAYLOAD_MUTATIONS}
    if set(scenarios) != set(wanted):
        problems.append("the mutated scenario file does not hold every base and mutation")
    for sid in sorted(set(scenarios) & set(wanted)):
        base, name = wanted[sid]
        item = scenarios[sid]
        if base in recorded and payload_of(item) != mutate(name, recorded[base]["payload"], base):
            problems.append(f"{sid}: the payload does not follow from its base")
        if item.get("derived_from") != base or item.get("transform") != name:
            problems.append(f"{sid}: wrong parent or transform")
        if item.get("variant_group") != expected[base].variant_group:
            problems.append(f"{sid}: wrong variant group")
    return problems
