"""Native YAML rule format. The YAML file is the source of truth for a rule.

See docs/rule-format.md for the full grammar and examples.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    Discriminator,
    Field,
    JsonValue,
    StringConstraints,
    Tag,
    model_validator,
)

from agent_detection_gauntlet.normalize import Normalization, normalize_text
from agent_detection_gauntlet.schema.common import (
    STRICT_MODEL,
    Identifier,
    NonEmptyStr,
    RuleId,
    SemVer,
    Severity,
    Tier,
    unique_items,
)
from agent_detection_gauntlet.schema.trace import EventType


class Status(StrEnum):
    EXPERIMENTAL = "experimental"
    TEST = "test"
    STABLE = "stable"


class Operator(StrEnum):
    EQUALS = "equals"
    IN = "in"
    CONTAINS = "contains"
    REGEX = "regex"
    EXISTS = "exists"
    STARTSWITH = "startswith"


TOP_LEVEL_FIELDS: frozenset[str] = frozenset({"event_type", "span_id", "parent_span_id"})
ATTRIBUTE_PREFIX = "attributes."
# Attribute keys hold dots, so a path into a structured value starts after this separator.
PATH_SEPARATOR = "#"
# The path that selects every string inside a structured value.
ALL_STRINGS_PATH = "*"
_VALUE_PATH = re.compile(r"\*|[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*")


def _check_field_ref(value: str) -> str:
    if value in TOP_LEVEL_FIELDS:
        return value
    key, separator, path = value[len(ATTRIBUTE_PREFIX) :].partition(PATH_SEPARATOR)
    path_ok = not separator or _VALUE_PATH.fullmatch(path) is not None
    if value.startswith(ATTRIBUTE_PREFIX) and key and key == key.strip() and path_ok:
        return value
    allowed = ", ".join(sorted(TOP_LEVEL_FIELDS))
    raise ValueError(
        f"field must be one of {allowed}, attributes.<key> or attributes.<key>#<path>; "
        f"got {value!r}"
    )


FieldRef = Annotated[str, AfterValidator(_check_field_ref)]
NAME_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
Name = Annotated[str, StringConstraints(pattern=NAME_PATTERN)]


class FieldCondition(BaseModel):
    """Compare one event field with a value."""

    model_config = STRICT_MODEL

    field: FieldRef
    op: Operator
    value: JsonValue
    normalize: Annotated[list[Normalization], AfterValidator(unique_items)] = Field(
        default_factory=list,
        description="Normalization steps applied in the listed order to string values.",
    )

    @model_validator(mode="after")
    def _check_operands(self) -> FieldCondition:
        op, value = self.op, self.value
        # Null fields count as missing, so a null operand could never match.
        if value is None or (isinstance(value, list) and None in value):
            raise ValueError("null is not a valid operand; use exists to test for absence")
        if op is Operator.EXISTS:
            if not isinstance(value, bool):
                raise ValueError("exists takes true or false")
            if self.normalize:
                raise ValueError("exists does not take normalize")
        elif op is Operator.IN:
            if not isinstance(value, list) or not value:
                raise ValueError("in takes a non-empty list")
        elif op is Operator.REGEX:
            if not isinstance(value, str) or not value:
                raise ValueError("regex takes a non-empty pattern string")
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid regex: {exc}") from exc
            if self.normalize and normalize_text(value, self.normalize) != value:
                # The subject is normalized but the pattern is not, so it must already be in
                # normalized form or parts of it could never match.
                raise ValueError(
                    "regex pattern changes under its normalize steps; write it in normalized "
                    "form (for example lowercase with casefold)"
                )
        elif op is Operator.STARTSWITH:
            if not isinstance(value, str) or not value:
                raise ValueError("startswith takes a non-empty string")
        elif op is Operator.CONTAINS:
            if isinstance(value, dict | list) or value == "":
                raise ValueError("contains takes a non-empty string or a scalar")
        return self


class AllCondition(BaseModel):
    model_config = STRICT_MODEL

    all_of: Annotated[list[Condition], Field(alias="all", min_length=1)]


class AnyCondition(BaseModel):
    model_config = STRICT_MODEL

    any_of: Annotated[list[Condition], Field(alias="any", min_length=1)]


class NotCondition(BaseModel):
    model_config = STRICT_MODEL

    negated: Annotated[Condition, Field(alias="not")]


def _condition_kind(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("all", "any", "not"):
            if key in value:
                return key
        return "field"
    if isinstance(value, AllCondition):
        return "all"
    if isinstance(value, AnyCondition):
        return "any"
    if isinstance(value, NotCondition):
        return "not"
    if isinstance(value, FieldCondition):
        return "field"
    return None


Condition = Annotated[
    Annotated[AllCondition, Tag("all")]
    | Annotated[AnyCondition, Tag("any")]
    | Annotated[NotCondition, Tag("not")]
    | Annotated[FieldCondition, Tag("field")],
    Discriminator(
        _condition_kind,
        custom_error_type="invalid_condition",
        custom_error_message="a condition must be all, any, not, or a field comparison",
    ),
]


class EventMatch(BaseModel):
    """Select single events: an event type filter plus an optional condition tree."""

    model_config = STRICT_MODEL

    event_types: Annotated[list[EventType], Field(min_length=1), AfterValidator(unique_items)]
    where: Condition | None = None


class RequireOp(StrEnum):
    EQUALS = "equals"
    CONTAINS = "contains"
    DERIVES_FROM = "derives_from"


class Requirement(BaseModel):
    """Constrain a later sequence step by a value bound in an earlier step."""

    model_config = STRICT_MODEL

    op: RequireOp
    bound: Name
    field: FieldRef | None = None

    @model_validator(mode="after")
    def _check_field(self) -> Requirement:
        if self.op is RequireOp.DERIVES_FROM and self.field is not None:
            raise ValueError("derives_from follows adg.content.ref and takes no field")
        if self.op is not RequireOp.DERIVES_FROM and self.field is None:
            raise ValueError(f"{self.op.value} needs a field")
        return self


class SequenceStep(BaseModel):
    model_config = STRICT_MODEL

    name: Name
    match: EventMatch
    bind: dict[Name, FieldRef] = Field(default_factory=dict)
    require: list[Requirement] = Field(default_factory=list)
    first_occurrence: FieldRef | None = Field(
        default=None,
        description=(
            "1.1: an event holds this step only if no earlier event matching the step has the "
            "same value of this field."
        ),
    )


class SequenceSpec(BaseModel):
    """Ordered steps inside one trace, with an optional window and value binding."""

    model_config = STRICT_MODEL

    steps: Annotated[list[SequenceStep], Field(min_length=2)]
    within_events: Annotated[int, Field(ge=2)] | None = None
    within_seconds: Annotated[float, Field(gt=0)] | None = None

    @model_validator(mode="after")
    def _check_steps(self) -> SequenceSpec:
        names = [step.name for step in self.steps]
        if len(set(names)) != len(names):
            raise ValueError("step names must be unique")
        if self.within_events is not None and self.within_events < len(self.steps):
            raise ValueError("within_events must be at least the number of steps")
        bound: set[str] = set()
        for step in self.steps:
            for requirement in step.require:
                if requirement.bound not in bound:
                    raise ValueError(
                        f"step {step.name!r} requires {requirement.bound!r}, "
                        "which no earlier step binds"
                    )
            for name in step.bind:
                if name in bound:
                    raise ValueError(f"bind name {name!r} is bound twice")
                bound.add(name)
        return self


class ThresholdOp(StrEnum):
    GTE = "gte"
    GT = "gt"
    EQ = "eq"


class ThresholdSpec(BaseModel):
    """Count (or distinct-count) matching events per trace and compare."""

    model_config = STRICT_MODEL

    match: EventMatch
    distinct: FieldRef | None = None
    op: ThresholdOp
    value: Annotated[int, Field(ge=1)]


class BaselineStatistic(StrEnum):
    CHAIN_LENGTH = "chain_length"
    RARE_TRANSITION = "rare_transition"


class BaselineSpec(BaseModel):
    """Compare a trace with a statistic fitted on dev benign traces. See docs/engine.md."""

    model_config = STRICT_MODEL

    statistic: BaselineStatistic
    match: EventMatch
    key: FieldRef | None = None
    percentile: Annotated[int, Field(ge=1, le=100)] | None = None
    max_rate: Annotated[float, Field(gt=0, le=1)] | None = None

    @model_validator(mode="after")
    def _check_parameters(self) -> BaselineSpec:
        if self.statistic is BaselineStatistic.CHAIN_LENGTH:
            if self.percentile is None or self.key is not None or self.max_rate is not None:
                raise ValueError("chain_length takes percentile, and no key or max_rate")
        elif self.key is None or self.max_rate is None or self.percentile is not None:
            raise ValueError("rare_transition takes key and max_rate, and no percentile")
        return self


class FittedBaseline(BaseModel):
    """What `gauntlet fit-baselines` computed. Written by the command, never by hand."""

    model_config = STRICT_MODEL

    command: NonEmptyStr
    population: Literal["dev benign"]
    traces: Annotated[int, Field(ge=1)]
    threshold: Annotated[int, Field(ge=0)] | None = None
    transitions: dict[str, Annotated[int, Field(ge=1)]] | None = None

    @model_validator(mode="after")
    def _check_shape(self) -> FittedBaseline:
        if (self.threshold is None) == (self.transitions is None):
            raise ValueError("fitted holds exactly one of threshold, transitions")
        return self


class MatchLogic(BaseModel):
    model_config = STRICT_MODEL

    match: EventMatch


class SequenceLogic(BaseModel):
    model_config = STRICT_MODEL

    sequence: SequenceSpec


class ThresholdLogic(BaseModel):
    model_config = STRICT_MODEL

    threshold: ThresholdSpec


class BaselineLogic(BaseModel):
    model_config = STRICT_MODEL

    baseline: BaselineSpec


_LOGIC_KEYS = ("match", "sequence", "threshold", "baseline")


def _logic_kind(value: Any) -> str | None:
    if isinstance(value, dict):
        keys = [key for key in _LOGIC_KEYS if key in value]
        return keys[0] if len(keys) == 1 else None
    if isinstance(value, MatchLogic):
        return "match"
    if isinstance(value, SequenceLogic):
        return "sequence"
    if isinstance(value, ThresholdLogic):
        return "threshold"
    if isinstance(value, BaselineLogic):
        return "baseline"
    return None


Logic = Annotated[
    Annotated[MatchLogic, Tag("match")]
    | Annotated[SequenceLogic, Tag("sequence")]
    | Annotated[ThresholdLogic, Tag("threshold")]
    | Annotated[BaselineLogic, Tag("baseline")],
    Discriminator(
        _logic_kind,
        custom_error_type="invalid_logic",
        custom_error_message=(
            "logic must contain exactly one of: match, sequence, threshold, baseline"
        ),
    ),
]

ATLAS_PATTERN = r"^AML\.T[0-9]{4}(\.[0-9]{3})?$"
OWASP_LLM_PATTERN = r"^LLM[0-9]{2}$"
OWASP_AGENTIC_PATTERN = r"^ASI[0-9]{2}$"
ATTACK_PATTERN = r"^T[0-9]{4}(\.[0-9]{3})?$"

MAPPING_PATTERNS: dict[str, str] = {
    "atlas": ATLAS_PATTERN,
    "owasp_llm": OWASP_LLM_PATTERN,
    "owasp_agentic": OWASP_AGENTIC_PATTERN,
    "attack": ATTACK_PATTERN,
}


AtlasId = Annotated[str, StringConstraints(pattern=ATLAS_PATTERN)]
OwaspLlmId = Annotated[str, StringConstraints(pattern=OWASP_LLM_PATTERN)]
OwaspAgenticId = Annotated[str, StringConstraints(pattern=OWASP_AGENTIC_PATTERN)]
AttackId = Annotated[str, StringConstraints(pattern=ATTACK_PATTERN)]


class Mappings(BaseModel):
    """Framework mappings. attack is only used when the agent performs a host action."""

    model_config = STRICT_MODEL

    atlas: Annotated[list[AtlasId], AfterValidator(unique_items)]
    owasp_llm: Annotated[list[OwaspLlmId], AfterValidator(unique_items)]
    owasp_agentic: Annotated[list[OwaspAgenticId], AfterValidator(unique_items)]
    attack: Annotated[list[AttackId], AfterValidator(unique_items)]

    def by_family(self) -> dict[str, list[str]]:
        return {
            "atlas": list(self.atlas),
            "owasp_llm": list(self.owasp_llm),
            "owasp_agentic": list(self.owasp_agentic),
            "attack": list(self.attack),
        }


TraceIdList = Annotated[list[Identifier], Field(min_length=1), AfterValidator(unique_items)]


class Fixtures(BaseModel):
    """Trace ids the rule must fire on (tp) and must stay silent on (fp)."""

    model_config = STRICT_MODEL

    tp: TraceIdList
    fp: TraceIdList

    @model_validator(mode="after")
    def _check_disjoint(self) -> Fixtures:
        overlap = sorted(set(self.tp) & set(self.fp))
        if overlap:
            raise ValueError(f"traces listed as both tp and fp: {overlap}")
        return self


def _uses_format_1_1(value: Any, parent: str | None = None) -> bool:
    """Whether dumped logic holds a feature added in rule format 1.1."""
    if isinstance(value, dict):
        if "baseline" in value or value.get("first_occurrence") is not None:
            return True
        if any(PATH_SEPARATOR in ref for ref in value.get("bind", {}).values()):
            return True
        return any(_uses_format_1_1(item, key) for key, item in value.items() if key != "bind")
    if isinstance(value, list):
        return any(_uses_format_1_1(item, parent) for item in value)
    return parent in ("field", "distinct") and isinstance(value, str) and PATH_SEPARATOR in value


class Rule(BaseModel):
    """A detection rule."""

    model_config = STRICT_MODEL

    format_version: Literal["1.0", "1.1"] = Field(
        default="1.0",
        description="Rule format. 1.1 adds value paths, first_occurrence and baseline logic.",
    )
    id: RuleId
    title: NonEmptyStr
    version: SemVer
    status: Status
    tier: Tier
    severity: Severity
    description: NonEmptyStr
    hypothesis: NonEmptyStr
    mappings: Mappings
    telemetry: Annotated[list[EventType], Field(min_length=1), AfterValidator(unique_items)]
    logic: Logic
    limitations: Annotated[list[NonEmptyStr], Field(min_length=1)]
    fixtures: Fixtures
    fitted: FittedBaseline | None = Field(
        default=None,
        description="1.1: baseline logic only. Null until `gauntlet fit-baselines` has run.",
    )

    @model_validator(mode="after")
    def _check_telemetry(self) -> Rule:
        missing = sorted(logic_event_types(self.logic) - set(self.telemetry))
        if missing:
            raise ValueError(f"logic uses event types not listed in telemetry: {missing}")
        return self

    @model_validator(mode="after")
    def _check_format(self) -> Rule:
        dumped = self.logic.model_dump(mode="json", by_alias=True)
        if self.format_version == "1.0" and _uses_format_1_1(dumped):
            raise ValueError("value paths, first_occurrence and baseline need format_version 1.1")
        return self

    @model_validator(mode="after")
    def _check_fitted(self) -> Rule:
        if self.fitted is None:
            return self
        if not isinstance(self.logic, BaselineLogic):
            raise ValueError("fitted belongs to baseline logic only")
        wants_threshold = self.logic.baseline.statistic is BaselineStatistic.CHAIN_LENGTH
        if wants_threshold != (self.fitted.threshold is not None):
            raise ValueError("fitted does not fit the baseline statistic")
        return self


def logic_event_types(
    logic: MatchLogic | SequenceLogic | ThresholdLogic | BaselineLogic,
) -> set[EventType]:
    if isinstance(logic, MatchLogic):
        return set(logic.match.event_types)
    if isinstance(logic, SequenceLogic):
        return {kind for step in logic.sequence.steps for kind in step.match.event_types}
    if isinstance(logic, BaselineLogic):
        return set(logic.baseline.match.event_types)
    return set(logic.threshold.match.event_types)


for _model in (AllCondition, AnyCondition, NotCondition, EventMatch):
    _model.model_rebuild()
