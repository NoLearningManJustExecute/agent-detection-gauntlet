"""Decide what converts, and render it. Anything that would be an approximation is refused.

A rule converts to a format only if the target can state the same test on the same data. The field
mapping is an assumption about a hypothetical schema, and it carries what a query language cannot
do at search time: normalization and "every string in the arguments" become fields an ingest
pipeline must compute exactly as docs/rule-format.md defines them. Everything else has to hold in
the target's own semantics, so a rule is listed as not converted with its reason otherwise.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

import yaml

from agent_detection_gauntlet.rules.model import (
    ALL_STRINGS_PATH,
    ATTRIBUTE_PREFIX,
    PATH_SEPARATOR,
    AllCondition,
    AnyCondition,
    BaselineLogic,
    EventMatch,
    FieldCondition,
    MatchLogic,
    NotCondition,
    Operator,
    Rule,
    SequenceLogic,
    ThresholdLogic,
)

HEADER = (
    "Generated artifact. Converted from native ADG rules. Not validated against a live SIEM. "
    "Field mappings are assumptions."
)
LABEL = "converted, not live SIEM validated"
FORMATS: Mapping[str, str] = {"sigma": "yml", "kql": "kql", "spl": "spl", "esql": "esql"}
UUID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "agent-detection-gauntlet/rules")
KQL_TABLE = "AdgTraces"
SPL_INDEX = "adg_traces"
ESQL_INDEX = "adg-traces"

Tree = AllCondition | AnyCondition | NotCondition | FieldCondition

# Python's re applies these to Unicode text. The targets apply them to ASCII or leave it to the
# backend, so the same pattern can decide differently on the same text.
UNICODE_ESCAPES = frozenset("bBwWdDsSAZ")
# ES|QL RLIKE takes Lucene syntax: always anchored, where these either are operators or are absent.
LUCENE_UNSAFE = frozenset('^$.\\<>@#&~"')


class NotConvertible(Exception):
    """A rule, or a part of it, has no faithful form in the target."""


def logic_gap(rule: Rule) -> str | None:
    """Why this rule's logic cannot convert to any of the formats, or None for a single event."""
    logic = rule.logic
    if isinstance(logic, BaselineLogic):
        return (
            "Baseline statistic fitted on dev benign traces. It needs the engine's per-trace state "
            "and fitted values, which these formats cannot hold."
        )
    if isinstance(logic, ThresholdLogic):
        return (
            "Counts over a whole trace with no time bound. A Sigma correlation and the query "
            "equivalents need a timespan, so the semantics would not match exactly."
        )
    if isinstance(logic, SequenceLogic):
        steps = logic.sequence.steps
        if any(step.first_occurrence for step in steps):
            return (
                "Sequence with first_occurrence: it needs per-trace memory of which tool values "
                "came before, which these formats cannot state."
            )
        if any(step.bind or step.require for step in steps):
            return (
                "Sequence with bind (taint): it follows content references across events, which "
                "these formats cannot state."
            )
        return (
            "Ordered steps within one trace, with no time bound. A temporal correlation needs a "
            "timespan and a grouping field, so it would be an approximation."
        )
    return None


def target_field(condition: FieldCondition) -> str:
    """The assumed field name for a native reference, including its normalization."""
    field = condition.field
    if field.startswith(ATTRIBUTE_PREFIX):
        field = field[len(ATTRIBUTE_PREFIX) :]
    key, separator, path = field.partition(PATH_SEPARATOR)
    if separator:
        key = f"{key}.__all_strings" if path == ALL_STRINGS_PATH else f"{key}.{path}"
    if condition.normalize:
        key += "__" + "_".join(step.value for step in condition.normalize)
    return key


def _meaning(condition: FieldCondition) -> str:
    parts = [f"`{condition.field}`"]
    if condition.field.endswith(PATH_SEPARATOR + ALL_STRINGS_PATH):
        parts.append("as every string inside it, joined with newlines")
    if condition.normalize:
        steps = ", then ".join(step.value for step in condition.normalize)
        parts.append(f"after {steps}")
    return " ".join(parts)


def _fields(tree: Tree) -> Iterable[FieldCondition]:
    if isinstance(tree, AllCondition):
        children: list[Tree] = list(tree.all_of)
    elif isinstance(tree, AnyCondition):
        children = list(tree.any_of)
    elif isinstance(tree, NotCondition):
        children = [tree.negated]
    else:
        yield tree
        return
    for child in children:
        yield from _fields(child)


def _has_not(tree: Tree) -> bool:
    if isinstance(tree, NotCondition):
        return True
    if isinstance(tree, AllCondition):
        return any(_has_not(child) for child in tree.all_of)
    if isinstance(tree, AnyCondition):
        return any(_has_not(child) for child in tree.any_of)
    return False


def _regex_gap(pattern: str, target: str) -> str | None:
    escapes = re.findall(r"\\(.)", pattern, re.DOTALL)
    unicode_escapes = sorted(set(escapes) & UNICODE_ESCAPES)
    if unicode_escapes:
        named = ", ".join(f"\\{item}" for item in unicode_escapes)
        return (
            f"Regex uses {named}, which the engine applies to Unicode text and the target applies "
            "differently, so the same text could decide differently."
        )
    if "(?" in pattern or any(item.isdigit() for item in escapes):
        return "Regex uses a group flag, lookaround or back-reference the target may not support."
    if target == "esql":
        unsafe = sorted(set(pattern) & LUCENE_UNSAFE)
        if unsafe:
            return (
                f"Regex uses {' '.join(unsafe)}, which RLIKE's Lucene syntax rejects or reads "
                "differently, and RLIKE is always anchored."
            )
    if target == "kql" and re.search(pattern, "") is not None:
        return "Regex matches empty text, and a Kusto string has no null to tell it from missing."
    return None


def condition_gap(tree: Tree, target: str) -> str | None:
    """Why this condition tree has no faithful form in the target, or None."""
    if _has_not(tree):
        return "Negation over a field that may be absent: the targets treat a missing field apart."
    for condition in _fields(tree):
        if condition.op is Operator.EXISTS:
            if target == "kql":
                return (
                    "Field existence: a Kusto string column cannot tell an empty value from a "
                    "missing one, and the engine can."
                )
            continue
        if condition.op is Operator.EQUALS:
            if not isinstance(condition.value, str):
                return "Equality on a non-string JSON value has no converter."
            continue
        if condition.op is Operator.REGEX:
            assert isinstance(condition.value, str)
            gap = _regex_gap(condition.value, target)
            if gap:
                return gap
            continue
        return f"Operator {condition.op.value} has no converter."
    return None


def conversion_gap(rule: Rule, target: str) -> str | None:
    """Why this rule does not convert to the target, or None if it does."""
    gap = logic_gap(rule)
    if gap:
        return gap
    assert isinstance(rule.logic, MatchLogic)
    where = rule.logic.match.where
    return None if where is None else condition_gap(where, target)


def _sigma_string(value: str) -> str:
    return re.sub(r"([\\*?])", r"\\\1", value)


def _sigma_item(condition: FieldCondition) -> dict[str, object]:
    field = target_field(condition)
    if condition.op is Operator.REGEX:
        return {f"{field}|re": condition.value}
    if condition.op is Operator.EXISTS:
        return {f"{field}|exists": condition.value}
    assert isinstance(condition.value, str)
    return {f"{field}|cased": _sigma_string(condition.value)}


@dataclass
class _SigmaBuilder:
    selections: dict[str, dict[str, object]]

    def add(self, tree: Tree) -> str:
        if isinstance(tree, AllCondition):
            return "(" + " and ".join(self.add(child) for child in tree.all_of) + ")"
        if isinstance(tree, AnyCondition):
            return "(" + " or ".join(self.add(child) for child in tree.any_of) + ")"
        assert isinstance(tree, FieldCondition)
        name = f"match_{len(self.selections)}"
        self.selections[name] = _sigma_item(tree)
        return name


def _comment(prefix: str, rule: Rule, rule_sha256: str) -> str:
    lines = [
        HEADER,
        f"Label: {LABEL}.",
        f"Native rule: {rule.id} version {rule.version}, rule file sha256 {rule_sha256}.",
        "Do not edit. Regenerate with gauntlet export.",
    ]
    return "".join(f"{prefix}{line}\n" for line in lines)


def _match_of(rule: Rule) -> EventMatch:
    assert isinstance(rule.logic, MatchLogic)
    return rule.logic.match


def render_sigma(rule: Rule, rule_sha256: str) -> str:
    match = _match_of(rule)
    builder = _SigmaBuilder(
        {"selection_event": {"event_type|cased": [item.value for item in match.event_types]}}
    )
    condition = "selection_event"
    if match.where is not None:
        condition += " and " + builder.add(match.where)
    document: dict[str, object] = {
        "title": rule.title,
        "id": str(uuid.uuid5(UUID_NAMESPACE, rule.id)),
        "status": rule.status.value,
        "description": f"{rule.description} {HEADER}",
        "logsource": {"product": "ai_agent", "service": "adg_traces"},
        "detection": {**builder.selections, "condition": condition},
        "level": rule.severity.value,
    }
    if rule.mappings.attack:
        document["tags"] = [f"attack.{item.lower()}" for item in rule.mappings.attack]
    body = yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=100)
    return _comment("# ", rule, rule_sha256) + body


def _kql_string(value: str) -> str:
    return '@"' + value.replace('"', '""') + '"'


def _kql_tree(tree: Tree) -> str:
    if isinstance(tree, AllCondition):
        return "(" + " and ".join(_kql_tree(child) for child in tree.all_of) + ")"
    if isinstance(tree, AnyCondition):
        return "(" + " or ".join(_kql_tree(child) for child in tree.any_of) + ")"
    assert isinstance(tree, FieldCondition)
    field = f"['{target_field(tree)}']"
    assert isinstance(tree.value, str)
    if tree.op is Operator.REGEX:
        return f"{field} matches regex {_kql_string(tree.value)}"
    return f"{field} == {_kql_string(tree.value)}"


def render_kql(rule: Rule, rule_sha256: str) -> str:
    match = _match_of(rule)
    types = ", ".join(_kql_string(item.value) for item in match.event_types)
    lines = [KQL_TABLE, f"| where event_type in ({types})"]
    if match.where is not None:
        lines.append(f"| where {_kql_tree(match.where)}")
    return _comment("// ", rule, rule_sha256) + "\n".join(lines) + "\n"


def _quoted(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _spl_tree(tree: Tree) -> str:
    if isinstance(tree, AllCondition):
        return "(" + " AND ".join(_spl_tree(child) for child in tree.all_of) + ")"
    if isinstance(tree, AnyCondition):
        return "(" + " OR ".join(_spl_tree(child) for child in tree.any_of) + ")"
    assert isinstance(tree, FieldCondition)
    field = f"'{target_field(tree)}'"
    if tree.op is Operator.EXISTS:
        return f"isnotnull({field})" if tree.value else f"isnull({field})"
    assert isinstance(tree.value, str)
    if tree.op is Operator.REGEX:
        return f"match({field}, {_quoted(tree.value)})"
    return f"{field}=={_quoted(tree.value)}"


def render_spl(rule: Rule, rule_sha256: str) -> str:
    match = _match_of(rule)
    types = ", ".join(_quoted(item.value) for item in match.event_types)
    where = f"in('event_type', {types})"
    if match.where is not None:
        where += f" AND {_spl_tree(match.where)}"
    comment = _comment("", rule, rule_sha256)
    block = "".join(f"``` {line} ```\n" for line in comment.splitlines())
    return f"{block}search index={SPL_INDEX}\n| where {where}\n"


def _esql_tree(tree: Tree) -> str:
    if isinstance(tree, AllCondition):
        return "(" + " AND ".join(_esql_tree(child) for child in tree.all_of) + ")"
    if isinstance(tree, AnyCondition):
        return "(" + " OR ".join(_esql_tree(child) for child in tree.any_of) + ")"
    assert isinstance(tree, FieldCondition)
    field = f"`{target_field(tree)}`"
    if tree.op is Operator.EXISTS:
        return f"{field} IS NOT NULL" if tree.value else f"{field} IS NULL"
    assert isinstance(tree.value, str)
    if tree.op is Operator.REGEX:
        # RLIKE must match the whole value, and the engine searches inside it.
        return f"{field} RLIKE {_quoted('.*(' + tree.value + ').*')}"
    return f"{field} == {_quoted(tree.value)}"


def render_esql(rule: Rule, rule_sha256: str) -> str:
    match = _match_of(rule)
    types = ", ".join(_quoted(item.value) for item in match.event_types)
    where = f"event_type IN ({types})"
    if match.where is not None:
        where += f" AND {_esql_tree(match.where)}"
    return _comment("// ", rule, rule_sha256) + f"FROM {ESQL_INDEX}\n| WHERE {where}\n"


RENDERERS = {"sigma": render_sigma, "kql": render_kql, "spl": render_spl, "esql": render_esql}


def assumed_fields(rule: Rule) -> dict[str, str]:
    """Target field name to what an ingest pipeline must store in it, for one converted rule."""
    fields = {"event_type": "`event_type`, unchanged"}
    assert isinstance(rule.logic, MatchLogic)
    if rule.logic.match.where is not None:
        for condition in _fields(rule.logic.match.where):
            fields[target_field(condition)] = _meaning(condition)
    return fields
