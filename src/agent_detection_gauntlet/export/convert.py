"""Decide what converts, and render it. Anything that would be an approximation is refused.

A rule converts to a format only if the target can state the same test on the same data. The field
mapping is an assumption about a hypothetical schema, and it carries what a query language cannot
do at search time: normalization and "every string in the arguments" become fields an ingest
pipeline must compute exactly as docs/rule-format.md defines them. Everything else has to hold in
the target's own semantics, so a rule is listed as not converted with its reason otherwise.

Regexes pass an allowlist, not a denylist: a construct this module has not reasoned about is
refused, including one no rule uses today.
"""

from __future__ import annotations

import re
import string
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

import yaml

from agent_detection_gauntlet.normalize import normalize_text
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
SIGMA_REGEX_NOTE = (
    "Regexes assume an unanchored search in PCRE style. A backend that anchors them or uses "
    "Lucene syntax is not faithful."
)
FORMATS: Mapping[str, str] = {"sigma": "yml", "kql": "kql", "spl": "spl", "esql": "esql"}
UUID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "agent-detection-gauntlet/rules")
KQL_TABLE = "AdgTraces"
SPL_INDEX = "adg_traces"
ESQL_INDEX = "adg-traces"

Tree = AllCondition | AnyCondition | NotCondition | FieldCondition

# Python's re applies these to Unicode text. Each target defines them its own way, so the same
# pattern can decide differently on the same text.
UNICODE_ESCAPES = frozenset("bBwWdDsSAZ")
ESCAPABLE = frozenset("\\./[](){}+*?|^$-")
META = frozenset("\\^$.|?*+()[]{}")
PRINTABLE = frozenset(chr(code) for code in range(0x20, 0x7F))
LITERAL = PRINTABLE - META
ALNUM = frozenset(string.ascii_letters + string.digits)
# In a character class these start a set operator in some targets, or are syntax in others.
CLASS_REFUSED = frozenset("[&~|^")
# ES|QL RLIKE takes Lucene syntax: always anchored, where these are operators or are absent.
LUCENE_UNSAFE = frozenset('^<>@#&~"')
SAFE_NAME = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*")
RESERVED_FIELDS = frozenset({"event_type", "span_id", "parent_span_id"})
UNCLAIMED = "this converter does not claim holds the same in the target"


def logic_gap(rule: Rule) -> str | None:
    """Why this rule's logic does not convert to any of the formats, or None for a single event."""
    logic = rule.logic
    if isinstance(logic, BaselineLogic):
        return (
            "Baseline statistic fitted on dev benign traces. Fitted rules stay native by policy: "
            "the value comes from the engine's fit, and no query form of it has been checked."
        )
    if isinstance(logic, ThresholdLogic):
        return (
            "Counts over a whole trace with no time bound. A Sigma correlation needs a timespan, "
            "and no query form of the count has been checked as exact."
        )
    if isinstance(logic, SequenceLogic):
        steps = logic.sequence.steps
        if any(step.first_occurrence for step in steps):
            return (
                "Sequence with first_occurrence: it needs per-trace memory of which tool values "
                "came before, with no faithful form in these formats."
            )
        if any(step.bind or step.require for step in steps):
            return (
                "Sequence with bind (taint): it follows content references across events, with "
                "no faithful form in these formats."
            )
        return (
            "Ordered steps within one trace, with no time bound. A Sigma temporal correlation "
            "needs a timespan, and no query form has been checked to search steps as the engine "
            "does, so any of them would be an approximation."
        )
    return None


def target_field(condition: FieldCondition) -> str:
    """The assumed field name. A double underscore only ever marks a derived part."""
    field = condition.field
    if field.startswith(ATTRIBUTE_PREFIX):
        field = field[len(ATTRIBUTE_PREFIX) :]
    key, separator, path = field.partition(PATH_SEPARATOR)
    if separator:
        key += "__all_strings" if path == ALL_STRINGS_PATH else f"__at__{path}"
    if condition.normalize:
        key += "__" + "_".join(step.value for step in condition.normalize)
    return key


def _field_gap(condition: FieldCondition) -> str | None:
    field = condition.field
    if not field.startswith(ATTRIBUTE_PREFIX):
        return None
    key, separator, path = field[len(ATTRIBUTE_PREFIX) :].partition(PATH_SEPARATOR)
    names = [key] if not separator or path == ALL_STRINGS_PATH else [key, path]
    if key in RESERVED_FIELDS:
        return f"Attribute {key} would collide with the event field of that name."
    for name in names:
        if SAFE_NAME.fullmatch(name) is None or "__" in name:
            return f"Field name {name} is not safe to use as an unescaped target field."
    return None


def _meaning(condition: FieldCondition) -> str:
    parts = [f"`{condition.field}`"]
    if condition.field.endswith(PATH_SEPARATOR + ALL_STRINGS_PATH):
        parts.append("as every string inside it, joined with newlines")
    if condition.normalize:
        steps = ", then ".join(step.value for step in condition.normalize)
        parts.append(f"after {steps}")
    if condition.op is Operator.EXISTS:
        parts.append("(any non-null value; null is absent, an empty string is present)")
    else:
        parts.append("(strings only; absent if missing, null or not a string)")
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


def _class_gap(pattern: str, start: int) -> tuple[str | None, int]:
    """Check a character class opening at ``start``. Returns a gap and the index after it."""
    index = start + 1
    while pattern[index] != "]":
        char = pattern[index]
        if char == "\\":
            if pattern[index + 1] not in ESCAPABLE:
                return f"Regex uses \\{pattern[index + 1]} in a class, which {UNCLAIMED}.", index
            index += 2
            continue
        if char in CLASS_REFUSED or char not in PRINTABLE:
            return f"Regex uses {char} in a character class, which {UNCLAIMED}.", index
        if char == "-" and pattern[index + 1] != "]":
            before, after = pattern[index - 1], pattern[index + 1]
            if before not in ALNUM or after not in ALNUM:
                return f"Regex uses a range in a class that {UNCLAIMED}.", index
        index += 1
    return None, index + 1


def _repeat_end(pattern: str, index: int) -> int | None:
    """The index after the repeat at ``index``, or None when its form is not allowed."""
    if pattern[index] == "{":
        bounded = re.compile(r"\{\d+(?:,\d*)?\}").match(pattern, index)
        if bounded is None:
            return None
        end = bounded.end()
    else:
        end = index + 1
    # A trailing ? or + is lazy or possessive, and not every target has those.
    return None if pattern[end : end + 1] in ("?", "+") else end


def regex_shape_gap(pattern: str) -> str | None:
    """Refuse anything but literals, ASCII classes, greedy repeats, groups, | and a leading ^."""
    index = 0
    at_start = True
    while index < len(pattern):
        char = pattern[index]
        next_start = False
        if char == "\\":
            escaped = pattern[index + 1]
            if escaped in UNICODE_ESCAPES:
                return (
                    f"Regex uses \\{escaped}, which the engine applies to Unicode text and each "
                    "target defines its own way, so the same text could decide differently."
                )
            if escaped.isdigit():
                return "Regex uses a back-reference the target may not support."
            if escaped not in ESCAPABLE:
                return f"Regex uses \\{escaped}, which {UNCLAIMED}."
            index += 2
        elif char == "(":
            if pattern[index + 1 : index + 2] == "?":
                return "Regex uses a group flag or lookaround the target may not support."
            next_start = True
            index += 1
        elif char == "|":
            next_start = True
            index += 1
        elif char == ")":
            index += 1
        elif char == "^":
            if not at_start:
                return f"Regex uses ^ inside a branch, which {UNCLAIMED}."
            index += 1
        elif char == "[":
            if pattern[index + 1] == "^":
                return f"Regex uses a negated class, which {UNCLAIMED} on all Unicode text."
            gap, index = _class_gap(pattern, index)
            if gap:
                return gap
        elif char in "*+?{":
            end = _repeat_end(pattern, index)
            if end is None:
                return f"Regex uses a repeat form that {UNCLAIMED}."
            index = end
        elif char in LITERAL:
            index += 1
        else:
            return f"Regex uses {char!r}, which {UNCLAIMED}."
        at_start = next_start
    return None


def _regex_gap(condition: FieldCondition, target: str) -> str | None:
    assert isinstance(condition.value, str)
    pattern = condition.value
    gap = regex_shape_gap(pattern)
    if gap:
        return gap
    if target == "esql":
        unsafe = sorted(set(pattern) & LUCENE_UNSAFE)
        if unsafe:
            return (
                f"Regex uses {' '.join(unsafe)}, which RLIKE's Lucene syntax rejects or reads "
                "differently."
            )
        steps = [step.value for step in condition.normalize]
        if "collapse_whitespace" not in steps:
            return (
                "RLIKE is anchored, so the search is wrapped in .*, and how its dot treats a "
                "newline is unchecked. Only a field with collapsed whitespace avoids the question."
            )
    if target == "kql" and re.search(pattern, "") is not None:
        return "Regex matches empty text, and a Kusto string has no null to tell it from missing."
    return None


def condition_gap(tree: Tree, target: str) -> str | None:
    """Why this condition tree has no faithful form in the target, or None."""
    if _has_not(tree):
        return "Negation over a field that may be absent: the targets treat a missing field apart."
    meanings: dict[str, str] = {}
    for condition in _fields(tree):
        field_gap = _field_gap(condition)
        if field_gap:
            return field_gap
        name, meaning = target_field(condition), _meaning(condition)
        if meanings.setdefault(name, meaning) != meaning:
            return f"Field {name} would have to hold two different things."
        if condition.op is Operator.EXISTS:
            if target == "kql":
                return (
                    "Field existence: a Kusto string column cannot tell an empty value from a "
                    "missing one, and the engine can."
                )
        elif condition.op is Operator.EQUALS:
            if not isinstance(condition.value, str):
                return "Equality on a non-string JSON value has no converter."
            if not condition.value:
                return "Equality with empty text: a missing field can read as empty in the target."
            if normalize_text(condition.value, condition.normalize) != condition.value:
                return "Equality value changes under its normalization, as the engine compares it."
        elif condition.op is Operator.REGEX:
            gap = _regex_gap(condition, target)
            if gap:
                return gap
        else:
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


def assumed_fields(rule: Rule) -> dict[str, str]:
    """Target field name to what an ingest pipeline must store in it, for one converted rule."""
    fields = {"event_type": "`event_type`, unchanged"}
    assert isinstance(rule.logic, MatchLogic)
    if rule.logic.match.where is not None:
        for condition in _fields(rule.logic.match.where):
            fields[target_field(condition)] = _meaning(condition)
    return fields


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


def _comment(prefix: str, rule: Rule, rule_sha256: str, *extra: str) -> str:
    required = ", ".join(sorted(assumed_fields(rule)))
    lines = [
        HEADER,
        f"Label: {LABEL}.",
        f"Native rule: {rule.id} version {rule.version}, rule file sha256 {rule_sha256}.",
        f"Required fields, computed at ingest as FIELD_MAPPINGS.md defines them: {required}.",
        *extra,
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
    return _comment("# ", rule, rule_sha256, SIGMA_REGEX_NOTE) + body


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
