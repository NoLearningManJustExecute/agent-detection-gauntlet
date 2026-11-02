"""Style and completeness checks on native rules, on top of what the validator enforces.

The validator already fails on a malformed id or version, an empty limitations list, a mapping the
catalog lacks and a fixture that does not exist. These checks cover what the model lets through.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from agent_detection_gauntlet.rules.loader import LoadedRule
from agent_detection_gauntlet.rules.model import Rule

TITLE_MAX = 80
MIN_SENTENCE = 20
DASHES = (chr(0x2013), chr(0x2014))


@dataclass(frozen=True)
class LintIssue:
    rule_id: str
    message: str

    def render(self) -> str:
        return f"{self.rule_id}: {self.message}"


def _sentence(name: str, text: str) -> list[str]:
    problems: list[str] = []
    if len(text.strip()) < MIN_SENTENCE:
        problems.append(f"{name} is too short to say anything")
    if not text.rstrip().endswith("."):
        problems.append(f"{name} does not end with a period")
    return problems


def lint_rule(rule: Rule) -> list[str]:
    problems: list[str] = []
    if len(rule.title) > TITLE_MAX:
        problems.append(f"title is longer than {TITLE_MAX} characters")
    if rule.title.rstrip().endswith("."):
        problems.append("title ends with a period")
    problems += _sentence("description", rule.description)
    problems += _sentence("hypothesis", rule.hypothesis)
    for index, limitation in enumerate(rule.limitations):
        problems += _sentence(f"limitation {index + 1}", limitation)
    if not rule.mappings.atlas:
        problems.append("no ATLAS mapping: ATLAS comes first in this project")
    if not rule.mappings.owasp_llm and not rule.mappings.owasp_agentic:
        problems.append("no OWASP mapping")
    texts = [rule.title, rule.description, rule.hypothesis, *rule.limitations]
    if any(dash in text for text in texts for dash in DASHES):
        problems.append("holds an em or en dash")
    return problems


def lint_rules(rules: Sequence[LoadedRule]) -> list[LintIssue]:
    return [LintIssue(item.rule.id, message) for item in rules for message in lint_rule(item.rule)]
