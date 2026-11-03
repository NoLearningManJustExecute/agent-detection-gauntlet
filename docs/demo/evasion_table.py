"""Print the guardrails-off recall table from results/evasion/evasion.json.

Reads the committed results only. Every number comes from the JSON; this script computes nothing.
"""

import json
from pathlib import Path
from typing import Any

RESULTS = Path("results/evasion/evasion.json")
TIERS = ("content", "sequence", "behavior", "all_tiers")
COLUMN = 15


def fraction(rate: dict[str, Any]) -> str:
    counts = f"{rate['numerator']}/{rate['denominator']}"
    return counts if rate["value"] is not None else f"null ({counts})"


def tier_rows(section: dict[str, Any]) -> dict[str, dict[str, Any]]:
    arm = next(arm for arm in section["arms"] if arm["guardrails"] == "off")
    table = arm["table"]
    rows = {row["name"]: row for row in table["per_tier"]}
    rows["all_tiers"] = table["all_tiers"]
    return rows


def cell(row: dict[str, Any]) -> str:
    paired = row["paired"]
    if paired["mutated"]["value"] is None:
        return fraction(paired["mutated"])
    return f"{fraction(paired['mutated'])} ({fraction(paired['baseline'])})"


def main() -> None:
    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    sections = [item for item in results["sections"] if item["category"] == "payload_mutation"]

    print(
        "Recall on attacks that still succeeded, guardrails off: mutated (same attacks, unmutated)"
    )
    print(
        "null (0/0) means no attack succeeded under that mutation, so there is no recall to read."
    )
    print()
    print(f"{'mutation':<24}" + "".join(f"{tier:<{COLUMN}}" for tier in TIERS))
    for section in sections:
        rows = tier_rows(section)
        print(f"{section['name']:<24}" + "".join(f"{cell(rows[tier]):<{COLUMN}}" for tier in TIERS))

    pooled = tier_rows(next(item for item in sections if item["pooled"]))
    print()
    print("Pooled change, mutated minus unmutated, with its 95% group interval:")
    for tier in TIERS:
        paired = pooled[tier]["paired"]
        if paired["delta"] is None:
            print(f"  {tier:<10} null")
            continue
        lower, upper = paired["ci95"]["lower"], paired["ci95"]["upper"]
        print(f"  {tier:<10} {paired['delta']:+.3f} [{lower:+.3f}, {upper:+.3f}]")


if __name__ == "__main__":
    main()
