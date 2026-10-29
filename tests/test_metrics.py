from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest

from agent_detection_gauntlet.errors import MetricsInputError
from agent_detection_gauntlet.metrics.compute import (
    ScoringInputs,
    build_report,
    check_detections_reproduce,
    compute_metrics,
    compute_rates,
    describe_inputs,
    git_provenance,
    make_rate,
)
from agent_detection_gauntlet.metrics.report import Confusion, InputFile
from agent_detection_gauntlet.metrics.stats import Z_95, ratio, wilson_interval
from agent_detection_gauntlet.paths import set_repo_root
from agent_detection_gauntlet.schema.detection import Detection
from agent_detection_gauntlet.schema.labels import LabelRecord, Split
from tests.conftest import make_rule


def label(
    trace_id: str, verdict: str, succeeded: bool | None = None, split: str = "heldout"
) -> LabelRecord:
    return LabelRecord.model_validate_json(
        json.dumps(
            {
                "schema_version": "0.1",
                "trace_id": trace_id,
                "label": verdict,
                "attack_class": "ipi" if verdict == "malicious" else None,
                "attack_succeeded": succeeded,
                "mutation": None,
                "guardrails": "off",
                "split": split,
                "source": "synthetic",
            }
        )
    )


def detection(trace_id: str, rule_id: str = "ADG-9001", version: str = "1.0.0") -> Detection:
    return Detection.model_validate_json(
        json.dumps(
            {
                "schema_version": "0.1",
                "rule_id": rule_id,
                "rule_version": version,
                "trace_id": trace_id,
                "tier": "sequence",
                "severity": "high",
                "matched_span_ids": ["s1"],
                "first_timestamp": "2026-01-15T09:00:00Z",
                "last_timestamp": "2026-01-15T09:00:00Z",
            }
        )
    )


# Hand-built heldout population:
#   m1..m4 malicious succeeded, m5 and m6 attack_failed, b1..b5 benign, d1 dev (ignored).
LABELS = {
    **{f"m{i}": label(f"m{i}", "malicious", True) for i in range(1, 5)},
    "m5": label("m5", "malicious", False),
    "m6": label("m6", "malicious", False),
    **{f"b{i}": label(f"b{i}", "benign") for i in range(1, 6)},
    "d1": label("d1", "malicious", True, split="dev"),
}
TRACES = sorted(LABELS)

RULE_A = make_rule(id="ADG-9001")
RULE_B = make_rule(id="ADG-9002")
RULE_C = make_rule(id="ADG-9003", tier="content")

# Rule A hits m1, m2, m3 (TP=3, FN=1), b1 (FP=1, TN=4), m5 (attack_failed detected), d1 (dev).
# Rule B hits m4 and b2. Sequence tier = A or B. Rule C hits nothing.
DETECTIONS = [
    *(detection(t) for t in ("m1", "m2", "m3", "b1", "m5", "d1")),
    *(detection(t, "ADG-9002") for t in ("m4", "b2")),
]


def inputs(**overrides: Any) -> ScoringInputs:
    base: dict[str, Any] = {
        "rules": [RULE_A, RULE_B, RULE_C],
        "trace_ids": TRACES,
        "labels": LABELS,
        "detections": DETECTIONS,
        "split": Split.HELDOUT,
    }
    base.update(overrides)
    return ScoringInputs(**base)


def test_hand_computed_confusion_matrix() -> None:
    population, per_rule, per_tier = compute_metrics(inputs())
    assert population.model_dump() == {
        "traces": 11,
        "benign": 5,
        "malicious_succeeded": 4,
        "attack_failed": 2,
    }
    rule_a = per_rule[0]
    assert rule_a.rule_id == "ADG-9001"
    assert rule_a.confusion.model_dump() == {"tp": 3, "fp": 1, "tn": 4, "fn": 1}
    assert rule_a.attack_failed.model_dump() == {"count": 2, "detected": 1}
    rates = rule_a.rates
    assert (rates.precision.numerator, rates.precision.denominator) == (3, 4)
    assert rates.precision.value == 0.75
    assert (rates.recall.numerator, rates.recall.denominator) == (3, 4)
    assert (rates.f1.numerator, rates.f1.denominator, rates.f1.value) == (6, 8, 0.75)
    assert rates.f1.ci95 is None
    assert (rates.fpr.numerator, rates.fpr.denominator, rates.fpr.value) == (1, 5, 0.2)
    assert rates.detection_rate == rates.recall

    tiers = {tier.tier.value: tier for tier in per_tier}
    assert list(tiers) == ["content", "sequence"]
    assert tiers["sequence"].rule_ids == ["ADG-9001", "ADG-9002"]
    assert tiers["sequence"].confusion.model_dump() == {"tp": 4, "fp": 2, "tn": 3, "fn": 0}
    assert tiers["content"].confusion.model_dump() == {"tp": 0, "fp": 0, "tn": 5, "fn": 4}
    content = tiers["content"].rates
    assert content.precision.value is None
    assert content.precision.ci95 is None
    assert content.precision.denominator == 0
    assert content.recall.value == 0.0


def test_dev_split_is_scored_separately() -> None:
    population, per_rule, _ = compute_metrics(inputs(split=Split.DEV))
    assert population.traces == 1
    assert per_rule[0].confusion.model_dump() == {"tp": 1, "fp": 0, "tn": 0, "fn": 0}


def test_zero_denominators_are_null_not_zero() -> None:
    rates = compute_rates(Confusion(tp=0, fp=0, tn=0, fn=0))
    for name in ("precision", "recall", "f1", "fpr", "detection_rate"):
        rate = getattr(rates, name)
        assert rate.value is None
        assert rate.ci95 is None
        assert (rate.numerator, rate.denominator) == (0, 0)


def test_ratio_and_validation() -> None:
    assert ratio(1, 3) == 0.333333
    assert ratio(0, 0) is None
    with pytest.raises(ValueError):
        ratio(2, 1)
    with pytest.raises(ValueError):
        wilson_interval(-1, 2)


@pytest.mark.parametrize(
    ("successes", "trials", "lower", "upper"),
    [
        (0, 10, 0.0, 0.2775),
        (10, 10, 0.7225, 1.0),
        (5, 10, 0.2366, 0.7634),
        (1, 2, 0.0945, 0.9055),
        (3, 4, 0.3006, 0.9544),
    ],
)
def test_wilson_bounds(successes: int, trials: int, lower: float, upper: float) -> None:
    # Reference values to four decimals; the score-test inversion below checks more digits.
    interval = wilson_interval(successes, trials)
    assert interval is not None
    assert interval == pytest.approx((lower, upper), abs=1e-4)


@pytest.mark.parametrize(("successes", "trials"), [(1, 3), (7, 9), (81, 263), (0, 1)])
def test_wilson_matches_score_test_inversion(successes: int, trials: int) -> None:
    # Independent derivation: the bounds are the roots in p of (phat - p)^2 = z^2 p (1 - p) / n.
    phat, n, z2 = successes / trials, trials, Z_95 * Z_95
    a = 1 + z2 / n
    b = -(2 * phat + z2 / n)
    c = phat * phat
    root = math.sqrt(b * b - 4 * a * c)
    expected = ((-b - root) / (2 * a), (-b + root) / (2 * a))
    assert wilson_interval(successes, trials) == pytest.approx(expected, abs=1e-6)


def test_wilson_matches_closed_form_and_is_none_for_empty() -> None:
    assert wilson_interval(0, 0) is None
    assert math.isclose(Z_95, 1.959963984540054, rel_tol=1e-12)
    rate = make_rate(3, 4)
    assert rate.ci95 is not None
    assert rate.ci95.lower <= 0.75 <= rate.ci95.upper


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"trace_ids": [*TRACES, "x9"]}, "traces without a label"),
        ({"trace_ids": [t for t in TRACES if t != "b5"]}, "not supplied: \\['b5'\\]"),
        ({"rules": [RULE_A, RULE_A]}, "duplicate rule ids"),
        ({"detections": [detection("m1", "ADG-9999")]}, "unknown rule ADG-9999"),
        ({"detections": [detection("m1", version="2.0.0")]}, "has version 2.0.0"),
        (
            {
                "detections": [detection("x9")],
                "labels": {**LABELS, "x9": label("x9", "benign", split="dev")},
            },
            "trace 'x9' not supplied",
        ),
    ],
)
def test_inputs_must_line_up(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(MetricsInputError, match=message):
        compute_metrics(inputs(**overrides))


def test_unassigned_split_fails_closed() -> None:
    unassigned = {**label("u1", "benign").model_dump(mode="json"), "schema_version": "0.2"}
    unassigned["split"] = None
    record = LabelRecord.model_validate_json(json.dumps(unassigned))
    assert record.split is None
    with pytest.raises(MetricsInputError, match=r"without a split \(not frozen yet\): \['u1'\]"):
        compute_metrics(inputs(labels={**LABELS, "u1": record}, trace_ids=[*TRACES, "u1"]))


def test_missing_dev_traces_are_allowed_when_scoring_heldout() -> None:
    population, _, _ = compute_metrics(
        inputs(trace_ids=[t for t in TRACES if t != "d1"], detections=DETECTIONS[:5])
    )
    assert population.traces == 11


def test_build_report_records_inputs_and_rules(tmp_path: Path) -> None:
    set_repo_root(tmp_path)
    a = tmp_path / "b.jsonl"
    a.write_bytes(b"x")
    b = tmp_path / "a.yaml"
    b.write_bytes(b"")
    report = build_report(inputs(), [("trace", a), ("rule", b), ("trace", a)])
    assert [(f.role, Path(f.path).name) for f in report.inputs] == [
        ("rule", "a.yaml"),
        ("trace", "b.jsonl"),
    ]
    assert report.inputs[0].sha256 == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert [rule.id for rule in report.rules] == ["ADG-9001", "ADG-9002", "ADG-9003"]
    assert report.split is Split.HELDOUT
    assert report.provenance.package_version == "0.1.0"


def test_git_provenance_handles_missing_git(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise OSError("no git")

    monkeypatch.setattr("agent_detection_gauntlet.metrics.compute.subprocess.run", fail)
    assert git_provenance() == (None, None)


def test_git_provenance_in_checkout() -> None:
    commit, dirty = git_provenance()
    if commit is None:
        pytest.skip("not running from a git checkout")
    assert len(commit) == 40
    assert isinstance(dirty, bool)


def test_heldout_rule_fixtures_fail_closed() -> None:
    leaky = {**LABELS, "t-fp": label("t-fp", "benign")}
    with pytest.raises(MetricsInputError, match=r"must not be heldout traces: \['ADG-9001:t-fp'"):
        compute_metrics(inputs(labels=leaky, trace_ids=[*TRACES, "t-fp"]))
    dev_only = {**LABELS, "t-fp": label("t-fp", "benign", split="dev")}
    population, _, _ = compute_metrics(inputs(labels=dev_only, trace_ids=[*TRACES, "t-fp"]))
    assert population.traces == 11


def test_detections_must_reproduce_the_scan() -> None:
    expected = [detection("m1"), detection("m2")]
    check_detections_reproduce(list(expected), expected)
    for loaded, missing, unexpected in (
        ([], 2, 0),
        ([detection("m1")], 1, 0),
        ([detection("m1"), detection("m2"), detection("b1")], 0, 1),
        (list(reversed(expected)), 0, 0),
    ):
        with pytest.raises(
            MetricsInputError, match=rf"{missing} detection\(s\) missing, {unexpected} unexpected"
        ):
            check_detections_reproduce(loaded, expected)


def test_input_paths_are_relative_to_repository_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "x.jsonl").write_bytes(b"")
    monkeypatch.chdir(root / "sub")
    entries = describe_inputs(
        [
            ("trace", Path("x.jsonl")),
            ("trace", Path("../sub/./x.jsonl")),
            ("trace", root / "sub" / "x.jsonl"),
        ],
        root=root,
    )
    assert [(entry.path, entry.external) for entry in entries] == [("sub/x.jsonl", False)]


def test_inputs_outside_the_root_fail_closed_unless_external(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "elsewhere" / "labels.jsonl"
    outside.parent.mkdir()
    outside.write_bytes(b"x")
    with pytest.raises(MetricsInputError, match="outside the repository root") as caught:
        describe_inputs([("labels", outside)], root=root)
    assert str(tmp_path) not in str(caught.value)
    assert tmp_path.as_posix() not in str(caught.value)
    assert "<outside repo>/labels.jsonl" in str(caught.value)

    [entry] = describe_inputs([("labels", outside)], root=root, external_basename=True)
    assert (entry.path, entry.external) == ("labels.jsonl", True)
    assert entry.sha256 == "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"

    twin = tmp_path / "other" / "labels.jsonl"
    twin.parent.mkdir()
    twin.write_bytes(b"y")
    with pytest.raises(MetricsInputError, match=r"would both be recorded as 'labels\.jsonl'"):
        describe_inputs([("labels", outside), ("labels", twin)], root=root, external_basename=True)


@pytest.mark.parametrize(
    ("path", "external"),
    [
        ("/abs/x.jsonl", False),
        ("C" + ":/x.jsonl", False),
        ("c" + ":x.jsonl", False),
        ("a" + chr(92) + "b.jsonl", False),
        ("../x.jsonl", False),
        ("a//b.jsonl", False),
        ("./x.jsonl", False),
        ("", False),
        ("sub/x.jsonl", True),
    ],
)
def test_report_paths_must_be_repository_relative(path: str, external: bool) -> None:
    with pytest.raises(ValueError):
        InputFile.model_validate(
            {"role": "trace", "path": path, "external": external, "sha256": "0" * 64}
        )
