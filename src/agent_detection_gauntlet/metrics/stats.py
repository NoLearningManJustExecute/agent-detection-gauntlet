"""Rates and Wilson score intervals.

A rate with a zero denominator is undefined and reported as null, never as 0.
"""

from __future__ import annotations

import math
from statistics import NormalDist

CONFIDENCE = 0.95
Z_95 = NormalDist().inv_cdf(1 - (1 - CONFIDENCE) / 2)
DECIMALS = 6


def ratio(numerator: int, denominator: int) -> float | None:
    if numerator < 0 or denominator < 0 or numerator > denominator:
        raise ValueError(f"invalid rate {numerator}/{denominator}")
    if denominator == 0:
        return None
    return round(numerator / denominator, DECIMALS)


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> tuple[float, float] | None:
    """Wilson score interval for a binomial proportion. None when trials is zero."""
    if successes < 0 or trials < 0 or successes > trials:
        raise ValueError(f"invalid proportion {successes}/{trials}")
    if trials == 0:
        return None
    p = successes / trials
    z2 = z * z
    denominator = 1 + z2 / trials
    center = (p + z2 / (2 * trials)) / denominator
    half_width = z * math.sqrt(p * (1 - p) / trials + z2 / (4 * trials * trials)) / denominator
    lower = max(0.0, center - half_width)
    upper = min(1.0, center + half_width)
    return round(lower, DECIMALS), round(upper, DECIMALS)
