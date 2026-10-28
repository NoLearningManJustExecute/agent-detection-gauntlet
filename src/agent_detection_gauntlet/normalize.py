"""Text normalization steps shared by the rule model and the engine."""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence
from enum import StrEnum


class Normalization(StrEnum):
    CASEFOLD = "casefold"
    NFKC = "nfkc"
    COLLAPSE_WHITESPACE = "collapse_whitespace"


def normalize_text(text: str, steps: Sequence[Normalization]) -> str:
    """Apply normalization steps in the given order."""
    for step in steps:
        if step is Normalization.CASEFOLD:
            text = text.casefold()
        elif step is Normalization.NFKC:
            text = unicodedata.normalize("NFKC", text)
        else:
            text = " ".join(text.split())
    return text
