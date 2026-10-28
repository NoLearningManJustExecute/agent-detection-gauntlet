"""Mapping ID catalogs for ATLAS, OWASP LLM, OWASP Agentic and ATT&CK.

Each catalog file lists the IDs rules may reference. The rule validator errors on IDs that are
not in a catalog and warns on entries that have not been verified against the primary source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources
from typing import Annotated

from pydantic import BaseModel, Field, StrictBool, StringConstraints, ValidationError

from agent_detection_gauntlet.errors import CatalogError
from agent_detection_gauntlet.io.jsonl import format_validation_error
from agent_detection_gauntlet.rules.loader import load_yaml_document
from agent_detection_gauntlet.rules.model import MAPPING_PATTERNS
from agent_detection_gauntlet.schema.common import STRICT_MODEL, NonEmptyStr

FAMILIES: tuple[str, ...] = ("atlas", "owasp_llm", "owasp_agentic", "attack")


class CatalogEntry(BaseModel):
    model_config = STRICT_MODEL

    id: NonEmptyStr
    name: NonEmptyStr
    url: Annotated[str, StringConstraints(pattern=r"^https://\S+$")]
    version: NonEmptyStr
    verified: StrictBool = False


class CatalogFile(BaseModel):
    model_config = STRICT_MODEL

    entries: Annotated[list[CatalogEntry], Field()]


@dataclass(frozen=True)
class Catalog:
    families: dict[str, dict[str, CatalogEntry]]

    def lookup(self, family: str, mapping_id: str) -> CatalogEntry | None:
        return self.families.get(family, {}).get(mapping_id)


def parse_catalog_file(family: str, text: str, origin: str) -> dict[str, CatalogEntry]:
    try:
        document = load_yaml_document(text, origin)
        parsed = CatalogFile.model_validate_json(document)
    except ValidationError as exc:
        raise CatalogError(f"{origin}: {format_validation_error(exc)}") from exc
    except ValueError as exc:
        raise CatalogError(f"{origin}: {exc}") from exc
    pattern = re.compile(MAPPING_PATTERNS[family])
    entries: dict[str, CatalogEntry] = {}
    for entry in parsed.entries:
        if pattern.fullmatch(entry.id) is None:
            raise CatalogError(f"{origin}: {entry.id!r} is not a valid {family} id")
        if entry.id in entries:
            raise CatalogError(f"{origin}: duplicate entry {entry.id!r}")
        entries[entry.id] = entry
    return entries


def load_catalog() -> Catalog:
    """Load the catalogs shipped with the package."""
    package = resources.files(__name__)
    families: dict[str, dict[str, CatalogEntry]] = {}
    for family in FAMILIES:
        name = f"{family}.yaml"
        text = package.joinpath(name).read_text(encoding="utf-8")
        families[family] = parse_catalog_file(family, text, f"catalog/{name}")
    return Catalog(families=families)
