"""Shared types, patterns and helpers used by every schema in the package."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any

from pydantic import (
    AfterValidator,
    ConfigDict,
    PlainSerializer,
    PlainValidator,
    StringConstraints,
    WithJsonSchema,
)

SCHEMA_VERSION = "0.1"

# Every model is strict: no unknown keys, no type coercion, immutable after validation.
STRICT_MODEL = ConfigDict(extra="forbid", strict=True, frozen=True)

_RFC3339_UTC = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|\+00:00)"
)
RFC3339_UTC_PATTERN = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|\+00:00)$"
)


def parse_utc_timestamp(value: Any) -> datetime:
    """Accept only RFC 3339 strings in UTC (or aware UTC datetimes built in code)."""
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("timestamp must be timezone aware and in UTC")
        return value.astimezone(UTC)
    if not isinstance(value, str) or _RFC3339_UTC.fullmatch(value) is None:
        raise ValueError(
            "timestamp must be an RFC 3339 string in UTC, for example 2026-01-15T10:00:00Z"
        )
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError as exc:
        raise ValueError(f"timestamp is not a valid date and time: {exc}") from exc


def format_utc_timestamp(value: datetime) -> str:
    """Render a UTC datetime as RFC 3339 with a Z suffix. Deterministic for equal inputs."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


UtcTimestamp = Annotated[
    datetime,
    PlainValidator(parse_utc_timestamp),
    PlainSerializer(format_utc_timestamp, return_type=str),
    WithJsonSchema({"type": "string", "format": "date-time", "pattern": RFC3339_UTC_PATTERN}),
]


def _reject_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be empty or whitespace only")
    return value


NonEmptyStr = Annotated[str, StringConstraints(min_length=1), AfterValidator(_reject_blank)]

IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
Identifier = Annotated[str, StringConstraints(pattern=IDENTIFIER_PATTERN)]

RULE_ID_PATTERN = r"^ADG-[0-9]{4}$"
RuleId = Annotated[str, StringConstraints(pattern=RULE_ID_PATTERN)]

SEMVER_PATTERN = (
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$"
)
SemVer = Annotated[str, StringConstraints(pattern=SEMVER_PATTERN)]


def unique_items[T](values: list[T]) -> list[T]:
    """Reject lists that repeat a value. Used as an AfterValidator."""
    seen: list[T] = []
    for value in values:
        if value in seen:
            raise ValueError(f"duplicate value {value!r}")
        seen.append(value)
    return values


class Tier(StrEnum):
    CONTENT = "content"
    SEQUENCE = "sequence"
    BEHAVIOR = "behavior"


TIER_ORDER: tuple[Tier, ...] = (Tier.CONTENT, Tier.SEQUENCE, Tier.BEHAVIOR)


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
