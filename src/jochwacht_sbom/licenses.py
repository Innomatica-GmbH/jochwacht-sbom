"""License values, put where CycloneDX says they belong.

Ported from the suite (``jochwacht.sbom.licenses``) on 2026-10-26, in the
simpler shape this tool needs: no knowledge database, so no curated lookup —
what the build file states is either an SPDX identifier, an SPDX expression,
or wording.

Why it exists at all: this writer used to put whatever a build file stated
straight into ``license.id``. That field is validated against a closed
enumeration, so a component carrying "BSD License" — which is exactly what a
PyPI classifier yields — made the customer's whole bill invalid against the
published schema. Measured 2026-10-26 against the official 1.7 schema.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Literal, NamedTuple

import yaml

_DATA_DIR = Path(__file__).parent / "data"

#: An SPDX expression joins identifiers with these operators.
_OPERATOR = re.compile(r"\s+(or|and|with)\s+", re.IGNORECASE)

#: A bare identifier: one token, no spaces.
_BARE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")

#: Values that say "look elsewhere", not "this is the license".
_NOT_A_LICENSE = (
    "see license in",
    "see license file",
    "unknown",
    "noassertion",
)


class LicenseValue(NamedTuple):
    """A license value and the CycloneDX field it belongs in."""

    kind: Literal["id", "expression", "name"]
    value: str


@lru_cache(maxsize=1)
def _spdx_identifiers() -> dict[str, str]:
    """Every SPDX identifier, keyed by its lower-case spelling.

    SPDX matching is case-insensitive while the written value is not: a
    lockfile saying ``apache-2.0`` means ``Apache-2.0``, and only the
    canonical spelling passes the schema's enumeration.
    """
    raw = yaml.safe_load((_DATA_DIR / "spdx_license_ids.yaml").read_text(encoding="utf-8"))
    return {i.lower(): i for i in raw["identifiers"]}


def spdx_license_list_version() -> str:
    """The SPDX License List version the vendored identifiers come from."""
    raw = yaml.safe_load((_DATA_DIR / "spdx_license_ids.yaml").read_text(encoding="utf-8"))
    return str(raw["license_list_version"])


def normalize_license(raw: str | None) -> LicenseValue | None:
    """Decide where *raw* belongs, or return None when it says nothing."""
    text = (raw or "").strip()
    if not text:
        return None
    lowered = text.lower()
    if any(lowered.startswith(p) or lowered == p for p in _NOT_A_LICENSE):
        return None

    if _OPERATOR.search(text):
        return LicenseValue("expression", text)

    if _BARE_ID.match(text):
        canonical = _spdx_identifiers().get(lowered)
        if canonical is not None:
            return LicenseValue("id", canonical)

    # Wording we cannot turn into an identifier is kept as what it is.
    # Dropping it is not an option: somebody stated it.
    return LicenseValue("name", text)


def cyclonedx_licenses(raw: str | None) -> list[dict[str, object]]:
    """The CycloneDX ``licenses`` array for *raw* (empty when it says nothing)."""
    value = normalize_license(raw)
    if value is None:
        return []
    if value.kind == "expression":
        return [{"expression": value.value}]
    return [{"license": {value.kind: value.value}}]


__all__ = [
    "LicenseValue",
    "cyclonedx_licenses",
    "normalize_license",
    "spdx_license_list_version",
]
