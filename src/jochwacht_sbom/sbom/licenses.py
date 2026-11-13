"""License values, put where the format says they belong.

Measured on the production knowledge database (build 8, 14.09.2026, 50,973
entries) and in the first real customer report of the live test on
16.09.2026, where a component read ``jinja2 3.1.2 · Pallets · BSD License``:

=========================================  ======  ======
class                                       count       %
=========================================  ======  ======
a single SPDX identifier                    44,957   90.2
a valid SPDX expression, wrong field         3,318    6.7
an expression with a lower-case operator       270    0.5
a plain-text name                            1,233    2.5
not a license at all ("SEE LICENSE IN …")       80    0.2
=========================================  ======  ======

CycloneDX has three different places for these, and a checker following
BSI TR-03183 objects when the wrong one is used: ``license.id`` takes an
SPDX identifier and nothing else, ``expression`` takes a composite, and
``license.name`` takes free text that is not an identifier. SPDX 2.3 only
accepts an identifier or an expression, so free text becomes
``NOASSERTION`` there — the value stays visible in the CycloneDX output,
and nothing is invented in either.

The rule in one sentence: **write what we have into the field that fits
it, and never dress free text up as an identifier.** Dropping a value is
not an option either — "BSD License" is a statement somebody made
(``fehlende-angabe-ist-kein-wert``, read in the other direction).
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Literal, NamedTuple

import yaml

_DATA_DIR = Path(__file__).parent / "data"


@lru_cache(maxsize=1)
def _spdx_identifiers() -> dict[str, str]:
    """Every SPDX identifier, keyed by its lower-case spelling.

    The map is lower-cased on the way in because SPDX matching is
    case-insensitive while the written value is not: a lockfile saying
    ``apache-2.0`` means ``Apache-2.0``, and only the canonical spelling
    passes the CycloneDX schema's enumeration.
    """
    raw = yaml.safe_load((_DATA_DIR / "spdx_license_ids.yaml").read_text(encoding="utf-8"))
    return {i.lower(): i for i in raw["identifiers"]}


@lru_cache(maxsize=1)
def _spdx_exceptions() -> dict[str, str]:
    """Every SPDX exception identifier (right-hand side of WITH), lower-case keyed."""
    raw = yaml.safe_load((_DATA_DIR / "spdx_exception_ids.yaml").read_text(encoding="utf-8"))
    return {i.lower(): i for i in raw["exceptions"]}


#: A user-defined reference, valid in an expression without being on the list.
_LICENSE_REF = re.compile(
    r"^(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+$")
_EXPR_TOKEN = re.compile(r"\(|\)|[^\s()]+")
#: Bounds of the strict parser (sicherheit-2, Y5): deeper or longer input is no
#: expression we write; it stays free text, and the recursion is never reached.
_MAX_EXPR_DEPTH = 32
_MAX_EXPR_TOKENS = 512


def _strict_expression(text: str) -> str | None:
    """The canonical SPDX expression for *text*, or None when it is not one.

    Every license part must be a listed identifier (optionally with ``+``) or
    a ``LicenseRef-``; after WITH only a listed exception. Operators and
    identifiers are matched case-insensitively and written canonically.
    Coordination, 13.11.2026: an expression only when every part is valid;
    "GPL-3.0+ WITH exception" is free text, not an expression.
    """
    tokens = _EXPR_TOKEN.findall(text)
    if len(tokens) > _MAX_EXPR_TOKENS:
        return None
    depth = deepest = 0
    for tok in tokens:
        depth += (tok == "(") - (tok == ")")
        deepest = max(deepest, depth)
    if deepest > _MAX_EXPR_DEPTH:
        return None
    ids, exceptions = _spdx_identifiers(), _spdx_exceptions()
    out: list[str] = []
    pos = 0

    def peek() -> str:
        return tokens[pos] if pos < len(tokens) else ""

    def license_part() -> bool:
        nonlocal pos
        tok = peek()
        if not tok or tok.upper() in ("AND", "OR", "WITH") or tok in "()":
            return False
        if _LICENSE_REF.match(tok):
            out.append(tok)
        elif tok.lower() in ids:
            out.append(ids[tok.lower()])
        elif tok.endswith("+") and tok[:-1].lower() in ids:
            out.append(ids[tok[:-1].lower()] + "+")
        else:
            return False
        pos += 1
        return True

    def atom() -> bool:
        nonlocal pos
        if peek() == "(":
            out.append("(")
            pos += 1
            if not disjunction() or peek() != ")":
                return False
            out.append(")")
            pos += 1
            return True
        if not license_part():
            return False
        if peek().upper() == "WITH":
            pos += 1
            exc = peek().lower()
            if exc not in exceptions:
                return False
            out.extend(["WITH", exceptions[exc]])
            pos += 1
        return True

    def chain(inner: object, op: str) -> bool:
        nonlocal pos
        if not inner():  # type: ignore[operator]
            return False
        while peek().upper() == op:
            out.append(op)
            pos += 1
            if not inner():  # type: ignore[operator]
                return False
        return True

    def conjunction() -> bool:
        return chain(atom, "AND")

    def disjunction() -> bool:
        return chain(conjunction, "OR")

    if not tokens or not disjunction() or pos != len(tokens):
        return None
    return " ".join(out).replace("( ", "(").replace(" )", ")")


#: SPDX placeholders: "no statement", never a license (any spelling).
_PLACEHOLDERS = frozenset({"noassertion", "none"})


def spdx_license_value(raw: object) -> str | None:
    """A license statement from an SPDX field, or None when it states nothing.

    Review of sicherheit (Y1 to Y3, 13.11.2026): NOASSERTION and NONE in any
    spelling, with blanks around, and as a token inside an expression ("MIT
    AND NOASSERTION") make the value unproven. The text is otherwise returned
    as written (stripped); where it belongs is decided when it is written.
    """
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    if any(tok.casefold() in _PLACEHOLDERS for tok in _EXPR_TOKEN.findall(text)):
        return None
    return text


def spdx_package_license(element: dict[str, object]) -> str | None:
    """The license of an SPDX package: ``licenseConcluded`` when real, else
    ``licenseDeclared``. The one rule for importer, merge and reader."""
    return (spdx_license_value(element.get("licenseConcluded"))
            or spdx_license_value(element.get("licenseDeclared")))


def spdx_license_list_version() -> str:
    """The SPDX License List version the vendored identifiers come from."""
    raw = yaml.safe_load((_DATA_DIR / "spdx_license_ids.yaml").read_text(encoding="utf-8"))
    return str(raw["license_list_version"])

#: An SPDX expression joins identifiers with these operators.
_OPERATOR = re.compile(r"\s+(or|and|with)\s+", re.IGNORECASE)

#: A bare SPDX identifier: one token, no spaces (``MIT``, ``Apache-2.0``,
#: ``GPL-2.0-or-later``, the deprecated-but-valid ``GPL-1.0+``).
_BARE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")

#: Values that say "look elsewhere", not "this is the license". npm writes
#: the first one; 80 entries in the production database carry it.
_NOT_A_LICENSE = (
    "see license in",
    "see the license file",
    "other/proprietary license",
    "proprietary",
    "unknown",
    "none",
    "n/a",
    "nolicense",
)


class LicenseValue(NamedTuple):
    """Where a license value belongs, and the value itself."""

    #: ``id`` = SPDX identifier · ``expression`` = SPDX expression ·
    #: ``name`` = free text that is not an identifier.
    kind: Literal["id", "expression", "name"]
    value: str


def _normalize_operators(raw: str) -> str:
    """``MIT or Apache-2.0`` → ``MIT OR Apache-2.0``; whitespace collapsed.

    SPDX operators are upper case; 270 entries in the production database
    spell them in lower case, which makes the expression invalid.
    """
    out = _OPERATOR.sub(lambda m: f" {m.group(1).upper()} ", " ".join(raw.split()))
    return " ".join(out.split())


def normalize_license(
    raw: str | None,
    *,
    lookup: object = None,
) -> LicenseValue | None:
    """Decide where *raw* belongs, or return None when it says nothing.

    Args:
        raw: The stored value, from a lockfile or from our knowledge base.
        lookup: Optional callable ``(text) -> str | None`` resolving a
            plain-text name to an SPDX identifier — in practice the
            curated ``license_mappings`` table, which already holds 962
            entries and resolves 386 of the 1,233 plain-text values.

    Returns:
        The value with the field it belongs in, or None when the text is
        not a license statement at all.
    """
    text = (raw or "").strip()
    if not text:
        return None
    lowered = text.lower()
    if any(lowered.startswith(p) or lowered == p for p in _NOT_A_LICENSE):
        return None

    if _OPERATOR.search(text) or "(" in text:
        # An expression only when every part is valid SPDX (13.11.2026).
        strict = _strict_expression(text)
        if strict is not None:
            return LicenseValue("expression", strict)
        if _OPERATOR.search(text):
            return LicenseValue("name", " ".join(text.split()))

    if _BARE_ID.match(text):
        # Looking like an identifier is not being one. ``license.id`` is
        # validated against a closed enumeration, so "BSD" or "PSFL" would
        # make the whole document invalid rather than merely imprecise.
        canonical = _spdx_identifiers().get(text.lower())
        if canonical is not None:
            return LicenseValue("id", canonical)

    if callable(lookup):
        mapped = lookup(text)
        if isinstance(mapped, str) and mapped.strip():
            canonical = _spdx_identifiers().get(mapped.strip().lower())
            if canonical is not None:
                return LicenseValue("id", canonical)
            return LicenseValue("name", mapped.strip())

    # A statement we cannot turn into an identifier is kept as what it is.
    return LicenseValue("name", text)


def cyclonedx_licenses(
    raw: str | None, *, lookup: object = None,
) -> list[dict[str, object]]:
    """The CycloneDX ``licenses`` array for *raw* (empty when it says nothing)."""
    value = normalize_license(raw, lookup=lookup)
    if value is None:
        return []
    if value.kind == "expression":
        return [{"expression": value.value}]
    return [{"license": {value.kind: value.value}}]


def spdx_license(raw: str | None, *, lookup: object = None) -> str:
    """The SPDX 2.3 value for *raw*.

    SPDX 2.3 accepts an identifier or an expression. Free text is not
    valid there, so it becomes ``NOASSERTION`` — the CycloneDX output
    keeps the wording, and neither format carries a made-up identifier.
    """
    value = normalize_license(raw, lookup=lookup)
    if value is None or value.kind == "name":
        return "NOASSERTION"
    return value.value
