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


def spdx_expression(raw: object) -> str | None:
    """The canonical SPDX identifier or expression for *raw*, or None.

    The strict rule (every part a listed identifier or ``LicenseRef-``,
    after WITH a listed exception). For BSI TR-03183-2 §6.1: a license MUST
    be named by an SPDX identifier or expression; free text cannot replace
    it (review sicherheit-2, L1, 14.11.2026). A placeholder is None.
    """
    text = spdx_license_value(raw)
    return _strict_expression(text) if text is not None else None


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
    "noassertion",  # the SPDX placeholder (sicherheit-2 on collector 9bbb255)
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
            return LicenseValue("expression", _current_ids(strict))
        if _OPERATOR.search(text):
            return LicenseValue("name", " ".join(text.split()))

    if _LICENSE_REF.match(text):
        # A user-defined reference alone is a valid SPDX expression
        # (yocto-lizenz-pkgdata, 14.11.2026); ``license.id`` cannot hold it,
        # free text would make it red.
        return LicenseValue("expression", text)

    if _BARE_ID.match(text):
        # Looking like an identifier is not being one. ``license.id`` is
        # validated against a closed enumeration, so "BSD" or "PSFL" would
        # make the whole document invalid rather than merely imprecise.
        canonical = _spdx_identifiers().get(text.lower())
        if canonical is not None:
            return LicenseValue("id", _current_ids(canonical))

    if callable(lookup):
        mapped = lookup(text)
        if isinstance(mapped, str) and mapped.strip():
            canonical = _spdx_identifiers().get(mapped.strip().lower())
            if canonical is not None:
                return LicenseValue("id", _current_ids(canonical))
            return LicenseValue("name", mapped.strip())

    # A statement we cannot turn into an identifier is kept as what it is.
    return LicenseValue("name", text)


def _current_ids(value: str) -> str:
    """*value* (an SPDX id or a strict expression) with each deprecated id that has
    one current id of the identical full name replaced by it (GPL-2.0 ->
    GPL-2.0-only, GPL-2.0+ -> GPL-2.0-or-later; data/spdx_deprecated_replacements.yaml,
    the SPDX list itself). A deprecated id without such a replacement (AGPL-3.0)
    is left as it is: its scope is not stated, never guessed (coordination,
    14.11.2026: our own enrichment must not turn a customer's SBOM yellow)."""
    replacement = _deprecated_replacements()
    return " ".join(replacement.get(tok, tok) for tok in _EXPR_TOKEN.findall(value)) \
        .replace("( ", "(").replace(" )", ")")


def cyclonedx_licenses(
    raw: str | None, *, lookup: object = None, as_text: bool = False,
) -> list[dict[str, object]]:
    """The CycloneDX ``licenses`` array for *raw* (empty when it says nothing).

    *as_text*: the caller knows *raw* is free text (a Yocto value no tier of
    TR-03183-2 §6.1 resolves): written as ``license.name``, never as an
    identifier, even when it looks like one (a deprecated ``GPL-2.0``).
    """
    if as_text:
        text = " ".join((raw or "").split())
        return [{"license": {"name": text}}] if text else []
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


# ---------------------------------------------------------------------------
# Yocto: the LICENSE value of a build, in the order of TR-03183-2 §6.1
# ---------------------------------------------------------------------------

#: Yocto's LICENSE syntax (bitbake oe.license): ``&`` and ``|`` with
#: parentheses; ``&`` binds tighter, as AND does in SPDX.
_YOCTO_TOKEN = re.compile(r"[()&|]|[^\s()&|]+")
#: create-spdx writes a name off the SPDX list as a LicenseRef, sometimes
#: through the recipe's document: the name is the part after LicenseRef-.
_YOCTO_REF = re.compile(r"^(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-(.+)$")
#: Characters outside the SPDX idstring, replaced in a LicenseRef.
_REF_UNSAFE = re.compile(r"[^A-Za-z0-9.-]+")
#: Namespace of the third tier: a name of OpenEmbedded's licence inventory
#: (poky meta/files/common-licenses), never a customer's own licence.
YOCTO_REF_PREFIX = "LicenseRef-openembedded-"


@lru_cache(maxsize=1)
def _spdx_deprecated() -> frozenset[str]:
    """The deprecated SPDX identifiers of the vendored list (canonical spelling)."""
    raw = yaml.safe_load((_DATA_DIR / "spdx_license_ids.yaml").read_text(encoding="utf-8"))
    return frozenset(raw.get("deprecated") or ())


@lru_cache(maxsize=1)
def _scancode_refs() -> frozenset[str]:
    raw = yaml.safe_load(
        (_DATA_DIR / "scancode_license_refs.yaml").read_text(encoding="utf-8"))
    return frozenset(str(v) for v in raw["refs"].values())


@lru_cache(maxsize=1)
def openembedded_license_names() -> frozenset[str]:
    """The names of poky's common-licenses (data/openembedded_common_licenses.yaml),
    empty while the list is not checked in: then no name reaches tier 3."""
    path = _DATA_DIR / "openembedded_common_licenses.yaml"
    if not path.is_file():
        return frozenset()
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return frozenset(str(n) for n in (raw.get("names") or {}))


def openembedded_ref(name: str) -> str:
    """``LicenseRef-openembedded-<name>``, characters outside the idstring -> ``-``."""
    return YOCTO_REF_PREFIX + _REF_UNSAFE.sub("-", name).strip("-")


def _current_expression(value: str) -> str | None:
    """*value* as a strict SPDX expression without a deprecated identifier."""
    strict = _strict_expression(value)
    if strict is None:
        return None
    deprecated = {d.lower() for d in _spdx_deprecated()}
    for tok in _EXPR_TOKEN.findall(strict):
        if tok.rstrip("+").lower() in deprecated or tok.lower() in deprecated:
            return None
    return strict


@lru_cache(maxsize=1)
def _yocto_license_map() -> dict[str, str]:
    """Curated Yocto name -> SPDX value (data/yocto_license_map.yaml).

    An entry counts only when it holds (sicherheit-2 TR1/TR2, 14.11.2026):
    tier ``spdx`` a current SPDX identifier or expression (a WITH exception
    included, no deprecated identifier); tier ``scancode`` a reference the
    checked-in key list has; tier ``openembedded`` a name of poky's
    common-licenses with exactly its ``LicenseRef-openembedded-`` value.
    """
    table = yaml.safe_load((_DATA_DIR / "yocto_license_map.yaml").read_text(encoding="utf-8"))
    refs, oe_names = _scancode_refs(), openembedded_license_names()
    out: dict[str, str] = {}
    for name, entry in table["entries"].items():
        name, value, tier = str(name), str(entry["value"]), entry["tier"]
        if tier == "spdx":
            current = _current_expression(value)
            if current is not None:
                out[name] = current
        elif (tier == "scancode" and value in refs) or (
                tier == "openembedded" and name in oe_names and value == openembedded_ref(name)):
            out[name] = value
    return out


def _yocto_part(tok: str) -> str | None:
    """The SPDX value of one licence name of a Yocto value, or None."""
    ids, deprecated = _spdx_identifiers(), _spdx_deprecated()
    ref = _YOCTO_REF.match(tok)
    if ref is not None and tok in _scancode_refs():
        return tok
    name = ref.group(1) if ref is not None else tok
    if ref is None:
        canonical = ids.get(name.lower())
        if canonical is not None and canonical not in deprecated:
            return canonical
        base = ids.get(name[:-1].lower()) if name.endswith("+") else None
        if base is not None and base not in deprecated:
            return base + "+"
    value = _yocto_license_map().get(name)
    if value is None:
        return None
    return value


def yocto_license_expression(raw: str | None) -> str | None:
    """The SPDX expression for a Yocto LICENSE value, or None.

    Each licence name in the order of TR-03183-2 §6.1 (coordination,
    14.11.2026): a current SPDX identifier as it is; every other name, a
    deprecated identifier and a create-spdx ``LicenseRef-<name>`` included,
    only through its evidenced entry in data/yocto_license_map.yaml (SPDX by
    text, else ScanCode, else ``LicenseRef-openembedded-<name>`` for a name
    of poky's common-licenses). A name without an entry gives None: the
    value is then free text and red, never attributed to OpenEmbedded.
    """
    text = (raw or "").strip()
    if not text or "${" in text:
        return None
    tokens = _YOCTO_TOKEN.findall(text)
    if len(tokens) > _MAX_EXPR_TOKENS:
        return None
    exceptions = _spdx_exceptions()
    out: list[str] = []
    for i, tok in enumerate(tokens):
        if tok == "&":
            out.append("AND")
        elif tok == "|":
            out.append("OR")
        elif tok in ("(", ")"):
            out.append(tok)
        elif tok.upper() in ("AND", "OR", "WITH"):
            out.append(tok.upper())
        elif out and out[-1] == "WITH":
            if tok.lower() not in exceptions:
                return None
            out.append(exceptions[tok.lower()])
        elif tok.casefold() in _PLACEHOLDERS:
            return None
        else:
            part = _yocto_part(tok)
            if part is None:
                return None
            # an entry's expression keeps its grouping inside a larger one;
            # alone, or already inside the build's own brackets, it needs none
            enclosed = 0 < i < len(tokens) - 1 and tokens[i - 1] == "(" \
                and tokens[i + 1] == ")"
            alone = len(tokens) == 1
            out.append(f"({part})" if " " in part and not (alone or enclosed) else part)
    return _strict_expression(" ".join(out))


def yocto_license(raw: str | None) -> tuple[str, bool] | None:
    """(value, is_text) for a licence the Yocto build states, or None.

    The SPDX expression when every name resolves (is_text False); else the
    build's own words, to be written as free text (``license.name``), which
    is red in the portal. None when the value states nothing (empty, a
    placeholder, an unexpanded ``${…}``).
    """
    text = " ".join((raw or "").split())
    if not text or "${" in text:
        return None
    if all(tok.casefold() in _PLACEHOLDERS for tok in _YOCTO_TOKEN.findall(text)
           if tok not in ("&", "|", "(", ")")):
        return None
    expression = yocto_license_expression(text)
    return (expression, False) if expression is not None else (text, True)


# --- Buildroot: <PKG>_LICENSE by the manual of the version built ---------------------
#
# Coordination, 14.11.2026 (TR-03183-2 §6.1). Buildroot's manual (2025.08.2,
# docs/manual/adding-packages-generic.adoc, <PKG>_LICENSE): an SPDX short
# identifier where the licence is on the SPDX list, else a precise description;
# a comma separates different parts under different licences (all apply: AND);
# a component in parentheses names the part (kept as the scope, never dropped);
# "or" separates the licences of a dual-licensed package (OR); "unknown" when
# the variable is not set (no statement).

#: A component of the package, in parentheses at the end of a licence.
_BR_SCOPE = re.compile(r"^(?P<name>.*?)\s*\((?P<scope>[^()]*)\)\s*$")
#: Buildroot's keyword for a dual licence (lower case, as the manual writes it).
_BR_OR = re.compile(r"\s+or\s+")
#: "<licence> with <exception>" where the exception is named.
_BR_WITH = re.compile(r"^(?P<lic>\S+)\s+with\s+(?P<exc>\S+)$", re.IGNORECASE)
#: Buildroot writes this when <PKG>_LICENSE is not set: no statement.
_BR_UNKNOWN = "unknown"
#: Named rule (coordination, 14.11.2026): "A (part) / B (part)", licences of
#: different components separated by a slash, is the manual's comma: AND.
_BR_SLASH = re.compile(r"^(?P<a>[^/]+\([^()]*\))\s*/\s*(?P<b>[^/]+\([^()]*\))$")
#: Named rule (coordination, 14.11.2026): "Dual A/B" is the manual's "A or B".
_BR_DUAL = re.compile(r"^Dual\s+(?P<a>[^\s/]+)\s*/\s*(?P<b>[^\s/]+)$")
#: A name that states public domain; it counts only with a dedication in the
#: package's own licence files (coordination, 14.11.2026).
_BR_PUBLIC_DOMAIN = frozenset({"public domain"})
_PD_REF = "LicenseRef-scancode-public-domain"
_SENTENCE = re.compile(r"[^.!?]*\bpublic\s+domain\b[^.!?]*[.!?]?", re.IGNORECASE)
#: PD1 (sicherheit-2 on 883c184): a dedication is stated positively ("is in
#: the public domain", "placed / released / dedicated ... into the public
#: domain", "is public domain"), never only mentioned ...
_DEDICATION = re.compile(
    r"\b(?:is|are)\s+(?:in(?:to)?\s+the\s+)?public\s+domain\b"
    r"|\b(?:placed|released|put|dedicat\w*|contributed)\b[^.!?]{0,80}?"
    r"\b(?:in|into|to)\s+the\s+public\s+domain\b",
    re.IGNORECASE)
#: ... and nothing in the sentence takes it back (not, isn't, cannot,
#: disclaim ...).
_NEGATION = re.compile(
    r"\b(?:not|no|never|neither|nor|cannot|without)\b|n't\b|\bdisclaim\w*",
    re.IGNORECASE)


class BuildrootLicense(NamedTuple):
    """The licence of a Buildroot package: an SPDX value (``is_text`` False)
    or the build's own words (``is_text`` True, written as free text and red);
    ``scope`` the components Buildroot names in parentheses, "" for none."""

    value: str
    is_text: bool
    scope: str
    #: What a licence text of the package proved, quoted ("" for none):
    #: "public domain: libtomcrypt/LICENSE: 'LibTomCrypt is public domain.'".
    evidence: str = ""
    #: The licence is stated by part (more than one comma part, or a component
    #: named): which part a single file is, the file list does not prove, so a
    #: file inherits no value (BR2, sicherheit-2 on 8cbf2f9). "A or B" alone is a
    #: choice for the whole package and is inherited.
    by_part: bool = False


@lru_cache(maxsize=1)
def _deprecated_replacements() -> dict[str, str]:
    """Deprecated SPDX id -> the one current id of the identical full name
    (data/spdx_deprecated_replacements.yaml, from the SPDX list itself)."""
    raw = yaml.safe_load(
        (_DATA_DIR / "spdx_deprecated_replacements.yaml").read_text(encoding="utf-8"))
    return {str(k): str(v["current"]) for k, v in (raw.get("replacements") or {}).items()}


@lru_cache(maxsize=1)
def _buildroot_license_map() -> dict[str, str]:
    """Curated Buildroot name -> SPDX value (data/buildroot_license_map.yaml);
    an entry counts only when it holds: tier spdx a current SPDX value, tier
    scancode a reference of the checked-in key list."""
    path = _DATA_DIR / "buildroot_license_map.yaml"
    if not path.is_file():
        return {}
    table = yaml.safe_load(path.read_text(encoding="utf-8"))
    refs = _scancode_refs()
    out: dict[str, str] = {}
    for name, entry in (table.get("entries") or {}).items():
        value, tier = str(entry["value"]), entry["tier"]
        if (tier == "spdx" and _current_expression(value) == value) or (
                tier == "scancode" and value in refs):
            out[str(name)] = value
    return out


def buildroot_parts(raw: str) -> list[str]:
    """A manifest.csv LICENSE value split at the commas outside parentheses."""
    parts, depth, cur = [], 0, ""
    for ch in raw:
        depth += (ch == "(") - (ch == ")")
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def _buildroot_name(name: str) -> str | None:
    """The SPDX value of one Buildroot licence name, or None."""
    text = name.strip()
    ids, deprecated = _spdx_identifiers(), _spdx_deprecated()
    canonical = ids.get(text.lower())
    if canonical is not None:
        return _deprecated_replacements().get(canonical) if canonical in deprecated else canonical
    if text.endswith("+"):
        base = ids.get(text[:-1].lower())
        if base is not None and base not in deprecated:
            return base + "+"  # the SPDX "or later" operator on a current id
    m = _BR_WITH.match(text)
    if m is not None:
        lic, exc = _buildroot_name(m["lic"]), _spdx_exceptions().get(m["exc"].lower())
        if lic is not None and exc is not None and " " not in lic:
            return f"{lic} WITH {exc}"
    return _buildroot_license_map().get(text)


def public_domain_statement(texts: dict[str, str] | None) -> str:
    """The first sentence of the package's licence files that dedicates code to
    the public domain: stated positively, nothing in it taking it back (PD1); as
    "<file>: '<sentence>'"; "" for none."""
    for rel, text in sorted((texts or {}).items()):
        for m in _SENTENCE.finditer(" ".join(text.split())):
            sentence = m.group(0).strip()
            if sentence and _DEDICATION.search(sentence) and not _NEGATION.search(sentence):
                return f"{rel}: '{sentence[:200]}'"
    return ""


def _buildroot_split(part: str) -> tuple[list[str], str]:
    """A part as (alternatives, how they join): the manual's "or", and the named
    rules "A (x) / B (y)" (AND) and "Dual A/B" (OR)."""
    m = _BR_SLASH.match(part)
    if m is not None:
        return [m["a"].strip(), m["b"].strip()], "AND"
    m = _BR_DUAL.match(part)
    if m is not None:
        return [m["a"], m["b"]], "OR"
    return _BR_OR.split(part), "OR"


def buildroot_license(parts: list[str] | tuple[str, ...] | str, *,
                      texts: dict[str, str] | None = None) -> BuildrootLicense | None:
    """The licence of a Buildroot package from its licence parts (the entries of
    buildroot.cdx.json, or the manifest.csv value), or None when none is stated.

    By the manual: parts are AND, ``or`` within a part is OR, a component in
    parentheses becomes the scope. A name resolves to a current SPDX id, a
    deprecated id to its replacement of the identical name, ``X+`` to the SPDX
    operator, ``A with <exception>`` to WITH, otherwise only through an
    evidenced entry. "Public domain" counts (ScanCode public-domain) only when
    *texts*, the package's licence files from legal-info, dedicate code to the
    public domain; the sentence is quoted in ``evidence``. If one name does not
    resolve, the whole licence stays the build's own words (free text, red):
    never a partial green.
    """
    raw_parts = [p.strip() for p in (buildroot_parts(parts) if isinstance(parts, str)
                                     else list(parts)) if p.strip()]
    placeholder = [spdx_license_value(p) is None or p == _BR_UNKNOWN for p in raw_parts]
    if all(placeholder):
        return None  # the whole value states nothing
    stated = raw_parts
    if any(placeholder):
        # BR1 (sicherheit-2 on 8cbf2f9): each comma part is a part of the package;
        # "unknown" or a placeholder for one of them leaves it unproven: the
        # whole licence stays the build's words, never a partial green
        return BuildrootLicense("; ".join(stated), True, "", by_part=True)
    groups: list[str] = []
    scopes: list[tuple[str, str, str]] = []  # (value, name as written, component)
    resolved = True
    evidence = ""
    for part in stated:
        alts: list[str] = []
        pieces, joiner = _buildroot_split(part)
        for alt in pieces:
            m = _BR_SCOPE.match(alt)
            name, scope = (m["name"], m["scope"].strip()) if m else (alt, "")
            value = _buildroot_name(name)
            if value is None and name.strip().casefold() in _BR_PUBLIC_DOMAIN:
                quote = public_domain_statement(texts)
                if quote:
                    value, evidence = _PD_REF, f"public domain: {quote}"
            if value is None:
                resolved = False
            if scope:
                scopes.append((value or "", name.strip(), scope))
            alts.append(value or "")
        if resolved:
            groups.append(alts[0] if len(alts) == 1 else "(" + f" {joiner} ".join(alts) + ")")
    # the scope in the same words as the value: SPDX when resolved, else the build's
    scope = "; ".join(f"{v if resolved else n} ({s})" for v, n, s in scopes)
    if resolved:
        joined = " AND ".join(
            g if len(groups) == 1 or " " not in g or g.startswith("(") else f"({g})"
            for g in groups)
        if len(groups) == 1 and joined.startswith("(") and joined.endswith(")"):
            joined = joined[1:-1]
        expression = _strict_expression(joined)
        if expression is not None and _current_expression(expression) == expression:
            return BuildrootLicense(expression, False, scope, evidence,
                                    by_part=len(stated) > 1 or bool(scopes))
    return BuildrootLicense("; ".join(stated), True, scope,
                            by_part=len(stated) > 1 or bool(scopes))


class DeprecatedIds(NamedTuple):
    """The deprecated SPDX ids in a licence value (coordination, 14.11.2026):
    ``replaced`` those with one current id of the same name (id, current) are
    taken, but named (yellow); ``unreplaced`` the others leave the scope
    (-only/-or-later) unnamed (red)."""

    replaced: list[tuple[str, str]]
    unreplaced: list[str]


def deprecated_ids(value: str | None) -> DeprecatedIds:
    """The deprecated SPDX ids of *value*, by whether a replacement exists."""
    strict = _strict_expression(value) if value else None
    if strict is None:
        return DeprecatedIds([], [])
    deprecated, replacement = _spdx_deprecated(), _deprecated_replacements()
    toks = sorted({tok for tok in _EXPR_TOKEN.findall(strict) if tok in deprecated})
    return DeprecatedIds([(t, replacement[t]) for t in toks if t in replacement],
                         [t for t in toks if t not in replacement])


def deprecated_without_replacement(value: str | None) -> list[str]:
    """The deprecated SPDX ids in *value* without a current id of the same name."""
    return deprecated_ids(value).unreplaced
