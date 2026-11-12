"""XML from outside — parsed only without DOCTYPE and entities.

XML that comes from outside (a foreign SBOM, pom.xml, MSBuild projects,
packages.config, .nuspec, FPGA project files) must not be able to expand
entities: ElementTree expands an internal entity (``<!ENTITY x "lol">`` →
``lol``), and nested entities blow up memory.

This module is the one way to parse such XML: :func:`fromstring` and
:func:`parse` refuse any document that contains ``<!DOCTYPE`` or
``<!ENTITY`` (case-insensitive, anywhere — a comment with that text is
refused too, deliberately) with :class:`XmlRejected`, a ``ParseError``, so
every caller that already treats malformed XML as "not parseable" treats a
rejected one the same way. Nothing is expanded before the check.

It also refuses what would let a declaration slip past that check or crash
a caller: NUL bytes (UTF-16 and UTF-32, where ``<!DOCTYPE`` is not these
bytes; bills of materials are UTF-8), an encoding expat cannot read, and a
document larger than the limit below.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.etree.ElementTree import Element, ElementTree, ParseError

# The only module that imports xml.*: everything else takes the parser AND
# these names from here (tests/test_core/test_xmlsafe.py checks the imports
# of every module by AST).

_FORBIDDEN = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)
_HEAD_LIMIT = 64 * 1024 * 1024   # a document larger than this is no SBOM we read


class XmlRejected(ET.ParseError):
    """The document is refused: DOCTYPE or entity declaration, too large,
    NUL bytes, or an encoding expat cannot read."""


def check_xml_bytes(data: bytes, *, what: str = "XML") -> None:
    """Refuse DOCTYPE and ENTITY declarations before anything parses them."""
    if len(data) > _HEAD_LIMIT:
        raise XmlRejected(f"{what}: {len(data)} bytes, more than the {_HEAD_LIMIT} we read")
    if b"\x00" in data:
        # In UTF-16/UTF-32 "<!DOCTYPE" is not these bytes: the search below
        # would miss it and expat would read it. Bills of materials are
        # UTF-8; a NUL byte refuses the document.
        raise XmlRejected(
            f"{what}: contains NUL bytes (UTF-16/UTF-32?) — only UTF-8 XML is accepted")
    m = _FORBIDDEN.search(data)
    if m:
        raise XmlRejected(
            f"{what}: <!{m.group(1).decode('ascii').upper()} is not accepted "
            "(no document type declarations, no entities)")


def _parse_checked(data: bytes, what: str) -> ET.Element:
    """``ET.fromstring`` on bytes that passed the check. An encoding
    declaration expat cannot read raises ValueError (multi-byte: Shift_JIS,
    UTF-7) or LookupError (unknown name), not ParseError; both become
    XmlRejected, so a caller that catches ParseError says "not readable"
    instead of crashing."""
    try:
        return ET.fromstring(data)  # noqa: S314 — checked: no DOCTYPE, no entities
    except (ValueError, LookupError) as exc:
        raise XmlRejected(f"{what}: encoding not readable ({exc})") from exc


def fromstring(text: str | bytes, *, what: str = "XML") -> ET.Element:
    """``ET.fromstring`` after the check."""
    data = text.encode("utf-8", errors="surrogatepass") if isinstance(text, str) else text
    check_xml_bytes(data, what=what)
    return _parse_checked(data, what)


def parse(path: str | Path, *, what: str = "") -> ET.ElementTree[ET.Element]:
    """``ET.parse`` after the check, reading the file once."""
    p = Path(path)
    data = p.read_bytes()
    check_xml_bytes(data, what=what or p.name)
    return ET.ElementTree(_parse_checked(data, what or p.name))


__all__ = [
    "Element",
    "ElementTree",
    "ParseError",
    "XmlRejected",
    "check_xml_bytes",
    "fromstring",
    "parse",
]
