"""Text from outside (a supplier's bill, a customer field) made safe to show.

One rule for every output — console, HTML, Markdown, JSON — and for the
reader of foreign bills: Unicode categories

* ``Cc`` control characters, except line feed and tab (ESC, BEL, NUL,
  carriage return, the C1 range with CSI U+009B),
* ``Cf`` format characters (direction overrides such as U+202E, zero-width
  characters, the byte order mark),
* ``Zl`` and ``Zp`` line and paragraph separators

are removed. ESC sequences (CSI ``ESC [ … final``, OSC ``ESC ] … BEL|ST``)
go as a whole, so no "[31m" is left behind.
"""

from __future__ import annotations

import re
import unicodedata

_BAD_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})
_KEEP = frozenset("\n\t")
_ESC_SEQUENCE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"           # CSI
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC, ended by BEL or ST (or not at all)
    r"|\x9b[0-?]*[ -/]*[@-~]"            # C1 CSI
)
_ASCII_BAD = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def strip_unsafe(text: str) -> str:
    """*text* without control, format and separator characters (see module)."""
    if not text:
        return text
    text = _ESC_SEQUENCE.sub("", text)
    if text.isascii():
        return _ASCII_BAD.sub("", text)
    return "".join(
        ch for ch in text
        if ch in _KEEP or unicodedata.category(ch) not in _BAD_CATEGORIES
    )


def is_unsafe(ch: str) -> bool:
    """True for one character :func:`strip_unsafe` removes."""
    return ch not in _KEEP and unicodedata.category(ch) in _BAD_CATEGORIES
