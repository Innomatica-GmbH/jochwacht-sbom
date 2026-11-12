"""Deterministic Autotools parser (configure.ac / configure.in).

Extracts dependency names from GNU Autotools build files:
- AC_CHECK_LIB([name], [func])
- AC_CHECK_HEADER([header.h])
- PKG_CHECK_MODULES([VAR], [name >= version])
- AC_SEARCH_LIBS([func], [lib1 lib2 ...])
- AX_CHECK_OPENSSL / AX_CHECK_ZLIB etc.
"""

from __future__ import annotations

import re

from jochwacht_sbom.analyzer.parsers.makefile import add_link_names, is_link_assignment
from jochwacht_sbom.analyzer.parsers.short_libs import short_library
from jochwacht_sbom.analyzer.parsers.system_libs import is_system_library

# AC_CHECK_LIB([crypto], [SHA1_Init], ...)
# AC_CHECK_LIB(curl, curl_global_init, ...)
_AC_CHECK_LIB = re.compile(
    r"AC_CHECK_LIB\s*\(\s*\[?(\w[\w.+-]*)\]?",  # stdc++ is one name
    re.IGNORECASE,
)

# PKG_CHECK_MODULES([DLT], ['automotive-dlt >= 2.11'])
# PKG_CHECK_MODULES(DLT, automotive-dlt >= 2.11)
_PKG_CHECK_MODULES = re.compile(
    r"PKG_CHECK_MODULES\s*\(\s*\[?\w+\]?\s*,\s*\[?'?\"?([a-zA-Z0-9_][a-zA-Z0-9_.+-]*)",
)

# AC_SEARCH_LIBS([clock_gettime], [rt posix4])
# Also handles unbracketed: AC_SEARCH_LIBS(fmod, m)
_AC_SEARCH_LIBS = re.compile(
    r"AC_SEARCH_LIBS\s*\(\s*\[?\w+\]?\s*,\s*\[?([^\],\)]+)",
)

# AC_CHECK_HEADER([header.h]) — not always a dependency, but useful
_AC_CHECK_HEADER = re.compile(
    r"AC_CHECK_HEADER\s*\(\s*\[?([a-zA-Z0-9_/.+-]+\.h)\]?",
)

# AX_CHECK_OPENSSL, AX_CHECK_ZLIB, etc.
_AX_CHECK = re.compile(
    r"AX_CHECK_(\w+)",
)

# A shell assignment to a link variable: LIBS="$LIBS -luv", LIBS+=" -lx",
# MOSQ_LIBS=-lmosquitto (then AC_SUBST). Measured 12.11.2026: none of it was
# read, so every autotools project lost its hand-written link libraries.
# Only at a command position (line start, after ; && || then else do, or as
# the shell argument of AS_IF [...]), never inside quotes: text such as
# echo "LIBS=-lx" or msg="set LIBS=-lx" is no assignment.
_SHELL_ASSIGN = re.compile(
    r"(?:^|[;&|\[(]|\bthen\b|\belse\b|\bdo\b)\s*([A-Za-z_][A-Za-z0-9_]*)\+?="
    r"(\"[^\"]*\"|'[^']*'|[^\s;\])]*)",
    re.MULTILINE,
)
# Text macros whose arguments are words for the reader, never shell
_TEXT_MACRO = re.compile(r"\b(?:AC_MSG_\w+|AS_HELP_STRING|AC_HELP_STRING|AS_ECHO(?:_N)?)\s*\(")
# AC_SUBST([MOSQ_LIBS], ["-lmosquitto"]) — the two-argument form sets the value
_AC_SUBST_VALUE = re.compile(r"AC_SUBST\(\s*\[?\w+\]?\s*,\s*([^)]*)\)")

# Header → library name mapping (common cases)
_HEADER_TO_LIB: dict[str, str] = {
    "openssl/ssl.h": "openssl",
    "openssl/crypto.h": "openssl",
    "curl/curl.h": "libcurl",
    "zlib.h": "zlib",
    "expat.h": "libexpat",
    "pcre2.h": "libpcre2",
    "pcre.h": "libpcre",
    "iconv.h": "libiconv",
    "libintl.h": "libintl",
    "pthread.h": "pthread",
}


def _strip_comments(content: str) -> str:
    """Remove autotools comments (dnl ... and # ...)."""
    content = re.sub(r"dnl\s+[^\n]*", "", content)
    content = re.sub(r"#[^\n]*", "", content)
    return content


def _without_text_macros(content: str) -> str:
    """Drop AC_MSG_*, AS_HELP_STRING and the like with their arguments."""
    out: list[str] = []
    pos = 0
    for m in _TEXT_MACRO.finditer(content):
        if m.start() < pos:
            continue
        out.append(content[pos:m.start()])
        depth, i = 1, m.end()
        while i < len(content) and depth:
            depth += {"(": 1, ")": -1}.get(content[i], 0)
            i += 1
        pos = i
    out.append(content[pos:])
    return "".join(out)


def _in_quotes(text: str, index: int) -> bool:
    """True when index lies inside a quoted string of its line."""
    line = text[text.rfind("\n", 0, index) + 1:index]
    quote = ""
    escaped = False
    for ch in line:
        if escaped:
            escaped = False
        elif ch == "\\" and quote != "'":
            escaped = True
        elif quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
    return bool(quote)


def parse(content: str) -> list[str]:
    """Extract dependency names from configure.ac content."""
    content = _strip_comments(content)
    deps: set[str] = set()

    # AC_CHECK_LIB
    for m in _AC_CHECK_LIB.finditer(content):
        name = short_library(m.group(1)) or m.group(1)
        # a short link name only as a real library (short_libs: z → zlib);
        # a part of the C library or compiler runtime never
        if len(name) > 2 and not is_system_library(name):
            deps.add(name)

    # PKG_CHECK_MODULES
    for m in _PKG_CHECK_MODULES.finditer(content):
        deps.add(m.group(1))

    # AC_SEARCH_LIBS — extract each library name
    for m in _AC_SEARCH_LIBS.finditer(content):
        libs = m.group(1).split()
        for lib in libs:
            lib = lib.strip()
            if lib and not is_system_library(lib):
                deps.add(short_library(lib) or lib)

    # link assignments and AC_SUBST values
    shell = _without_text_macros(content)
    for m in _SHELL_ASSIGN.finditer(shell):
        if _in_quotes(shell, m.start(1)):
            continue
        value = m.group(2).strip("\"'")
        if is_link_assignment(m.group(1), value):
            add_link_names(deps, value)
    for m in _AC_SUBST_VALUE.finditer(content):
        add_link_names(deps, m.group(1).strip().strip("[]").strip("\"'"))

    # AX_CHECK_*
    for m in _AX_CHECK.finditer(content):
        name = m.group(1).lower()
        deps.add(name)

    # AC_CHECK_HEADER — map known headers to library names
    for m in _AC_CHECK_HEADER.finditer(content):
        header = m.group(1)
        if header in _HEADER_TO_LIB:
            deps.add(_HEADER_TO_LIB[header])

    return sorted(deps)
