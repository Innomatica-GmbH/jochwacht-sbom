"""Declared project identities: what a project calls itself, in which ecosystem.

The self filter of the suite and of the collector drops a "dependency"
that is the project itself (a test group naming ``mytool[extra]``, a
``find_package`` of the own target). It compares against what the project
DECLARES in its root directory, each name in the ecosystem of the file that
declares it:

- ``jochwacht.yaml`` → ``project.name`` (every ecosystem: the customer's word)
- ``pyproject.toml`` → ``[project].name`` / ``[tool.poetry].name`` (pypi)
- ``package.json`` → ``name`` (npm)
- ``Cargo.toml`` → ``[package].name`` (cargo)
- ``CMakeLists.txt`` → the first ``project(<name> …)`` command (cmake)
- ``go.mod`` → ``module <path>`` (golang)

Never the folder name: it says where a checkout lives, not what the project
is called. Never a fuzzy match: the comparison (:func:`is_own`) is exact, up
to the equality the ecosystem itself defines (PEP 503 for pypi, ``-`` = ``_``
for cargo, case elsewhere) — a Cargo.toml named "requests" next
to a Python project dropped requests==2.19.0, and "requests" dropped
requests-core. A file over 1 MiB, unreadable, too deeply nested or with an
unexpanded variable gives no name.

Shared file: the open collector carries a generated copy (ci/sync-twin.py).
"""

from __future__ import annotations

import json
import re
import stat
import tomllib
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

#: Larger root files are no project declaration we read.
MAX_FILE = 1024 * 1024

# "[ \t]*", not "\s*": "^\s*" ran across line ends, quadratic on blank lines.
_CMAKE_PROJECT = re.compile(r"^[ \t]*project[ \t]*\([ \t\r\n]*([A-Za-z0-9_.+-]+)",
                            re.IGNORECASE | re.MULTILINE)
_GO_MODULE = re.compile(r"^[ \t]*module[ \t]+(\S+)", re.MULTILINE)
_BRACKET_OPEN = re.compile(r"\[(=*)\[")


def _read(path: Path, root: Path) -> str:
    """The file as text — only a regular file inside *root* (no link out of
    the tree, no device), at most MAX_FILE bytes. A link
    go.mod -> /dev/zero reports size 0 and was read without limit."""
    try:
        real = path.resolve()
        if not real.is_relative_to(root) or not stat.S_ISREG(real.stat().st_mode):
            return ""
        with real.open("rb") as fh:
            data = fh.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            return ""
        return data.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _name(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def cmake_code(text: str, *, keep_strings: bool = False) -> str:
    """*text* with comments (and, unless *keep_strings*, quoted or bracket
    arguments) blanked out, newlines kept: ``project(`` counts only as a real
    command, not inside ``message("… project(openssl) …")`` or a comment.
    With *keep_strings* only the comments go (a quoted URL stays)."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "#":
            m = _BRACKET_OPEN.match(text, i + 1)
            if m:                                   # bracket comment #[[ … ]]
                end = text.find("]" + m.group(1) + "]", m.end())
                end = n if end < 0 else end + len(m.group(1)) + 2
            else:                                   # line comment
                end = text.find("\n", i)
                end = n if end < 0 else end
        elif ch == '"':                             # quoted argument
            end = i + 1
            while end < n and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            end = min(end + 1, n)
            if keep_strings:
                out.append(text[i:end])
                i = end
                continue
        elif ch == "[" and not keep_strings and _BRACKET_OPEN.match(text, i):
            m = _BRACKET_OPEN.match(text, i)
            assert m is not None
            end = text.find("]" + m.group(1) + "]", m.end())
            end = n if end < 0 else end + len(m.group(1)) + 2
        else:
            out.append(ch)
            i += 1
            continue
        out.append("".join(c if c == "\n" else " " for c in text[i:end]))
        i = end
    return "".join(out)


def _load(parse: Any, text: str) -> Any:
    try:
        return parse(text)
    except (ValueError, yaml.YAMLError, RecursionError):   # S3: deep nesting
        return None


def declared_project_identities(path: Path) -> frozenset[tuple[str, str]]:
    """``{(name, ecosystem)}`` the project in *path* declares; ``""`` as the
    ecosystem for a name from jochwacht.yaml (valid in every ecosystem)."""
    ids: set[tuple[str, str]] = set()
    root = path.resolve()

    text = _read(path / "jochwacht.yaml", root)
    data = _load(yaml.safe_load, text) if text else None
    if isinstance(data, dict) and isinstance(data.get("project"), dict):
        ids.add((_name(data["project"].get("name")), ""))

    for toml_file, eco, tables in (("pyproject.toml", "pypi", (("project",), ("tool", "poetry"))),
                                   ("Cargo.toml", "cargo", (("package",),))):
        text = _read(path / toml_file, root)
        doc = _load(tomllib.loads, text) if text else None
        for keys in tables:
            node = doc
            for key in keys:
                node = node.get(key) if isinstance(node, dict) else None
            if isinstance(node, dict):
                ids.add((_name(node.get("name")), eco))

    text = _read(path / "package.json", root)
    pkg = _load(json.loads, text) if text else None
    if isinstance(pkg, dict):
        ids.add((_name(pkg.get("name")), "npm"))

    text = _read(path / "CMakeLists.txt", root)
    if text:
        m = _CMAKE_PROJECT.search(cmake_code(text))
        if m:
            ids.add((m.group(1), "cmake"))

    text = _read(path / "go.mod", root)
    if text:
        m = _GO_MODULE.search(text)
        if m:
            ids.add((m.group(1), "golang"))

    return frozenset((n, e) for n, e in ids if n)


def declared_project_names(path: Path) -> frozenset[str]:
    """The declared names alone (for display)."""
    return frozenset(n for n, _e in declared_project_identities(path))


def _key(name: str, ecosystem: str) -> str:
    name = name.strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()     # PEP 503
    if ecosystem == "cargo":
        return name.lower().replace("-", "_")
    return name.casefold()


def is_own(name: str, ecosystem: str, identities: Iterable[tuple[str, str]]) -> bool:
    """Whether *name* in *ecosystem* is the project itself: exactly a declared
    name of that ecosystem (or of jochwacht.yaml), no fuzzy matching."""
    key = _key(name, ecosystem)
    return any((not eco or eco == ecosystem) and _key(own, ecosystem) == key
               for own, eco in identities)
