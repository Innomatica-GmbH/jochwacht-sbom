"""What ships: required, optional, or development material (excluded).

Rule (block 5, measured 11.11.2026 on the parity corpus, flask uv.lock and
requests pyproject.toml):

- what the production dependencies reach is required (no scope);
- what only the extras reach is ``optional``: an extra is installed on
  request only;
- what only dependency groups / dev dependencies reach is ``excluded``:
  listed, never gating.

With a lockfile the rule runs over its dependency graph
(:func:`closure_scope`); without one over the sections of pyproject.toml
(:func:`pyproject_requirements`, :func:`poetry_dependency_tables`). Where
nothing names the production roots, nothing is marked — unknown is not
"dev".

Shared file: the open collector carries a generated copy (ci/sync-twin.py).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from jochwacht_sbom.core.log import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from pathlib import Path

    from jochwacht_sbom.sbom.scanner import Dependency

logger = get_logger(__name__)


def _reach(edges: dict[str, set[str]], roots: Iterable[str]) -> set[str]:
    reachable: set[str] = set()
    stack = list(roots)
    while stack:
        n = stack.pop()
        if n in reachable:
            continue
        reachable.add(n)
        stack.extend(e for e in edges.get(n, ()) if e not in reachable)
    return reachable


def closure_scope(
    deps: list[Dependency], edges: dict[str, set[str]],
    main_roots: Iterable[str], extra_roots: Iterable[str] = (),
    *, key: Callable[[str], str] = str.lower,
) -> int:
    """Mark what *main_roots* do not reach: ``optional`` when *extra_roots*
    reach it, else ``excluded``. *edges* and the roots use the key space of
    *key*. A dependency with a scope already, or declared, is left alone.
    Returns the number of dependencies marked."""
    main = _reach(edges, (key(r) for r in main_roots))
    extra = _reach(edges, (key(r) for r in extra_roots)) - main
    marked = 0
    for dep in deps:
        if dep.scope or dep.declared:
            continue
        k = key(dep.name)
        if k in main:
            continue
        dep.scope = "optional" if k in extra else "excluded"
        marked += 1
    if marked:
        logger.info("%d dependencies outside the production closure marked "
                    "optional or excluded", marked)
    return marked


#: Group names that mean development material: a group is
#: excluded when its whole name is one of DEV_GROUP_NAMES, or every part of
#: it is one of DEV_GROUP_PARTS ("test-unit", "dev-test"). Ambiguous parts
#: (qa, doc, style, check, pre, format, types, ci, coverage, bench) never
#: decide alone: "doc-processing" or "ci-agent" may well ship.
DEV_GROUP_NAMES = frozenset({
    "dev", "develop", "development", "test", "tests", "testing", "lint", "linting",
    "docs", "typing", "typecheck", "type-check", "mypy", "pre-commit", "precommit",
})
DEV_GROUP_PARTS = frozenset({
    "dev", "develop", "development", "test", "tests", "testing", "lint", "linting",
    "docs", "typing", "typecheck", "mypy",
})
#: Parts that count only next to a clear one: "test-unit" is dev material,
#: a group named "integration" alone may be a runtime integration.
DEV_GROUP_QUALIFIERS = frozenset({"unit", "integration", "e2e"})

_RANK = {"": 0, "optional": 1, "excluded": 2}


def is_dev_group(name: str) -> bool:
    """Whether a group name says development material: "dev", "docs",
    "test-unit" yes; "server", "qa", "doc-processing" no."""
    low = str(name).strip().lower()
    if low in DEV_GROUP_NAMES:
        return True
    parts = [p for p in re.split(r"[-_.\s]+", low) if p]
    return (bool(parts) and all(p in DEV_GROUP_PARTS | DEV_GROUP_QUALIFIERS for p in parts)
            and any(p in DEV_GROUP_PARTS for p in parts))


def _has_production(data: dict[str, Any]) -> bool:
    """Whether pyproject.toml names production dependencies at all. Without
    them nothing is marked: unknown is not "dev"."""
    project = data.get("project") or {}
    if isinstance(project, dict) and isinstance(project.get("dependencies"), list) \
            and project["dependencies"]:
        return True
    tool = data.get("tool") or {}
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    deps = poetry.get("dependencies") if isinstance(poetry, dict) else None
    return isinstance(deps, dict) and any(k != "python" for k in deps)


def pyproject_requirements(data: dict[str, Any]) -> list[tuple[str, str, str]]:
    """``(PEP 508 requirement, scope, reason)`` from [project] and
    [dependency-groups]: dependencies required (""), optional-dependencies
    "optional", a group "excluded" only when its name says development
    material — and nothing at all is marked without production
    dependencies."""
    out: list[tuple[str, str, str]] = []
    prod = _has_production(data)
    project = data.get("project") or {}
    if not isinstance(project, dict):
        project = {}
    sections: list[tuple[object, str, str]] = [(project.get("dependencies") or [], "", "")]
    extras = project.get("optional-dependencies") or {}
    if isinstance(extras, dict):
        sections.extend((v, "optional" if prod else "", "") for v in extras.values())
    groups = data.get("dependency-groups") or {}
    if isinstance(groups, dict):
        for name, v in groups.items():
            dev = prod and is_dev_group(name)
            sections.append((v, "excluded" if dev else "",
                             f"dependency group '{name}'" if dev else ""))
    for reqs, scope, reason in sections:
        if isinstance(reqs, list):
            out.extend((r, scope, reason) for r in reqs if isinstance(r, str))
    return out


def poetry_dependency_tables(data: dict[str, Any]) -> list[tuple[dict[str, Any], str, str]]:
    """``(table, scope, reason)`` of [tool.poetry]: dependencies required;
    dev-dependencies and a group whose name says development material
    "excluded"; an ``optional = true`` group "optional" (installed on
    request, like an extra); any other group (Poetry installs it by
    default) required. Nothing is marked without production
    dependencies."""
    tool = data.get("tool") or {}
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if not isinstance(poetry, dict):
        return []
    prod = _has_production(data)
    tables: list[tuple[object, str, str]] = [
        (poetry.get("dependencies") or {}, "", ""),
        (poetry.get("dev-dependencies") or {}, "excluded" if prod else "",
         "poetry dev-dependencies" if prod else ""),
    ]
    groups = poetry.get("group") or {}
    if isinstance(groups, dict):
        for name, g in groups.items():
            if not isinstance(g, dict):
                continue
            if prod and is_dev_group(name):
                tables.append((g.get("dependencies") or {}, "excluded",
                               f"poetry group '{name}'"))
            elif prod and g.get("optional") is True:
                # Installed on request, like an extra (gpu/torch).
                tables.append((g.get("dependencies") or {}, "optional", ""))
            else:
                tables.append((g.get("dependencies") or {}, "", ""))
    return [(t, s, r) for t, s, r in tables if isinstance(t, dict)]


def strongest_per_name(deps: list[Dependency]) -> list[Dependency]:
    """One entry per name: the one with the stronger scope (required over
    optional over excluded), in first-seen order."""
    best: dict[str, Dependency] = {}
    order: list[str] = []
    for dep in deps:
        k = re.sub(r"[-_.]+", "-", dep.name).lower()
        if k not in best:
            order.append(k)
            best[k] = dep
        elif _RANK.get(dep.scope or "", 0) < _RANK.get(best[k].scope or "", 0):
            best[k] = dep
    return [best[k] for k in order]


def usable_lock(path: Path) -> bool:
    """Whether a lockfile can stand in for pyproject.toml: it parses and its
    "package" is a list. An unusable one is skipped by its reader; then the
    pyproject.toml rule applies instead of nothing."""
    import tomllib

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError):
        return False
    packages = data.get("package", [])
    if not isinstance(packages, list):
        return False
    # At least one entry the reader can take; all skipped is as good as none
    # An empty list, or (uv.lock) nothing but the project's own
    # members, names no dependency: pyproject.toml counts then.
    def takes(p: object) -> bool:
        if not (isinstance(p, dict) and isinstance(p.get("name"), str)
                and isinstance(p.get("version"), str)):
            return False
        source = p.get("source")
        return not (path.name == "uv.lock" and isinstance(source, dict) and (
            "editable" in source or "virtual" in source or "directory" in source))

    return any(takes(p) for p in packages)
