"""Zephyr ``west.yml``: the module list of a west workspace.

Every project in the manifest is a component with its repository. A
revision that pins — a tag (``v3.6.0``, ``3.6.0``, ``zephyr-v3.6.0``) or a
commit hash — is the version. A branch (``main``, ``develop``, ``ncs-2.6``)
names a moving target: the version stays empty, the purl carries no
``@``, and the branch travels as the declaration ``branch:<name>``.

Shared file: the open collector carries a generated copy (ci/sync-twin.py),
so both tools read west.yml with the same code.
"""

from __future__ import annotations

import unicodedata
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import yaml

from jochwacht_sbom.core.log import get_logger
from jochwacht_sbom.core.revisions import is_pinned_revision
from jochwacht_sbom.sbom.scanner import Dependency, _make_purl

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger(__name__)

__all__ = ["is_pinned_revision", "read_west_manifest"]


def _clean(value: Any) -> str:
    """A string field without control and format characters, trimmed;
    anything that is not a string is no value."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        value = str(value)          # "revision: 3.6", "name: 77"
    if not isinstance(value, str):
        return ""
    return "".join(ch for ch in value if unicodedata.category(ch) not in ("Cc", "Cf")).strip()


def read_west_manifest(path: Path) -> list[Dependency]:
    """The projects of one ``west.yml`` as components.

    A file of unexpected form (not UTF-8, wrong types, deep nesting) is
    skipped with a warning; the run goes on.
    """
    try:
        return _read(path)
    except (OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError,
            AttributeError, TypeError, ValueError) as exc:
        logger.warning("Skipped %s: %s", path, type(exc).__name__)
        return []


def _read(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    # BaseLoader: every scalar stays the text that was written. safe_load
    # turns "revision: 3.10" into the float 3.1 and "name: 77" into an int
    # BaseLoader constructs no objects either.
    data = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)  # noqa: S506

    manifest = data.get("manifest") if isinstance(data, dict) else None
    if not isinstance(manifest, dict):
        return deps

    remote_list = manifest.get("remotes") or []
    projects = manifest.get("projects") or []
    defaults = manifest.get("defaults") or {}
    if not isinstance(remote_list, list) or not isinstance(projects, list) \
            or not isinstance(defaults, dict):
        raise TypeError("remotes/projects must be lists, defaults a mapping")
    remotes = {
        _clean(r.get("name")): _clean(r.get("url-base"))
        for r in remote_list
        if isinstance(r, dict)
    }
    default_remote = _clean(defaults.get("remote")) or (next(iter(remotes), ""))

    for project in projects:
        if not isinstance(project, dict):
            continue
        name = _clean(project.get("name"))
        revision = _clean(project.get("revision"))
        if not name or not revision:
            continue
        repo_path = _clean(project.get("repo-path")) or name
        base = remotes.get(_clean(project.get("remote")) or default_remote, "")
        pinned = is_pinned_revision(revision)
        version = revision if pinned else ""
        purl = None
        if base.startswith("https://github.com/"):
            org = base[len("https://github.com/"):].strip("/")
            purl = (f"pkg:github/{quote(org, safe='/')}/{quote(repo_path, safe='')}"
                    + (f"@{quote(revision, safe='.+-_~')}" if pinned else ""))
        deps.append(Dependency(
            name=name,
            version=version,
            ecosystem="github",
            purl=purl or _make_purl("generic", name, version),
            declared_range="" if pinned else f"branch:{revision}",
        ))

    logger.info("Found %d west modules in %s", len(deps), path)
    return deps
