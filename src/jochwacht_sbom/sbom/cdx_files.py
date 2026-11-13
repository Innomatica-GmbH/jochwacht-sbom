"""CycloneDX for what a build directory proves: file components, images, creator.

One writer for both halves (coordination, 13.11.2026: no second version). The
suite's generator and the public collector's writer call these functions with
their own records; this module imports nothing but the standard library, so
``ci/sync-twin.py`` copies it verbatim.

Rules (TR-03183-2 v2.1.0, reading of sicherheit-2):

- A delivered executable file or archive is a component of type ``file``:
  name = filename, SHA-512, the proven properties only (3.2.1, 5.2.2).
- Its version, licence and creator are the package's: the same fact, proven
  by the file list, and marked; a licence by part is never given to a file.
- The creator stands in ``manufacturer`` (8.2, Table 9), which CycloneDX has
  from 1.6 on; below, the gap is named.
- A package is a logical component (3.2.2) only when the build proves it, and
  then carries ``jochwacht:component-kind=logical``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from pathlib import PurePosixPath
from typing import Protocol

#: Our property namespace (the same string as properties.PREFIX on both sides).
PREFIX = "jochwacht:"

#: The mark of a proven logical component.
LOGICAL = {"name": PREFIX + "component-kind", "value": "logical"}

#: Package file lists that prove a package delivers no executable or no file.
NO_FILE_REASONS = ("no_executable_file", "no_delivered_file")

#: A licence statement by part ("GPL-2.0+ (programs), LGPL-2.1+ (libraries)")
#: or a list of licences joined with "," or "; ": which part a single file is,
#: the file list does not prove (sicherheit-2, 13.11.2026).
LICENSE_BY_PART = re.compile(r"[,;]|\((?![^()]*\b(?:OR|AND|WITH)\b)[^()]*[a-z][^()]*\)")


class DeliveredFileLike(Protocol):
    """What a delivered file record offers (suite: DeliveredFile; collector: its own)."""

    path: str
    sha512: str
    executable: bool | None
    archive: bool | None
    structured: bool | None
    origin: str


def _prop(key: str, value: str) -> dict[str, str]:
    return {"name": PREFIX + key, "value": value}


def file_properties(f: DeliveredFileLike, filename: str) -> list[dict[str, str]]:
    """bsi:component:filename, the proven properties and our evidence marks."""
    props: list[dict[str, str]] = [{"name": "bsi:component:filename", "value": filename}]
    for flag in ("executable", "archive", "structured"):
        value = getattr(f, flag)
        if value is not None:
            props.append({"name": f"bsi:component:{flag}",
                          "value": "true" if value else "false"})
    props.append(_prop("evidence:path", f.path))
    props.append(_prop("evidence:origin", f.origin))
    return props


def file_components(
    files: Iterable[DeliveredFileLike],
    *,
    parent_ref: str,
    package_name: str,
    version: str,
    package_license: str,
    to_licenses: Callable[[str], list[dict[str, object]]],
) -> list[dict[str, object]]:
    """The delivered files of a package as nested CycloneDX components.

    *to_licenses* turns the package's licence text into the CycloneDX
    ``licenses`` array with the caller's licence library.
    """
    out: list[dict[str, object]] = []
    by_part = bool(package_license and LICENSE_BY_PART.search(package_license))
    for f in files:
        filename = PurePosixPath(f.path).name
        child: dict[str, object] = {
            "type": "file",
            "bom-ref": f"{parent_ref}#file:{f.path}",
            "name": filename,
        }
        if version:
            child["version"] = version
        child["hashes"] = [{"alg": "SHA-512", "content": f.sha512}]
        props: list[dict[str, str]] = []
        if package_license and not by_part:
            licenses = to_licenses(package_license)
            if licenses:
                child["licenses"] = licenses
                props.append(_prop("evidence:license", f"package {package_name}"))
        elif package_license:
            props.append(_prop("not-evidenced", "license_by_part"))
        child["properties"] = file_properties(f, filename) + props
        out.append(child)
    return out


def image_component(f: DeliveredFileLike, *, name: str, version: str) -> dict[str, object]:
    """A delivered image without a package: type file, hash, filename, proven
    properties; creator and version stay open unless known."""
    comp: dict[str, object] = {"type": "file", "name": name}
    if version:
        comp["version"] = version
    comp["hashes"] = [{"alg": "SHA-512", "content": f.sha512}]
    comp["properties"] = file_properties(f, name)
    return comp


def apply_creator(
    comp: dict[str, object],
    *,
    package_name: str,
    url: str,
    origin: str,
    gap: str,
    field_ok: bool,
) -> None:
    """The creator the build proves: ``manufacturer.url`` on the component and on
    its file components (the same fact), each marked; below CycloneDX 1.6 the
    field does not exist and the gap is named instead."""
    def add(c: dict[str, object], key: str, value: str) -> None:
        props = c.setdefault("properties", [])
        if isinstance(props, list):
            props.append(_prop(key, value))

    nested = comp.get("components")
    children = [c for c in nested if isinstance(c, dict)] if isinstance(nested, list) else []
    if url and field_ok:
        comp["manufacturer"] = {"url": [url]}
        add(comp, "evidence:creator", origin)
        for child in children:
            child["manufacturer"] = {"url": [url]}
            add(child, "evidence:creator", f"package {package_name}, {origin}")
    elif url:
        add(comp, "not-evidenced:creator", "cyclonedx_below_1.6")
    elif gap:
        add(comp, "not-evidenced:creator", gap)


def is_logical(*, excluded: bool, is_image: bool, has_files: bool, not_evidenced: str) -> bool:
    """A delivered package the build proves to be a logical component (3.2.2):
    it has file components, or its file list shows only configuration/data or
    no file at all. Never an excluded package, never an image."""
    if excluded or is_image:
        return False
    return has_files or not_evidenced in NO_FILE_REASONS


def mark_logical(comp: dict[str, object]) -> None:
    """Add the logical mark once."""
    props = comp.setdefault("properties", [])
    if isinstance(props, list) and LOGICAL not in props:
        props.append(dict(LOGICAL))
