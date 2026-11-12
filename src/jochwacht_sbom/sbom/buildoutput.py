"""Yocto/Buildroot BUILD OUTPUT readers.

What is authoritative for an image is the build output —
``deploy/images/**/*.manifest`` (what is IN the image) and Buildroot's
``legal-info/manifest.csv`` — not the recipe source tree, which only says
what could be built.

Shared file: the open collector carries a generated copy (ci/sync-twin.py),
so both tools read build output with the same code.
"""

from __future__ import annotations

import csv
import unicodedata
from pathlib import Path
from urllib.parse import quote

from jochwacht_sbom.sbom.scanner import Dependency

#: Longest package name taken from build output; a longer "name" is no
#: package (a stray line), it is left out.
MAX_NAME = 256


def _clean(text: str) -> str:
    """Without control and format characters (U+202E and friends)."""
    return "".join(ch for ch in text if unicodedata.category(ch) not in ("Cc", "Cf"))


def _inside(entry: Path, root: Path) -> bool:
    """Whether *entry*, links resolved, lies in *root*."""
    try:
        return entry.resolve().is_relative_to(root)
    except OSError:
        return False


def _purl(kind: str, name: str, version: str) -> str:
    """A purl with name and version percent-encoded (``a@9?x`` stays one name)."""
    base = f"pkg:{kind}/{quote(name, safe='')}"
    return f"{base}@{quote(version, safe='.+-_~')}" if version else base


def parse_yocto_manifest_file(path: Path) -> list[Dependency]:
    """Parse ONE Yocto image manifest (``name arch version`` lines).

    A line with a name only keeps the name and no version: a missing
    version is shown as missing, never invented.
    """
    deps: list[Dependency] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            name, version = parts[0], parts[2]
        elif len(parts) == 2:
            name, version = parts[0], parts[1]
        else:
            name, version = parts[0], ""
        name, version = _clean(name), _clean(version)
        if not name or len(name) > MAX_NAME:
            continue
        deps.append(Dependency(
            name=name, version=version, ecosystem="yocto",
            purl=_purl("yocto", name, version),
        ))
    return deps


def parse_buildroot_manifest_csv(path: Path) -> list[Dependency]:
    """Parse Buildroot's ``legal-info/manifest.csv``.

    Layout (``make legal-info``): quoted CSV with the columns PACKAGE,
    VERSION, LICENSE, LICENSE FILES, SOURCE ARCHIVE, SOURCE SITE,
    DEPENDENCIES WITH LICENSES. ``host-manifest.csv`` (build-host tooling)
    is deliberately not parsed: host tools never ship in the image.
    """
    deps: list[Dependency] = []
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if not header or header[0].strip().upper() != "PACKAGE":
            return deps
        for row in reader:
            if len(row) < 2 or not row[0].strip():
                continue
            name, version = _clean(row[0].strip()), _clean(row[1].strip())
            if not name or len(name) > MAX_NAME:
                continue
            license_id = _clean(row[2].strip()) if len(row) > 2 else ""
            deps.append(Dependency(
                name=name, version=version, ecosystem="buildroot",
                license=license_id or None,
                purl=_purl("buildroot", name, version),
            ))
    return deps


def find_build_output(path: Path, *, max_depth: int = 5) -> tuple[list[Path], list[Path]]:
    """``(yocto image manifests, legal-info directories)`` under ``path``.

    Nothing whose resolved path lies outside ``path`` is taken: a manifest
    or a directory that is a symbolic link out of the tree is skipped, so
    no file from elsewhere becomes components.
    """
    manifests: list[Path] = []
    legal_dirs: list[Path] = []
    root = path.resolve()

    def _walk(current: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = sorted(current.iterdir())
        except OSError:
            return
        for entry in entries:
            if not _inside(entry, root):
                continue
            if entry.is_dir():
                if entry.name.startswith(".") or entry.name in ("sources", "host-sources"):
                    continue
                if entry.name == "legal-info":
                    legal_dirs.append(entry)
                    continue
                _walk(entry, depth + 1)
            elif entry.name.endswith(".rootfs.manifest") or (
                entry.name.endswith(".manifest") and "images" in current.parts
            ):
                manifests.append(entry)

    _walk(path, 0)
    return manifests, legal_dirs


def scan_build_output(
    path: Path, *, max_depth: int = 5,
) -> tuple[list[Dependency], list[str]]:
    """Find and parse Yocto/Buildroot build output under ``path``.

    Returns:
        (dependencies, human-readable source descriptions)
    """
    manifests, legal_dirs = find_build_output(path, max_depth=max_depth)
    deps: list[Dependency] = []
    sources: list[str] = []
    for mf in manifests:
        try:
            found = parse_yocto_manifest_file(mf)
        except (OSError, UnicodeDecodeError) as exc:
            # One unusual file must not end the run.
            sources.append(f"skipped yocto image manifest {mf.name}: {type(exc).__name__}")
            continue
        if found:
            deps.extend(found)
            sources.append(f"yocto image manifest {mf.name} ({len(found)} packages)")
    for legal in legal_dirs:
        csv_file = legal / "manifest.csv"
        if not csv_file.is_file():
            continue
        if not _inside(csv_file, path.resolve()):
            continue
        try:
            found = parse_buildroot_manifest_csv(csv_file)
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            sources.append(f"skipped buildroot legal-info manifest.csv: {type(exc).__name__}")
            continue
        if found:
            deps.extend(found)
            sources.append(f"buildroot legal-info manifest.csv ({len(found)} packages)")
    return deps, sources
