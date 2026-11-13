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
import json
import unicodedata
from pathlib import Path
from urllib.parse import quote

from jochwacht_sbom.sbom.scanner import Dependency

#: Longest package name taken from build output; a longer "name" is no
#: package (a stray line), it is left out.
MAX_NAME = 256
#: A testdata.json is the image's datastore (a few hundred KiB); larger is
#: not read.
MAX_TESTDATA_BYTES = 16 << 20


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


def _stated_candidates(folder: Path) -> list[list[str]] | None:
    """Per regular ``*.testdata.json`` in *folder* (the dated file; the
    undated name is a link): the candidate names of its manifest, by the one
    rule of the core (build_files_yocto.image_file_names: IMAGE_MANIFEST,
    IMAGE_NAME + IMAGE_NAME_SUFFIX, IMAGE_NAME, IMAGE_NAME + ".rootfs").
    None when no testdata.json states an image."""
    from jochwacht_sbom.sbom.build_files_yocto import image_file_names

    stated: list[list[str]] = []
    for testdata in sorted(folder.glob("*.testdata.json")):
        if testdata.is_symlink() or not testdata.is_file():
            continue
        try:
            if testdata.stat().st_size > MAX_TESTDATA_BYTES:
                continue
            data = json.loads(testdata.read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError):
            continue
        candidates = image_file_names(data, "manifest") if isinstance(data, dict) else []
        if candidates:
            stated.append(candidates)
    return stated or None


def stated_image_manifests(manifests: list[Path]) -> tuple[list[Path], list[str]]:
    """The manifests to read, and what to say about the rest.

    Per folder: where a testdata.json states the image(s), only each stated
    image's ``IMAGE_NAME.manifest`` — and none of the folder if one of them is
    missing (coordination 13.11.2026: the bill never names another image's
    content as the product). Without a testdata.json every manifest, as
    before, with a warning when the folder holds several different ones.
    """
    by_folder: dict[Path, list[Path]] = {}
    for mf in manifests:
        by_folder.setdefault(mf.parent, []).append(mf)
    selected: list[Path] = []
    notes: list[str] = []
    for folder, found in by_folder.items():
        stated = _stated_candidates(folder)
        if stated is None:
            selected.extend(found)
            distinct = {p.resolve() for p in found}
            if len(distinct) > 1:
                notes.append(f"warning: {len(distinct)} image manifests in "
                              f"{_clean(folder.name)} without testdata.json, all read "
                              "(which image is the product is not stated)")
            continue
        regular = {p.name: p for p in found if not p.is_symlink()}
        chosen: list[Path] = []
        missing = ""
        for candidates in stated:
            hit = next((regular[c] for c in candidates if c in regular), None)
            if hit is None:
                missing = candidates[0]
                break
            if hit not in chosen:
                chosen.append(hit)
        if missing:
            notes.append(f"skipped yocto image manifests in {_clean(folder.name)}: the stated "
                         f"image's manifest {_clean(missing)} is missing")
            continue
        selected.extend(chosen)
    return selected, notes


def scan_build_output(
    path: Path, *, max_depth: int = 5, warnings: list[str] | None = None,
) -> tuple[list[Dependency], list[str]]:
    """Find and parse Yocto/Buildroot build output under ``path``.

    Args:
        warnings: Receives the notes on stated-image manifests (folder and
            image names). Local only — never in the returned sources, which a
            collector's payload carries (decision b, sicherheit-2 MS1).

    Returns:
        (dependencies, human-readable source descriptions)
    """
    found_manifests, legal_dirs = find_build_output(path, max_depth=max_depth)
    manifests, notes = stated_image_manifests(found_manifests)
    if warnings is not None:
        warnings.extend(notes)
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
