"""Finding a Buildroot build in what the customer scans, and reading it.

The reading is the shared core (``sbom/build_files.py``, generated from the
suite by ci/sync-twin.py): Buildroot's own SBOM, the delivered files with
SHA-512 and their proven properties, images/, the creator URL. This file
only finds the build folders, inside the scanned path and nowhere else.
The writer onto CheckComponent and the call in the collector are suite-b's.

Order suite-c, coordination 13.11.2026 (collector 0.20).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from jochwacht_sbom.sbom.build_files import BuildrootBuild, read_buildroot_build
from jochwacht_sbom.sbom.buildoutput import find_build_output

if TYPE_CHECKING:
    from pathlib import Path


def _inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
    except OSError:
        return False


def _build_root(legal_info: Path, scanned: Path) -> Path | None:
    """The folder to read for a legal-info/ that holds Buildroot's SBOM.

    An in-tree build (the Buildroot folder with .config and package/ around
    output/) gives that folder, so the creator URLs are found; otherwise
    output/ itself. Only inside the scanned path.
    """
    if not (legal_info / "buildroot.cdx.json").is_file():
        return None
    out = legal_info.parent
    top = out.parent
    if (out.name == "output" and _inside(top, scanned) and (top / ".config").is_file()
            and (top / "package").is_dir()):
        return top
    # Defensive: find_build_output yields legal-info/ folders below *scanned*
    # only, so output/ lies inside; kept should the finder ever change.
    return out if _inside(out, scanned) else None


def find_buildroot_builds(path: Path) -> list[Path]:
    """The Buildroot build folders under *path* (none from outside it)."""
    _, legal_dirs = find_build_output(path)
    found: list[Path] = []
    for legal in legal_dirs:
        root = _build_root(legal, path)
        if root is not None and root not in found:
            found.append(root)
    return found


def read_buildroot_builds(
    path: Path, *, buildroot_source: Path | None = None,
) -> list[BuildrootBuild]:
    """Every Buildroot build under *path*, read by the shared core.

    *buildroot_source*: the Buildroot tree of an O= build outside *path*,
    read only if the build's output/Makefile names exactly it. Whoever scans
    foreign build folders does not pass it.
    """
    builds: list[BuildrootBuild] = []
    for root in find_buildroot_builds(path):
        build = read_buildroot_build(root, buildroot_source=buildroot_source)
        if build is not None:
            builds.append(build)
    return builds
