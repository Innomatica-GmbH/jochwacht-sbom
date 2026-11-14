"""Finding a Yocto build in what the customer scans, and reading it.

The reading is the shared core (``sbom/build_files_yocto.py``, generated from
the suite by ci/sync-twin.py): the scope of delivery from the image
manifest, the regular files of the rootfs per runtime package with SHA-512
and their proven properties, image files, kernel, the creator URL. This file
only finds the build folders (bitbake's TMPDIR), inside the scanned path and
nowhere else. The writer onto CheckComponent and the call in the collector
are suite-b's; the upload stays names and versions (coordination 13.11.2026).

Order suite-d, coordination 13.11.2026 (collector 0.20/0.21).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from jochwacht_sbom.sbom.build_files_yocto import (
    ManifestUnreadableError,
    YoctoBuildEvidence,
    yocto_build,
    yocto_manifest_entries,
)
from jochwacht_sbom.sbom.buildoutput import find_build_output, find_yocto_image_folders

if TYPE_CHECKING:
    from pathlib import Path


@dataclass
class YoctoBuildRead:
    """One Yocto build: where it is, what the image installs, what it proves."""

    tmp_dir: Path
    #: (name, version) of the image manifest(s), in their order.
    packages: list[tuple[str, str]]
    build: YoctoBuildEvidence


def _inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
    except OSError:
        return False


def find_yocto_builds(path: Path) -> list[Path]:
    """The bitbake TMPDIRs under *path* (none from outside it).

    An image manifest lies in ``<TMPDIR>/deploy/images/<machine>/``; the
    folder counts when it also holds ``pkgdata/`` and lies inside *path*.
    """
    manifests, _ = find_build_output(path)
    # sicherheit-2 H2: an image folder that states itself (testdata.json) but
    # holds no manifest is a Yocto build too; its gap is named, never missed.
    folders = [m.parent for m in manifests] + find_yocto_image_folders(path)
    found: list[Path] = []
    for folder in folders:
        parents = [folder, *folder.parents]
        if len(parents) < 4:
            continue
        tmp = parents[3]
        if (parents[1].name == "images" and parents[2].name == "deploy"
                and (tmp / "pkgdata").is_dir() and _inside(tmp, path) and tmp not in found):
            found.append(tmp)
    return found


def read_yocto_builds(path: Path, gaps: list[tuple[Path, str]] | None = None,
                      ) -> list[YoctoBuildRead]:
    """Every Yocto build under *path*, read by the shared core with the
    image manifest's names (the suite passes its create-spdx names; the
    evidence per name is the same, tested in the suite).

    *gaps*: receives (TMPDIR, reason) for a build whose stated image's
    manifest is missing or unknown (an unusable testdata.json): a state of
    the customer's build, not a defect of the reader (coordination,
    14.11.2026). Without *gaps* the ManifestUnreadableError is raised.
    """
    out: list[YoctoBuildRead] = []
    for tmp in find_yocto_builds(path):
        try:
            packages = yocto_manifest_entries(tmp)
        except ManifestUnreadableError as exc:
            if gaps is None:
                raise
            gaps.append((tmp, str(exc)))
            continue
        if not packages:
            continue
        out.append(YoctoBuildRead(tmp, packages, yocto_build(tmp, [n for n, _ in packages])))
    return out
