"""Finding and reading a Yocto build in what the customer scans.

The reading itself is the shared core (sbom/build_files_yocto.py, one source
with the suite). This file pins how the collector finds it: a bitbake TMPDIR
with deploy/images/<machine>/*.manifest and pkgdata/, inside the scanned
path only, read with the image manifest's names. The fixture is the suite's
real excerpt of infra's tree yocto-baum-scarthgap-4 (see its README).
Order suite-d, coordination 13.11.2026.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
from pathlib import Path

import pytest

from jochwacht_sbom.yocto_build import find_yocto_builds, read_yocto_builds

EXCERPT = Path(__file__).parent / "fixtures" / "yocto_scarthgap4_excerpt"
IMAGE = "core-image-minimal-qemux86-64.rootfs-20261113162618"


@pytest.fixture()
def scanned(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    shutil.copytree(EXCERPT, root / "build", symlinks=True)
    return root


def test_the_tmpdir_is_found_inside(scanned: Path) -> None:
    assert find_yocto_builds(scanned) == [scanned / "build" / "tmp"]


def test_a_link_out_of_the_scanned_path_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    shutil.copytree(EXCERPT, outside, symlinks=True)
    scanned = tmp_path / "project"
    scanned.mkdir()
    os.symlink(outside, scanned / "build")
    assert find_yocto_builds(scanned) == []


def test_read_with_the_manifest_names(scanned: Path) -> None:
    (read,) = read_yocto_builds(scanned)
    names = [n for n, _ in read.packages]
    assert ("base-files", "3.0.14") in read.packages
    assert [e.name for e in read.build.entries] == names
    by = {e.name: e for e in read.build.entries}
    with tarfile.open(scanned / "build/tmp/deploy/images/qemux86-64" / f"{IMAGE}.tar.bz2") as tf:
        data = tf.extractfile("./bin/start_getty").read()  # type: ignore[union-attr]
    (f,) = by["sysvinit-inittab"].files
    assert (f.path, f.sha512, f.executable) == (
        "bin/start_getty", hashlib.sha512(data).hexdigest(), True)
    assert not any(e.excluded for e in read.build.entries)  # the manifest's own names
    assert read.build.product_name == "core-image-minimal"
    assert [r.path for r in read.build.images] == [f"{IMAGE}.tar.bz2"]


def test_without_a_manifest_there_is_no_build(scanned: Path) -> None:
    for p in (scanned / "build/tmp/deploy/images").rglob("*.manifest"):
        p.unlink()
    assert read_yocto_builds(scanned) == []
