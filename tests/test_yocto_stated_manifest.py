"""A stated Yocto image without its own manifest (suite fix, coordination
13.11.2026): the Yocto BUILD reading uses no other image's manifest — it is
recorded as a reader failure, so no build evidence (scope, files, creator)
comes from a foreign image. The older generic build-output reader (0.19,
sbom/buildoutput.py) still lists every *.manifest of the folder as plain
components; that is pinned here as it is, pending a decision."""

from __future__ import annotations

import shutil
from pathlib import Path

from jochwacht_sbom import diagnosis
from jochwacht_sbom.collector import collect_components

EXCERPT = Path(__file__).parent / "fixtures" / "yocto_scarthgap4_excerpt"
IMAGES = Path("build/tmp/deploy/images/qemux86-64")
STAMP = "core-image-minimal-qemux86-64.rootfs-20261113162618"


def _yocto(tmp_path: Path) -> Path:
    root = tmp_path / "yocto"
    shutil.copytree(EXCERPT, root / "build", symlinks=True)
    return root


def test_reads_the_stated_manifest(tmp_path: Path) -> None:
    diagnosis.reset()
    components, _ = collect_components(_yocto(tmp_path))
    assert any(c.name == "libc6" for c in components)
    assert not [f for f in diagnosis.failures() if f.reader == "yocto_build"]


def test_never_reads_another_image_s_manifest(tmp_path: Path) -> None:
    root = _yocto(tmp_path)
    folder = root / IMAGES
    (folder / f"{STAMP}.manifest").rename(folder / "other-image-qemux86-64.rootfs.manifest")
    (folder / "core-image-minimal-qemux86-64.rootfs.manifest").unlink()
    diagnosis.reset()
    components, _ = collect_components(root)
    failed = [f for f in diagnosis.failures() if f.reader == "yocto_build"]
    assert [f.exc_type for f in failed] == ["ManifestUnreadableError"]
    # No component carries Yocto build evidence; what remains comes from the
    # generic build-output reader only.
    assert {c.source_type for c in components if c.ecosystem == "yocto"} <= {"build-output"}
    assert not any(c.delivered_files or c.delivered_image for c in components)
