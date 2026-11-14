"""An unusable testdata.json still states an image (suite-d R3/P2, cbbc9dd).

The coordination, 14.11.2026: this is a state of the customer's build. The
collector names it as such ("the scope of delivery is unknown") and marks the
bill incomplete, without calling it a defect of its own.

Up to 0.21 the shared core skipped a regular testdata.json it could not read
or that stated no IMAGE_NAME; the image then counted as not stated, every
manifest of the folder was read, and another image's manifest could mark
packages excluded without a word. In the collector that made libattr1 and
libedit0 of the excerpt "not shipped". Now the scope of delivery is unknown:
named, and nothing is excluded.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from jochwacht_sbom import diagnosis
from jochwacht_sbom.cli import main
from jochwacht_sbom.collector import collect_components

EXCERPT = Path(__file__).parent / "fixtures" / "yocto_scarthgap4_excerpt"
IMAGES = Path("build/tmp/deploy/images/qemux86-64")
STAMP = "core-image-minimal-qemux86-64.rootfs-20261113162618"


@pytest.fixture()
def scanned(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    shutil.copytree(EXCERPT, root / "build", symlinks=True)
    folder = root / IMAGES
    # the stated image's manifest is gone, another image's lies in the folder
    (folder / f"{STAMP}.manifest").rename(folder / "other-image-qemux86-64.rootfs.manifest")
    (folder / "core-image-minimal-qemux86-64.rootfs.manifest").unlink()
    return root


@pytest.mark.parametrize("content", ["{not json", "[]", '{"IMAGE_NAME": 5}'])
def test_the_foreign_manifest_does_not_decide(scanned: Path, content: str) -> None:
    (scanned / IMAGES / f"{STAMP}.testdata.json").write_text(content, encoding="utf-8")
    diagnosis.reset()
    components, _ = collect_components(scanned)
    # coordination, 14.11.2026: a state of the customer's build, named as
    # such and without blame; the bill is still marked incomplete
    assert [f for f in diagnosis.failures() if f.reader == "yocto_build"] == []
    assert not any(c.ecosystem == "yocto" for c in components)
    res = CliRunner().invoke(main, [str(scanned)])
    out = " ".join(res.output.split())
    assert f"{STAMP}.testdata.json cannot be read or states no IMAGE_NAME" in out, out
    assert "Yocto build at build/tmp: the scope of delivery is unknown" in out, out
    assert "the bill of materials is INCOMPLETE" in out
    assert "defect" not in out.lower() and "reader failed" not in out, out
    assert not (scanned / "jochwacht-sbom-diagnosis.json").exists()


def test_a_yocto_build_without_any_manifest_is_named_not_missed(tmp_path: Path) -> None:
    """sicherheit-2 H2 (14.11.2026): the image states itself in testdata.json,
    but the folder holds no manifest at all. Up to 0.21 the build was found only
    through its manifests and the run said "No supported build system found"."""
    root = tmp_path / "project"
    shutil.copytree(EXCERPT, root / "build", symlinks=True)
    for manifest in (root / IMAGES).glob("*.manifest"):
        manifest.unlink()
    diagnosis.reset()
    components, stats = collect_components(root)
    assert not any(c.ecosystem == "yocto" for c in components)
    assert any("the scope of delivery is unknown" in w and "manifest is missing" in w
               for w in stats.build_warnings), stats.build_warnings
    assert [f for f in diagnosis.failures() if f.reader == "yocto_build"] == []
    res = CliRunner().invoke(main, [str(root)])
    out = " ".join(res.output.split())
    assert "No supported build system found" not in out, out
    assert "A Yocto build was found, but which packages its image installs is unknown" \
        in out, out
