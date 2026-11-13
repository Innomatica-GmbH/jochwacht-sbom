"""A stated Yocto image without its own manifest (suite fix, coordination
13.11.2026): the Yocto BUILD reading uses no other image's manifest — it is
recorded as a reader failure, so no build evidence (scope, files, creator)
comes from a foreign image. Decision (b): the generic build-output rows
(collector._scan_build_output) read only the stated image's manifest too;
without a testdata.json as in 0.19, with a local warning for several."""

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
    # No component carries Yocto build evidence, and (b) no generic row
    # either: nothing of the foreign image is named.
    assert not any(c.ecosystem == "yocto" for c in components)


# --- decision (b): the generic build-output rows (collector._scan_build_output) ---


def _without_testdata(root: Path) -> None:
    for testdata in (root / IMAGES).glob("*.testdata.json"):
        testdata.unlink()


def test_b1_foreign_manifest_only_gives_no_row_and_is_named(tmp_path: Path) -> None:
    root = _yocto(tmp_path)
    folder = root / IMAGES
    (folder / f"{STAMP}.manifest").rename(folder / "other-image-qemux86-64.rootfs.manifest")
    (folder / "core-image-minimal-qemux86-64.rootfs.manifest").unlink()
    components, stats = collect_components(root)
    assert not any(c.name == "libc6" for c in components)
    assert any("stated image's manifest" in w for w in stats.build_warnings)


def test_b2_own_and_foreign_only_own(tmp_path: Path) -> None:
    root = _yocto(tmp_path)
    (root / IMAGES / "other-image-qemux86-64.rootfs.manifest").write_text(
        "only-in-the-other-image core2_64 1.0\n", encoding="utf-8")
    components, _ = collect_components(root)
    assert any(c.name == "libc6" for c in components)
    assert not any(c.name == "only-in-the-other-image" for c in components)


def test_b3_without_testdata_both_rows_and_a_warning(tmp_path: Path) -> None:
    root = _yocto(tmp_path)
    _without_testdata(root)
    (root / IMAGES / "other-image-qemux86-64.rootfs.manifest").write_text(
        "only-in-the-other-image core2_64 1.0\n", encoding="utf-8")
    components, stats = collect_components(root)
    names = {c.name for c in components}
    assert {"libc6", "only-in-the-other-image"} <= names
    assert any("2 image manifests" in w for w in stats.build_warnings)


def test_b4_nothing_new_leaves_the_house(tmp_path: Path) -> None:
    from jochwacht_sbom.sbom_out import slim_bytes

    root = _yocto(tmp_path)
    folder = root / IMAGES
    (folder / f"{STAMP}.manifest").rename(folder / "other-image-qemux86-64.rootfs.manifest")
    (folder / "core-image-minimal-qemux86-64.rootfs.manifest").unlink()
    from jochwacht_sbom.payload import build_payload

    components, stats = collect_components(root)
    # Both ways out: the slim SBOM (subscription upload) and the check payload
    # JSON (upload_payload sends payload.model_dump_json()).
    payload = build_payload(voucher="", contact_email="", tool_version="t",
                            project_label="fw", components=components, stats=stats)
    for sent in (slim_bytes(components, stats, project_name="fw").decode(),
                 payload.model_dump_json()):
        assert "stated image" not in sent and "testdata" not in sent
        assert STAMP not in sent and "qemux86-64" not in sent
