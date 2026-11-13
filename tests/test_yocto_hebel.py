"""A Yocto build directory in the collector (0.20, coordination 13.11.2026).

suite-d's finder (``yocto_build.py``) and the shared core
(``sbom/build_files_yocto.py``) read the build; this file pins what the
collector writes from it: the LOCAL bill carries the delivered files with
SHA-512 and their proven properties, the image files as components of type
file, the creator the build proves. The upload stays names and versions.
The fixture is the suite's real excerpt of yocto-baum-scarthgap-4.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from jochwacht_sbom.collector import collect_components
from jochwacht_sbom.sbom_out import build_cyclonedx, slim_bytes

EXCERPT = Path(__file__).parent / "fixtures" / "yocto_scarthgap4_excerpt"
IMAGE = "core-image-minimal-qemux86-64.rootfs-20261113162618"


@pytest.fixture()
def scanned(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    shutil.copytree(EXCERPT, root / "build", symlinks=True)
    return root


def _props(comp: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in comp.get("properties", [])}


def test_the_local_bill_carries_the_delivered_files(scanned: Path) -> None:
    components, stats = collect_components(scanned)
    doc = build_cyclonedx(components, stats, project_name="fw")
    by = {c["name"]: c for c in doc["components"]}
    inittab = by["sysvinit-inittab"]
    (f,) = inittab["components"]
    assert f["type"] == "file" and f["name"] == "start_getty"
    assert f["hashes"][0]["alg"] == "SHA-512"
    assert _props(f)["bsi:component:executable"] == "true"
    assert _props(f)["jochwacht:evidence:path"] == "bin/start_getty"
    assert _props(inittab)["jochwacht:component-kind"] == "logical"
    assert by[f"{IMAGE}.tar.bz2"]["type"] == "file"


def test_each_manifest_package_is_listed_once(scanned: Path) -> None:
    components, _ = collect_components(scanned)
    names = [c.name for c in components if c.ecosystem == "yocto"]
    assert names.count("base-files") == 1
    assert len(names) == len(set(names))
    base = next(c for c in components if c.name == "base-files")
    assert base.version == "3.0.14"
    assert base.local_purl.startswith("pkg:")


def test_the_upload_stays_names_and_versions(scanned: Path) -> None:
    components, stats = collect_components(scanned)
    text = slim_bytes(components, stats, project_name="fw").decode("utf-8")
    for leaked in ("SHA-512", '"hashes"', '"manufacturer"', "jochwacht:evidence",
                   "component-kind", "bsi:component", IMAGE):
        assert leaked not in text, leaked
    doc = json.loads(text)
    assert all("components" not in c for c in doc["components"])
    assert {"base-files", "sysvinit-inittab"} <= {c["name"] for c in doc["components"]}


def test_a_second_manifest_only_tree_keeps_its_rows(scanned: Path) -> None:
    """Only the rows of the build that was read are replaced; a manifest
    without pkgdata/ elsewhere in the path still counts."""
    other = scanned / "other" / "deploy" / "images" / "m"
    other.mkdir(parents=True)
    (other / "img-m.rootfs.manifest").write_text(
        "zlib core2_64 1.3.1\nbase-files qemux86_64 3.0.14\n", encoding="utf-8")
    components, _ = collect_components(scanned)
    names = [c.name for c in components if c.ecosystem == "yocto"]
    assert "zlib" in names
    assert names.count("base-files") == 1


def _rewrite_rootfs(scanned: Path, extra: list[tuple[str, bytes]]) -> None:
    import io
    import tarfile

    path = scanned / "build/tmp/deploy/images/qemux86-64" / f"{IMAGE}.tar.bz2"
    with tarfile.open(path) as tf:
        members = [(m, tf.extractfile(m).read() if m.isfile() else None)  # type: ignore[union-attr]
                   for m in tf.getmembers()]
    with tarfile.open(path, "w:bz2") as tf:
        for m, data in members:
            tf.addfile(m, io.BytesIO(data) if data is not None else None)
        for name, data in extra:
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755
            tf.addfile(info, io.BytesIO(data))


def test_sy1_a_duplicate_rootfs_path_is_said(scanned: Path) -> None:
    """sicherheit-2 SY1: the reader's warnings reach the customer, not only
    the suite's import."""
    from click.testing import CliRunner

    from jochwacht_sbom.cli import main

    _rewrite_rootfs(scanned, [("./bin/start_getty", b"#!/bin/sh\nchanged\n")])
    _, stats = collect_components(scanned)
    assert any("appear more than once" in w and "bin/start_getty" in w
               for w in stats.build_warnings), stats.build_warnings
    res = CliRunner().invoke(main, [str(scanned)])
    assert res.exit_code == 0, res.output
    assert "appear more than once" in " ".join(res.output.split())


def test_sy1_a_rootfs_over_the_limit_is_said(scanned: Path, monkeypatch: Any) -> None:
    from jochwacht_sbom.sbom import build_files_yocto

    monkeypatch.setattr(build_files_yocto, "MAX_ROOTFS_MEMBERS", 1)
    _, stats = collect_components(scanned)
    assert any("rootfs not read" in w for w in stats.build_warnings), stats.build_warnings
    sent = json.dumps(stats.model_dump())
    assert "build_warnings" not in sent  # local only, never uploaded


def test_the_local_bill_names_the_product_the_build_states(scanned: Path) -> None:
    """suite-d's parity finding: the suite writes the image recipe
    (IMAGE_BASENAME, PV of testdata.json) as metadata.component; the collector
    wrote the folder name and 'unspecified'. The upload keeps its header."""
    from jochwacht_sbom.yocto_build import read_yocto_builds

    (read,) = read_yocto_builds(scanned)
    components, stats = collect_components(scanned)
    meta = build_cyclonedx(components, stats, project_name="project")["metadata"]["component"]
    assert (meta["name"], meta["version"]) == (
        read.build.product_name, read.build.product_version) == ("core-image-minimal", "1.0")
    sent = json.loads(slim_bytes(components, stats, project_name="project"))
    assert sent["metadata"]["component"]["name"] == "project"


def test_two_builds_name_no_product(scanned: Path, tmp_path: Path) -> None:
    shutil.copytree(EXCERPT, scanned / "zweiter", symlinks=True)
    components, stats = collect_components(scanned)
    meta = build_cyclonedx(components, stats, project_name="project")["metadata"]["component"]
    assert (meta["name"], meta["version"]) == ("project", "unspecified")


@pytest.mark.skipif(__import__("sys").platform == "win32",
                    reason="symbolic links need privileges on Windows")
def test_y1_a_root_linked_out_of_the_build_is_named(scanned: Path, tmp_path: Path) -> None:
    """suite-c Y1 (shared core): a root of the reading that is a link out of
    the build directory is not read; the collector names it in the summary."""
    import os

    from click.testing import CliRunner

    from jochwacht_sbom.cli import main

    rpm = scanned / "build" / "tmp" / "deploy" / "rpm"
    outside = tmp_path / "elsewhere" / "rpm"
    shutil.move(str(rpm), str(outside))
    os.symlink(outside, rpm)
    _, stats = collect_components(scanned)
    assert any("deploy/rpm points outside the build directory" in w
               for w in stats.build_warnings), stats.build_warnings
    res = CliRunner().invoke(main, [str(scanned)])
    assert res.exit_code == 0, res.output
    assert "points outside the build directory" in " ".join(res.output.split())


@pytest.mark.skipif(__import__("sys").platform == "win32",
                    reason="symbolic links need privileges on Windows")
@pytest.mark.parametrize("rel", [
    "tmp", "tmp/deploy", "tmp/deploy/images", "tmp/deploy/images/qemux86-64", "tmp/pkgdata",
])
def test_a_build_part_linked_outside_is_named_never_read(
    scanned: Path, tmp_path: Path, rel: str,
) -> None:
    """sicherheit-2 on 31735f7: with tmp, deploy, images or the machine folder
    a link out of the scanned folder, the Yocto build fell away silently (1
    instead of 37 components, no line). Nothing is read from outside, and the
    customer is told which link was not followed."""
    import os

    from click.testing import CliRunner

    from jochwacht_sbom.cli import main

    inside = scanned / "build" / rel
    outside = tmp_path / "elsewhere" / Path(rel).name
    outside.parent.mkdir()
    shutil.move(str(inside), str(outside))
    os.symlink(outside, inside)
    components, stats = collect_components(scanned)
    assert not any(c.delivered_files for c in components)  # nothing read from outside
    # the core names a root it would read (relative to TMPDIR, prefixed with
    # the build); the collector names a part that hides the whole build
    expected = ("Yocto build at build/tmp: pkgdata points outside" if rel == "tmp/pkgdata"
                else f"Yocto build part build/{rel} points outside")
    assert any(expected in w for w in stats.build_warnings), stats.build_warnings
    res = CliRunner().invoke(main, [str(scanned)])
    # nothing read is exit 2 (no build found), the found build with an
    # outside root exit 0; both say which link was not followed
    assert res.exit_code == (0 if rel == "tmp/pkgdata" else 2), res.output
    assert expected in " ".join(res.output.split())


@pytest.mark.skipif(__import__("sys").platform == "win32",
                    reason="symbolic links need privileges on Windows")
def test_an_unrelated_link_out_is_not_called_a_yocto_build(tmp_path: Path) -> None:
    import os

    proj = tmp_path / "proj"
    (proj / "conf").mkdir(parents=True)
    (proj / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "scratch").mkdir()
    os.symlink(tmp_path / "scratch", proj / "tmp")
    (tmp_path / "pics" / "images").mkdir(parents=True)
    os.symlink(tmp_path / "pics" / "images", proj / "images")
    _, stats = collect_components(proj)
    assert stats.build_warnings == []
