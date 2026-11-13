"""Finding and reading a Buildroot build in what the customer scans.

The reading itself is the shared core (sbom/build_files.py, one source with
the suite). This file pins how the collector finds a build folder: inside the
scanned path only, the Buildroot folder of an in-tree build when it lies
inside, otherwise output/. Order suite-c, coordination 13.11.2026.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from jochwacht_sbom.buildroot_build import find_buildroot_builds, read_buildroot_builds

ELF = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 56


def _output(out: Path) -> Path:
    (out / "build").mkdir(parents=True)
    (out / "target" / "bin").mkdir(parents=True)
    (out / "target" / "bin" / "busybox").write_bytes(ELF)
    (out / "target" / "bin" / "busybox").chmod(0o755)
    (out / "build" / "packages-file-list.txt").write_text("busybox,./bin/busybox\n",
                                                           encoding="utf-8")
    legal = out / "legal-info"
    legal.mkdir()
    (legal / "buildroot.cdx.json").write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "metadata": {"component": {"bom-ref": "zc706", "name": "zc706",
                                   "version": "1.0", "type": "firmware"}},
        "components": [
            {"bom-ref": "busybox", "type": "library", "name": "busybox",
             "version": "1.37.0", "licenses": [{"license": {"id": "GPL-2.0"}}],
             "properties": [{"name": "BR_TYPE", "value": "target"}]},
            {"bom-ref": "host-m4", "type": "library", "name": "m4", "version": "1.4.20",
             "properties": [{"name": "BR_TYPE", "value": "host"}]}]}), encoding="utf-8")
    return out


def test_an_o_build_output_folder(tmp_path: Path) -> None:
    out = _output(tmp_path / "work" / "output")
    assert find_buildroot_builds(tmp_path) == [out]


def test_an_in_tree_build_gives_the_buildroot_folder(tmp_path: Path) -> None:
    root = tmp_path / "buildroot"
    _output(root / "output")
    (root / "package").mkdir()
    (root / ".config").write_text("# Buildroot 2025.08.2 Configuration\n", encoding="utf-8")
    assert find_buildroot_builds(tmp_path) == [root]


def test_the_scanned_folder_itself(tmp_path: Path) -> None:
    out = _output(tmp_path / "output")
    assert find_buildroot_builds(out) == [out]


def test_scanning_output_of_an_in_tree_build_stays_inside(tmp_path: Path) -> None:
    """The Buildroot folder around output/ lies outside what was scanned:
    output/ is read, never its parent."""
    root = tmp_path / "buildroot"
    out = _output(root / "output")
    (root / "package").mkdir()
    (root / ".config").write_text("# Buildroot 2025.08.2 Configuration\n", encoding="utf-8")
    assert find_buildroot_builds(out) == [out]


def test_scanning_legal_info_alone_reads_nothing_above_it(tmp_path: Path) -> None:
    out = _output(tmp_path / "output")
    assert find_buildroot_builds(out / "legal-info") == []


def test_nothing_outside_the_scanned_path(tmp_path: Path) -> None:
    _output(tmp_path / "elsewhere" / "output")
    scanned = tmp_path / "scan"
    scanned.mkdir()
    os.symlink(tmp_path / "elsewhere", scanned / "link")
    assert find_buildroot_builds(scanned) == []


def test_no_build_no_result(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    assert find_buildroot_builds(tmp_path) == []
    assert read_buildroot_builds(tmp_path) == []


def test_reading_goes_through_the_shared_core(tmp_path: Path) -> None:
    _output(tmp_path / "output")
    (build,) = read_buildroot_builds(tmp_path)
    assert (build.product_name, build.product_version) == ("zc706", "1.0")
    by = {p.package.name: p for p in build.packages}
    assert [f.path for f in by["busybox"].files] == ["bin/busybox"]
    assert by["m4"].not_evidenced == "not_delivered"
    assert by["m4"].scope_reason.startswith("Buildroot host package (host-m4)")
    assert {p.package.name for p in build.delivered_packages()} == {"busybox"}
