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
