"""The Yocto licence from the build, in the collector (coordination, 14.11.2026).

Up to 0.21 a Yocto upload carried no licence: the shared core passed none per
package, though pkgdata states it (``LICENSE:<pkg>`` before the recipe's
``LICENSE``). The core now reads it and writes it in the order of
TR-03183-2 §6.1 (SPDX, else the evidenced ScanCode reference, else
``LicenseRef-openembedded-<name>``); this pins what the collector writes:
the licence and, beside it, where the build stated it.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from jochwacht_sbom.cli import main
from jochwacht_sbom.collector import collect_components
from jochwacht_sbom.sbom_out import build_cyclonedx, upload_bytes

EXCERPT = Path(__file__).parent / "fixtures" / "yocto_scarthgap4_excerpt"
RUNTIME = Path("build/tmp/pkgdata/qemux86-64/runtime")


@pytest.fixture()
def scanned(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    shutil.copytree(EXCERPT, root / "build", symlinks=True)
    return root


def _by_name(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["name"]: c for c in doc["components"]}


def _props(comp: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in comp.get("properties", [])}


def test_the_local_bill_carries_the_licence_and_its_origin(scanned: Path) -> None:
    components, stats = collect_components(scanned)
    by = _by_name(build_cyclonedx(components, stats, project_name="fw"))
    # libc6 is glibc's package (PKG:glibc); the recipe's LICENSE, & -> AND
    assert by["libc6"]["licenses"] == [{"expression": "GPL-2.0-only AND LGPL-2.1-or-later"}]
    assert _props(by["libc6"])["jochwacht:evidence:license"] == \
        "yocto:pkgdata runtime/glibc LICENSE"
    assert by["base-files"]["licenses"] == [{"license": {"id": "GPL-2.0-only"}}]
    # no runtime file for busybox in the excerpt: no licence, none invented
    assert "licenses" not in by["busybox"]
    assert "jochwacht:evidence:license" not in _props(by["busybox"])


def test_the_upload_carries_the_licence(scanned: Path) -> None:
    components, stats = collect_components(scanned)
    by = _by_name(json.loads(upload_bytes(components, stats)))
    assert by["libc6"]["licenses"] == [{"expression": "GPL-2.0-only AND LGPL-2.1-or-later"}]
    assert _props(by["libc6"])["jochwacht:evidence:license"] == \
        "yocto:pkgdata runtime/glibc LICENSE"


@pytest.mark.parametrize(("stated", "expected"), [
    # tier 2 from the evidenced table: bzip2-1.0.4 and PD
    ("GPL-2.0-only & (bzip2-1.0.4 | PD)",
     [{"expression": "GPL-2.0-only AND (LicenseRef-scancode-bzip2-libbzip-1.0.4 OR "
                     "LicenseRef-scancode-public-domain)"}]),
    # a name without an entry: the build's words as free text, red
    # (sicherheit-2 TR1: never attributed to OpenEmbedded)
    ("GPL-2.0-only & Firmenlizenz",
     [{"license": {"name": "GPL-2.0-only & Firmenlizenz"}}]),
    # a deprecated SPDX id only through its evidenced entry (TR2): GPL-2.0 has
    # one (poky's mapping, target text matched), StandardML-NJ has none
    ("GPL-2.0", [{"license": {"id": "GPL-2.0-only"}}]),
    ("StandardML-NJ", [{"license": {"name": "StandardML-NJ"}}]),
    # a likeness poky claims without a text stays free text (sicherheit-2)
    ("MIT-style", [{"license": {"name": "MIT-style"}}]),
])
def test_names_off_the_spdx_list_follow_the_tiers(
        scanned: Path, stated: str, expected: list[dict[str, Any]]) -> None:
    netbase = scanned / RUNTIME / "netbase"
    netbase.write_text(netbase.read_text(encoding="utf-8").replace(
        "LICENSE: GPL-2.0-only", f"LICENSE: {stated}"), encoding="utf-8")
    components, stats = collect_components(scanned)
    for doc in (build_cyclonedx(components, stats, project_name="fw"),
                json.loads(upload_bytes(components, stats))):
        assert _by_name(doc)["netbase"]["licenses"] == expected


def test_the_cli_writes_it_into_sbom_cdx_json(scanned: Path) -> None:
    res = CliRunner().invoke(main, [str(scanned)])
    assert res.exit_code in (0, 2), res.output
    by = _by_name(json.loads((scanned / "sbom.cdx.json").read_text(encoding="utf-8")))
    assert by["libc6"]["licenses"] == [{"expression": "GPL-2.0-only AND LGPL-2.1-or-later"}]
