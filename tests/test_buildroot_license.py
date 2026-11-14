"""Buildroot's licence in the order of TR-03183-2 §6.1, in the collector
(coordination, 14.11.2026: Buildroot is the main audience; 119 red licence
findings per upload must not be the first thing a customer sees).

The shared rule (licenses.buildroot_license, suite-c) gives an SPDX value or
the build's own words as free text, and the components Buildroot names in
parentheses as the scope; this pins what the collector writes from it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from test_build_hebel import _by_name, _doc, _props, _tree

from jochwacht_sbom.collector import collect_components
from jochwacht_sbom.sbom_out import upload_bytes


def _licensed(root: Path, licences: list[str]) -> Path:
    sbom = root / "output" / "legal-info" / "buildroot.cdx.json"
    doc = json.loads(sbom.read_text(encoding="utf-8"))
    doc["components"][0]["licenses"] = [{"license": {"name": n}} for n in licences]
    sbom.write_text(json.dumps(doc), encoding="utf-8")
    return root


@pytest.mark.parametrize(("parts", "licenses", "scope"), [
    # a deprecated id goes to its replacement of the SPDX list itself
    (["GPL-2.0"], [{"license": {"id": "GPL-2.0-only"}}], None),
    # parts that are all SPDX: one expression; the parentheses are the scope
    (["GPL-2.0+ (programs)", "LGPL-2.1+ (libraries)"],
     [{"expression": "GPL-2.0-or-later AND LGPL-2.1-or-later"}],
     "GPL-2.0-or-later (programs); LGPL-2.1-or-later (libraries)"),
    # a name of the evidenced table
    (["GPL-2.0", "bzip2-1.0.4"],
     [{"expression": "GPL-2.0-only AND LicenseRef-scancode-bzip2-libbzip-1.0.4"}], None),
    # free text among them: the build's words, written as a name, red
    (["Python-2.0", "others"], [{"license": {"name": "Python-2.0; others"}}], None),
])
def test_the_bill_writes_the_rule(tmp_path: Path, parts: list[str],
                                  licenses: list[dict[str, Any]], scope: str | None) -> None:
    root = _licensed(_tree(tmp_path), parts)
    components, stats = collect_components(root)
    for doc in (_doc(root), json.loads(upload_bytes(components, stats))):
        busybox = _by_name(doc)["busybox"]
        assert busybox["licenses"] == licenses
        props = _props(busybox)
        assert props.get("jochwacht:license-scope") == scope
        assert props["jochwacht:evidence:license"] == "buildroot:legal-info/buildroot.cdx.json"
        # the delivered file: a licence by part (several Buildroot parts, or
        # free text "A; B") is not inherited (sicherheit-2 BR2), any other is
        (f,) = busybox["components"]
        if len(parts) > 1:
            assert "licenses" not in f
            assert _props(f)["jochwacht:not-evidenced"] == "license_by_part"
        else:
            assert f["licenses"] == licenses


@pytest.mark.parametrize("parts", [
    # by part with a scope, and by part as plain comma parts (sicherheit-2 BR2:
    # Buildroot's manual: several comma parts are licences of different parts)
    ["GPL-2.0+ (programs)", "LGPL-2.1+ (libraries)"],
    ["GPL-2.0+", "LGPL-2.1+"],
])
def test_a_licence_by_part_is_not_inherited_by_a_delivered_file(
        tmp_path: Path, parts: list[str]) -> None:
    root = _licensed(_tree(tmp_path), parts)
    busybox = _by_name(_doc(root))["busybox"]
    assert busybox["licenses"] == [{"expression": "GPL-2.0-or-later AND LGPL-2.1-or-later"}]
    (f,) = busybox["components"]
    # which part the file falls under is not stated: no licence claimed for it
    assert "licenses" not in f
    assert _props(f)["jochwacht:not-evidenced"] == "license_by_part"


def test_a_single_or_choice_is_inherited(tmp_path: Path) -> None:
    """"A or B" is one licence choice for the whole package: the file inherits it."""
    root = _licensed(_tree(tmp_path), ["GPL-2.0+ or BSD-2-Clause"])
    (f,) = _by_name(_doc(root))["busybox"]["components"]
    assert f["licenses"] == [{"expression": "GPL-2.0-or-later OR BSD-2-Clause"}]


def _licence_file(root: Path, rel: str, text: str) -> Path:
    path = root / "output" / "legal-info" / "licenses" / "busybox-1.37.0" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_public_domain_counts_with_the_builds_dedication(tmp_path: Path) -> None:
    """suite-c 883c184: "Public domain" is ScanCode public-domain only when the
    package's licence file in legal-info dedicates the code; the sentence is
    quoted in the origin. The collector reads those files as the suite does."""
    root = _licensed(_tree(tmp_path), ["Public domain"])
    _licence_file(root, "LICENSE", "This code is released into the public domain.\n")
    busybox = _by_name(_doc(root))["busybox"]
    assert busybox["licenses"] == [{"expression": "LicenseRef-scancode-public-domain"}]
    origin = _props(busybox)["jochwacht:evidence:license"]
    assert origin.startswith("buildroot:legal-info/buildroot.cdx.json; public domain: ")
    assert "LICENSE" in origin and "/home" not in origin and str(tmp_path) not in origin


def test_public_domain_without_a_dedication_stays_free_text(tmp_path: Path) -> None:
    root = _licensed(_tree(tmp_path), ["Public domain"])
    busybox = _by_name(_doc(root))["busybox"]
    assert busybox["licenses"] == [{"license": {"name": "Public domain"}}]


def test_a_licence_file_behind_a_link_is_not_read(tmp_path: Path) -> None:
    root = _licensed(_tree(tmp_path / "t"), ["Public domain"])
    outside = tmp_path / "outside.txt"
    outside.write_text("This code is released into the public domain.\n", encoding="utf-8")
    link = root / "output" / "legal-info" / "licenses" / "busybox-1.37.0" / "LICENSE"
    link.parent.mkdir(parents=True)
    link.symlink_to(outside)
    assert _by_name(_doc(root))["busybox"]["licenses"] == [{"license": {"name": "Public domain"}}]
