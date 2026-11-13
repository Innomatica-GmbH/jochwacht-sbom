"""The build directory in the collector (0.20, coordination 13.11.2026).

A Buildroot build in the scanned path is read by the shared core
(``sbom/build_files.py``) and written by the shared writer
(``sbom/cdx_files.py``): the LOCAL bill carries the delivered files with
SHA-512, their proven properties, the creator the build proves and the host
packages as not shipped. What ``--send`` uploads stays as slim as in 0.19:
names, versions and the customer's own declarations; nothing of the build
evidence leaves the house without the customer's explicit choice.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

from jochwacht_sbom.collector import collect_components
from jochwacht_sbom.sbom_out import build_cyclonedx, slim_bytes

ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57


def _tree(root: Path) -> Path:
    out = root / "output"
    (out / "legal-info").mkdir(parents=True)
    (out / "legal-info" / "buildroot.cdx.json").write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "metadata": {"component": {"bom-ref": "buildroot", "name": "buildroot",
                                   "version": "2025.08.2", "type": "firmware"}},
        "components": [
            {"bom-ref": "busybox", "name": "busybox", "version": "1.37.0",
             "licenses": [{"license": {"id": "GPL-2.0"}}],
             "cpe": "cpe:2.3:a:busybox:busybox:1.37.0:-:*:*:*:*:*:*"},
            {"bom-ref": "host-gcc", "name": "gcc", "version": "14.2.0",
             "licenses": [{"license": {"id": "GPL-3.0+"}}]},
        ]}), encoding="utf-8")
    (out / "build").mkdir()
    (out / "build" / "packages-file-list.txt").write_text(
        "busybox,./bin/busybox\nbusybox,./etc/inittab\n", encoding="utf-8")
    (out / "target" / "bin").mkdir(parents=True)
    (out / "target" / "etc").mkdir()
    exe = out / "target" / "bin" / "busybox"
    exe.write_bytes(ELF)
    exe.chmod(0o755)
    (out / "target" / "etc" / "inittab").write_text("::sysinit\n", encoding="utf-8")
    return root


def _doc(root: Path, *, full: bool = True) -> dict[str, Any]:
    components, stats = collect_components(root)
    return build_cyclonedx(components, stats, project_name="fw", full=full)


def _by_name(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["name"]: c for c in doc["components"]}


def _props(comp: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in comp.get("properties", [])}


def test_the_local_bill_carries_the_delivered_file(tmp_path: Path) -> None:
    busybox = _by_name(_doc(_tree(tmp_path)))["busybox"]
    files = busybox["components"]
    assert [f["name"] for f in files] == ["busybox"]
    assert files[0]["type"] == "file"
    assert files[0]["hashes"][0]["alg"] == "SHA-512"
    props = _props(files[0])
    assert props["bsi:component:executable"] == "true"
    assert props["jochwacht:evidence:path"] == "bin/busybox"
    assert _props(busybox)["jochwacht:component-kind"] == "logical"


def test_the_local_bill_keeps_licence_and_cpe_from_buildroot(tmp_path: Path) -> None:
    busybox = _by_name(_doc(_tree(tmp_path)))["busybox"]
    assert busybox["licenses"]
    assert busybox["cpe"].startswith("cpe:2.3:a:busybox:busybox")


def test_a_host_package_is_listed_as_not_shipped(tmp_path: Path) -> None:
    gcc = _by_name(_doc(_tree(tmp_path)))["gcc"]
    assert gcc["scope"] == "excluded"
    assert "host package" in _props(gcc)["jochwacht:not-shipped-reason"]
    assert "components" not in gcc


def test_buildroot_packages_are_not_listed_twice(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "output" / "legal-info" / "manifest.csv").write_text(
        '"PACKAGE","VERSION","LICENSE","LICENSE FILES","SOURCE ARCHIVE","SOURCE SITE",'
        '"DEPENDENCIES WITH LICENSES"\n"busybox","1.37.0","GPL-2.0","","","",""\n',
        encoding="utf-8")
    names = [c["name"] for c in _doc(root)["components"]]
    assert names.count("busybox") == 1


def test_the_upload_stays_as_slim_as_0_19(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    components, stats = collect_components(root)
    sent = slim_bytes(components, stats, project_name="fw")
    text = sent.decode("utf-8")
    for leaked in ("SHA-512", '"hashes"', '"manufacturer"', "jochwacht:evidence",
                   "component-kind", "bsi:component", '"licenses"', '"cpe"', '"pedigree"'):
        assert leaked not in text, leaked
    doc = json.loads(text)
    assert {c["name"] for c in doc["components"]} == {"busybox", "gcc"}
    assert all("components" not in c for c in doc["components"])


def test_without_a_build_directory_nothing_changes(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    full = _doc(tmp_path)
    slim = json.loads(slim_bytes(*collect_components(tmp_path), project_name="fw"))
    strip = ("serialNumber", "metadata")
    assert {k: v for k, v in full.items() if k not in strip} == \
        {k: v for k, v in slim.items() if k not in strip}


def test_send_uploads_the_slim_copy_it_shows(tmp_path: Path, monkeypatch: Any) -> None:
    """The customer can open exactly what leaves the house before saying yes."""
    from click.testing import CliRunner

    from jochwacht_sbom import api
    from jochwacht_sbom.cli import main

    root = _tree(tmp_path)
    sent: list[bytes] = []

    def fake_upload(self: Any, sbom: bytes, *, product: str) -> dict[str, Any]:
        sent.append(sbom)
        return {"status": "accepted"}

    monkeypatch.setattr(api.Client, "upload", fake_upload)
    monkeypatch.setenv("JOCHWACHT_API_KEY", "jw_test_" + "x" * 32)
    # without --yes the summary is shown (no terminal: no question, but the text)
    res = CliRunner().invoke(main, [str(root), "--send"])
    assert res.exit_code == 0, res.output
    copy = root / ".jochwacht" / "sent.cdx.json"
    assert sent == [copy.read_bytes()]
    assert b"SHA-512" not in sent[0]
    assert b"SHA-512" in (root / "sbom.cdx.json").read_bytes()
    assert "sent.cdx.json" in " ".join(res.output.split())


def test_the_binary_carries_the_spdx_lists() -> None:
    """The shared licence library reads two YAML lists at run time; the
    PyInstaller spec must bundle them (it bundled none before 0.20)."""
    spec = (Path(__file__).resolve().parents[1] / "jochwacht-sbom.spec").read_text()
    assert '"src/jochwacht_sbom/sbom/data/*.yaml"' in spec
    data = Path(__file__).resolve().parents[1] / "src" / "jochwacht_sbom" / "sbom" / "data"
    assert {p.name for p in data.glob("*.yaml")} == {
        "spdx_license_ids.yaml", "spdx_exception_ids.yaml"}


def test_licence_text_that_is_not_valid_spdx_stays_text() -> None:
    """suite-c measured on zc706: 'GPL-3.0+ with exceptions' and 'EPL-2.0 or
    EDLv1.0' were written as expressions; the shared strict rule keeps them text."""
    from jochwacht_sbom.sbom.licenses import cyclonedx_licenses

    for raw in ("GPL-3.0+ with exceptions", "EPL-2.0 or EDLv1.0", "BSD-3-Clause or GPL-2.0"):
        got = cyclonedx_licenses(raw)
        assert "expression" not in got[0] or raw == "BSD-3-Clause or GPL-2.0", (raw, got)
    assert cyclonedx_licenses("BSD-3-Clause or GPL-2.0") == [
        {"expression": "BSD-3-Clause OR GPL-2.0"}]


def _in_tree(root: Path) -> Path:
    """An in-tree Buildroot build: the Buildroot source with .config and
    package/ around output/ (suite-c on zc706, Abweichung 3)."""
    _tree(root)
    (root / ".config").write_text("BR2_HAVE_DOT_CONFIG=y\n", encoding="utf-8")
    (root / "package" / "busybox").mkdir(parents=True)
    (root / "package" / "busybox" / "Config.in").write_text(
        "config BR2_PACKAGE_BUSYBOX\n\tbool \"busybox\"\n", encoding="utf-8")
    kconfig = root / "support" / "kconfig"
    kconfig.mkdir(parents=True)
    (kconfig / "Makefile").write_text(
        "HOSTLOADLIBES_gconf = $(shell pkg-config --libs gtk+-2.0)\n"
        "HOSTLOADLIBES_qconf = $(shell pkg-config --libs Qt5Core QtCore)\n"
        "HOSTLOADLIBES_nconf = -lmenu -lpanel -lmenuw\n", encoding="utf-8")
    (root / "utils").mkdir()
    (root / "utils" / "requirements.txt").write_text("flask==0.12.2\n", encoding="utf-8")
    return root


def test_the_buildroot_source_of_an_in_tree_build_is_not_scanned(tmp_path: Path) -> None:
    """Buildroot's own tooling (kconfig's pkg-config probes, utils/) is not
    the product; the build tells what is (suite-c, Abweichung 3)."""
    components, stats = collect_components(_in_tree(tmp_path))
    names = {c.name for c in components}
    for foreign in ("gtk+-2.0", "Qt5Core", "QtCore", "menu", "menuw", "panel", "flask"):
        assert foreign not in names, foreign
    assert {"busybox", "gcc"} <= names
    assert stats.buildroot_source_skipped == ["."]


def test_a_project_beside_the_buildroot_tree_is_still_scanned(tmp_path: Path) -> None:
    _in_tree(tmp_path / "buildroot")
    app = tmp_path / "app"
    app.mkdir()
    (app / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    components, stats = collect_components(tmp_path)
    names = {c.name for c in components}
    assert "requests" in names
    assert "flask" not in names and "gtk+-2.0" not in names
    assert stats.buildroot_source_skipped == ["buildroot"]
    sent = json.loads(slim_bytes(components, stats, project_name="fw"))
    assert "buildroot_source_skipped" not in json.dumps(sent)


def test_buildroot_names_and_versions_are_cleaned_before_anything(tmp_path: Path) -> None:
    """Buildroot's SBOM is foreign text: a bidi override or a zero-width
    space in name or version must not reach the bill or the upload."""
    root = _tree(tmp_path)
    sbom = root / "output" / "legal-info" / "buildroot.cdx.json"
    doc = json.loads(sbom.read_text(encoding="utf-8"))
    comp = doc["components"][0]
    comp["name"] = "busy\u202ebox"
    comp["version"] = "1.37.0\u200b\x1b[31m"
    comp["cpe"] = "cpe:2.3:a:busybox:busybox:1.37.0\u2028:-:*:*:*:*:*:*"
    comp["purl"] = "pkg:generic/busy%E2%80%AEbox@1.37.0"
    sbom.write_text(json.dumps(doc), encoding="utf-8")
    components, stats = collect_components(root)
    by = {c.name: c for c in components}
    assert "busybox" in by, sorted(by)
    assert by["busybox"].version == "1.37.0"
    assert "\u2028" not in by["busybox"].local_cpe
    assert "%E2%80%AE" not in (by["busybox"].local_purl or "")
    sent = slim_bytes(components, stats, project_name="fw").decode("utf-8")
    full = json.dumps(build_cyclonedx(components, stats, project_name="fw"))
    for bad in ("\u202e", "\u200b", "\u2028", "\x1b"):
        assert bad not in sent and bad not in full, repr(bad)


def test_send_with_yes_still_names_the_copy_it_uploads(tmp_path: Path, monkeypatch: Any) -> None:
    from click.testing import CliRunner

    from jochwacht_sbom import api
    from jochwacht_sbom.cli import main

    root = _tree(tmp_path)
    monkeypatch.setattr(api.Client, "upload",
                        lambda self, sbom, *, product: {"status": "accepted"})
    monkeypatch.setenv("JOCHWACHT_API_KEY", "jw_test_" + "x" * 32)
    res = CliRunner().invoke(main, [str(root), "--send", "--yes"])
    assert res.exit_code == 0, res.output
    out = " ".join(res.output.split())
    assert "uploaded: .jochwacht/sent.cdx.json (2 components)" in out


def test_the_summary_names_the_skipped_buildroot_source(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from jochwacht_sbom.cli import main

    root = tmp_path / "proj"
    _in_tree(root / "buildroot")
    res = CliRunner().invoke(main, [str(root)])
    assert res.exit_code == 0, res.output
    out = " ".join(res.output.split())
    assert "Buildroot source not scanned (its build is read instead): buildroot" in out


def test_sb1_a_second_tree_keeps_its_manifest_rows(tmp_path: Path) -> None:
    """sicherheit-2 SB1: only the manifest.csv of the read build is replaced
    (by path); another tree's rows stay, as in 0.19."""
    _tree(tmp_path / "br")
    second = tmp_path / "second" / "output" / "legal-info"
    second.mkdir(parents=True)
    (second / "manifest.csv").write_text(
        '"PACKAGE","VERSION","LICENSE","LICENSE FILES","SOURCE ARCHIVE","SOURCE SITE",'
        '"DEPENDENCIES WITH LICENSES"\n"zweitbaum-only","9.9","MIT","","","",""\n',
        encoding="utf-8")
    (tmp_path / "br" / "output" / "legal-info" / "manifest.csv").write_text(
        '"PACKAGE","VERSION","LICENSE","LICENSE FILES","SOURCE ARCHIVE","SOURCE SITE",'
        '"DEPENDENCIES WITH LICENSES"\n"busybox","1.37.0","GPL-2.0","","","",""\n',
        encoding="utf-8")
    components, stats = collect_components(tmp_path)
    names = [c.name for c in components]
    assert "zweitbaum-only" in names
    assert names.count("busybox") == 1
    assert any("replaced by the build" in s for s in stats.build_output_sources)


def test_the_local_bill_names_the_buildroot_product(tmp_path: Path) -> None:
    meta = _doc(_tree(tmp_path))["metadata"]["component"]
    assert (meta["name"], meta["version"]) == ("buildroot", "2025.08.2")
    sent = json.loads(slim_bytes(*collect_components(tmp_path), project_name="fw"))
    assert sent["metadata"]["component"]["name"] == "fw"


@pytest.mark.skipif(sys.platform == "win32", reason="symbolic links need privileges on Windows")
@pytest.mark.parametrize("rel", ["output", "output/legal-info"])
def test_a_buildroot_part_linked_outside_is_named_never_read(tmp_path: Path, rel: str) -> None:
    """Y1 for Buildroot (coordination): with output/ or legal-info/ a link out
    of the scanned folder, the build fell away without a word. Nothing is
    read from outside; the customer is told which link was not followed."""
    import os

    from click.testing import CliRunner

    from jochwacht_sbom.cli import main

    root = _tree(tmp_path / "proj")
    inside = root / rel
    outside = tmp_path / "elsewhere" / Path(rel).name
    outside.parent.mkdir()
    shutil.move(str(inside), str(outside))
    os.symlink(outside, inside)
    components, stats = collect_components(root)
    assert not any(c.delivered_files for c in components)
    expected = f"Buildroot build part {rel} points outside"
    assert any(expected in w for w in stats.build_warnings), stats.build_warnings
    res = CliRunner().invoke(main, [str(root)])
    assert expected in " ".join(res.output.split()), res.output
