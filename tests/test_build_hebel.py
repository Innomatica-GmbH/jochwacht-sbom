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
from pathlib import Path
from typing import Any

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
