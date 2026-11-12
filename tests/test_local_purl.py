"""The local bill carries purl and bom-ref for every component it can.

Measured 11.11.2026 with the parity corpus: the collector wrote a purl for
0 of 573 components; the suite writes one for each. Without a purl the
local file is of little use to a vulnerability tool. The purl is built
like the suite builds it (the same ``_make_purl``), the bom-ref follows the
suite's rule (purl, else name@version, else name; a repeat gets ``#n``).

What does NOT change: the payload of ``--send`` still carries no purl for
a discovered component. Only names and versions travel; the purl is for
the customer's own file.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from jochwacht_sbom.cli import main
from jochwacht_sbom.collector import collect_components
from jochwacht_sbom.payload import CheckComponent, CheckStats, build_payload
from jochwacht_sbom.sbom_out import build_cyclonedx
from jochwacht_sbom.upload import serialize_payload


def _bill(proj: Path) -> dict[str, dict[str, str]]:
    res = CliRunner().invoke(main, [str(proj), "--no-send"])
    assert res.exit_code == 0, res.output
    doc = json.loads((proj / "sbom.cdx.json").read_text(encoding="utf-8"))
    return {c["name"]: c for c in doc["components"]}


def _npm(tmp_path: Path) -> Path:
    proj = tmp_path / "web"
    proj.mkdir()
    (proj / "package.json").write_text(json.dumps(
        {"name": "web", "version": "1.0.0", "dependencies": {"@scope/pkg": "1.2.3"}}),
        encoding="utf-8")
    (proj / "package-lock.json").write_text(json.dumps({
        "name": "web", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": {"name": "web", "version": "1.0.0", "dependencies": {"@scope/pkg": "1.2.3"}},
            "node_modules/@scope/pkg": {"version": "1.2.3"},
        }}), encoding="utf-8")
    return proj


def test_lockfile_component_has_purl_and_bom_ref(tmp_path: Path) -> None:
    comp = _bill(_npm(tmp_path))["@scope/pkg"]
    assert comp["purl"] == "pkg:npm/%40scope/pkg@1.2.3"
    assert comp["bom-ref"] == comp["purl"]


def test_build_file_component_has_purl(tmp_path: Path) -> None:
    proj = tmp_path / "fw"
    proj.mkdir()
    (proj / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.16)\nproject(fw C)\n"
        "find_package(MbedTLS 3.5 REQUIRED)\nadd_executable(fw main.c)\n", encoding="utf-8")
    comp = _bill(proj)["MbedTLS"]
    assert comp["purl"] == "pkg:generic/MbedTLS@3.5"
    assert comp["bom-ref"] == "pkg:generic/MbedTLS@3.5"


def test_the_send_payload_still_carries_no_purl(tmp_path: Path) -> None:
    comps, stats = collect_components(_npm(tmp_path))
    payload = build_payload(voucher="", contact_email="a@b.de", tool_version="t",
                            project_label="web", components=comps, stats=stats)
    raw = json.loads(serialize_payload(payload))
    assert all(not c.get("purl") for c in raw["components"]), raw["components"]
    assert "pkg:npm" not in serialize_payload(payload).decode("utf-8")


def test_bom_refs_are_unique() -> None:
    a = CheckComponent(name="x", version="1", ecosystem="npm")
    doc = build_cyclonedx([a, a.model_copy(), CheckComponent(name="y")], CheckStats(),
                          project_name="p")
    refs = [c["bom-ref"] for c in doc["components"]]  # type: ignore[index]
    assert len(set(refs)) == 3, refs
    assert refs == ["pkg:npm/x@1", "pkg:npm/x@1#2", "pkg:generic/y"]
