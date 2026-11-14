"""J1 and J3 in the collector (sicherheit-2, 14.11.2026; synced from the suite's
build_files.py, develop 210f664).

J3: a patch with ``"type": []`` in Buildroot's SBOM made the shared core raise
(an unhashable list against the set of patch types); in the collector 0.20.0
every Buildroot package dropped out and the run ended with exit 1.
J1: valid JSON without an object at the root is a named gap, never a crash.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from test_build_hebel import _tree

from jochwacht_sbom.cli import main
from jochwacht_sbom.collector import collect_components


def _sbom(root: Path) -> Path:
    return root / "output" / "legal-info" / "buildroot.cdx.json"


def test_j3_a_patch_type_that_is_no_string_keeps_the_packages(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    doc = json.loads(_sbom(root).read_text(encoding="utf-8"))
    doc["components"][0]["pedigree"] = {"patches": [
        {"type": [], "diff": {"text": {"content": "x"}}},
        {"type": {"a": 1}},
        {"type": "backport"}]}
    _sbom(root).write_text(json.dumps(doc), encoding="utf-8")
    res = CliRunner().invoke(main, [str(root)])
    assert res.exit_code == 0, res.output
    components, _ = collect_components(root)
    busybox = next(c for c in components if c.name == "busybox")
    assert [p["type"] for p in busybox.patches] == ["backport"]


def test_j1_a_json_list_as_buildroot_sbom_is_named_not_a_crash(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    _sbom(root).write_text("[1, 2, 3]", encoding="utf-8")
    res = CliRunner().invoke(main, [str(root)])
    out = " ".join(res.output.split())
    assert res.exit_code != 1 or "no JSON object at the root" in out, res.output
    assert "Traceback" not in res.output
    _, stats = collect_components(root)
    assert any("no JSON object at the root" in w for w in stats.build_warnings)
