"""Zephyr west.yml: read like the suite, counted as a build file.

Measured 11.11.2026 (parity corpus): the collector took a branch name
("main") as the version and wrote "pkg:github/…@main"; the suite writes no
version for a branch, a purl without "@" and the declaration
"branch:main". A branch is a moving target, not a version. Both read west.yml with the same code now
(sbom/west.py, a twin file).

Also measured: "Found 1 components (github) in 0 build files" — west.yml
was read but not counted, so a workspace whose only component the self
filter dropped ended with exit 2 "No supported build system found".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from jochwacht_sbom.cli import main

WEST = """manifest:
  remotes:
    - name: zephyrproject-rtos
      url-base: https://github.com/zephyrproject-rtos
  projects:
    - name: {name}
      remote: zephyrproject-rtos
      revision: {revision}
"""


def _run(tmp_path: Path, folder: str, name: str, revision: str):  # noqa: ANN202
    ws = tmp_path / folder
    ws.mkdir()
    (ws / "west.yml").write_text(WEST.format(name=name, revision=revision), encoding="utf-8")
    res = CliRunner().invoke(main, [str(ws), "--no-send"])
    bill = ws / "sbom.cdx.json"
    comps = ({c["name"]: c for c in json.loads(bill.read_text(encoding="utf-8"))["components"]}
             if bill.is_file() else {})
    return res, comps


def test_a_branch_is_no_version(tmp_path: Path) -> None:
    res, comps = _run(tmp_path, "ws", "zephyr", "main")
    assert res.exit_code == 0, res.output
    z = comps["zephyr"]
    assert "version" not in z
    assert z["purl"] == "pkg:github/zephyrproject-rtos/zephyr"
    props = {p["name"]: p["value"] for p in z.get("properties", [])}
    assert props.get("jochwacht:declared-range") == "branch:main"


@pytest.mark.parametrize("revision", ["v3.6.0", "zephyr-v3.6.0", "0123456789abcdef0123"])
def test_a_tag_or_hash_is_the_version(tmp_path: Path, revision: str) -> None:
    res, comps = _run(tmp_path, "ws", "zephyr", revision)
    assert res.exit_code == 0, res.output
    assert comps["zephyr"]["version"] == revision
    assert comps["zephyr"]["purl"] == f"pkg:github/zephyrproject-rtos/zephyr@{revision}"


def test_west_yml_counts_as_a_build_file(tmp_path: Path) -> None:
    res, _ = _run(tmp_path, "ws", "hal_nordic", "v4.0.0")
    assert "in 0 build files" not in res.output, res.output


def test_a_read_west_yml_is_never_no_build_system(tmp_path: Path) -> None:
    """The folder is named like its only module: the self filter drops it,
    but west.yml was read — that is no exit 2."""
    res, comps = _run(tmp_path, "zephyr", "zephyr", "main")
    assert res.exit_code != 2, res.output
    assert "No supported build system found" not in res.output
