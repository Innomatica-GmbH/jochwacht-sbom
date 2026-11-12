"""The self filter takes only a declared project name, never the folder name.

Measured 11.11.2026: a Zephyr workspace in a folder named "zephyr" (or
"zephyr-app": the name normalisation strips "-app") lost its zephyr module;
a project in a folder named like a dependency loses that dependency. The
folder name is where a checkout happens to live, not what the project is
called. Declared names: jochwacht.yaml, pyproject.toml, package.json,
Cargo.toml, project() in CMakeLists.txt, the module in go.mod
(sbom/project_identity.py, the same code as in the suite).
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
    - name: zephyr
      remote: zephyrproject-rtos
      revision: v3.6.0
"""


def _names(proj: Path) -> set[str]:
    res = CliRunner().invoke(main, [str(proj), "--no-send"])
    assert res.exit_code == 0, res.output
    doc = json.loads((proj / "sbom.cdx.json").read_text(encoding="utf-8"))
    return {c["name"] for c in doc["components"]}


@pytest.mark.parametrize("folder", ["zephyr", "zephyr-app"])
def test_a_folder_named_like_a_module_keeps_the_module(tmp_path: Path, folder: str) -> None:
    ws = tmp_path / folder
    ws.mkdir()
    (ws / "west.yml").write_text(WEST, encoding="utf-8")
    assert "zephyr" in _names(ws)


def test_a_folder_named_like_a_dependency_keeps_it(tmp_path: Path) -> None:
    proj = tmp_path / "requests"
    proj.mkdir()
    (proj / "requirements.txt").write_text("requests==2.32.3\nidna==3.7\n", encoding="utf-8")
    assert {"requests", "idna"} <= _names(proj)


def test_the_declared_name_is_still_filtered(tmp_path: Path) -> None:
    proj = tmp_path / "checkout"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "mytool"\nversion = "1.0"\ndependencies = ["idna==3.7"]\n'
        '[dependency-groups]\ntest = ["mytool[extra]", "pytest==8.0.0"]\n', encoding="utf-8")
    names = _names(proj)
    assert "mytool" not in names
    assert "idna" in names


def test_jochwacht_yaml_name_is_still_filtered(tmp_path: Path) -> None:
    proj = tmp_path / "checkout"
    proj.mkdir()
    (proj / "jochwacht.yaml").write_text("project:\n  name: idna\n", encoding="utf-8")
    (proj / "requirements.txt").write_text("idna==3.7\nrequests==2.32.3\n", encoding="utf-8")
    names = _names(proj)
    assert "idna" not in names and "requests" in names


def test_another_ecosystem_is_not_the_project(tmp_path: Path) -> None:
    """Measured: a Python project with a Cargo.toml named "requests" and a
    CMake project(Flask) next to it lost requests==2.19.0 and flask==0.12."""
    proj = tmp_path / "checkout"
    proj.mkdir()
    (proj / "requirements.txt").write_text(
        "requests==2.19.0\nflask==0.12\nPyYAML==5.1\n", encoding="utf-8")
    (proj / "Cargo.toml").write_text('[package]\nname = "requests"\n', encoding="utf-8")
    (proj / "CMakeLists.txt").write_text("project(Flask C)\n", encoding="utf-8")
    assert {"requests", "flask", "PyYAML"} <= _names(proj)


def test_no_fuzzy_self_match(tmp_path: Path) -> None:
    """Measured: project "requests" lost requests-core and requests_client."""
    proj = tmp_path / "checkout"
    proj.mkdir()
    (proj / "pyproject.toml").write_text('[project]\nname = "requests"\nversion = "1"\n',
                                         encoding="utf-8")
    (proj / "requirements.txt").write_text(
        "requests-core==2.19.0\nrequests_client==1.0\n", encoding="utf-8")
    assert {"requests-core", "requests_client"} <= _names(proj)


def test_the_self_drop_is_named(tmp_path: Path) -> None:
    proj = tmp_path / "checkout"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "requests"\nversion = "1"\n'
        '[project.optional-dependencies]\nsocks = ["PySocks>=1.5.6"]\n'
        '[dependency-groups]\ntest = ["requests[socks]", "pytest-cov"]\n', encoding="utf-8")
    res = CliRunner().invoke(main, [str(proj), "--no-send"])
    assert res.exit_code == 0, res.output
    names = {c["name"] for c in json.loads((proj / "sbom.cdx.json").read_text())["components"]}
    assert "requests" not in names
    assert "the project itself: requests" in " ".join(res.output.split())
