"""Python scope like the suite (sbom/dev_scope.py): runtime required,
extras optional, dependency groups excluded — with uv.lock over its graph,
without a lockfile by pyproject section. Measured 11.11.2026: the collector
counted 73 group-only packages of flask's uv.lock and the group entries of
requests' pyproject as required."""

from __future__ import annotations

from pathlib import Path

from jochwacht_sbom.sbom.scanner import scan_directory

UV_LOCK = """version = 1
requires-python = ">=3.10"

[[package]]
name = "app"
version = "1.0"
source = { editable = "." }
dependencies = [{ name = "httpx" }]

[package.optional-dependencies]
cli = [{ name = "click" }]

[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "certifi" }]

[[package]]
name = "certifi"
version = "2024.2.2"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "click"
version = "8.1.7"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.1.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "pluggy" }]

[[package]]
name = "pluggy"
version = "1.4.0"
source = { registry = "https://pypi.org/simple" }
"""


def test_uv_lock(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(UV_LOCK, encoding="utf-8")
    s = {d.name: d.scope or "required" for d in scan_directory(tmp_path)}
    assert s == {"httpx": "required", "certifi": "required", "click": "optional",
                 "pytest": "excluded", "pluggy": "excluded"}


def test_pyproject_without_lock(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["idna>=2.5"]\n'
        '[project.optional-dependencies]\nsocks = ["PySocks>=1.5.6"]\n'
        '[dependency-groups]\ntest = ["pytest>=3"]\n', encoding="utf-8")
    s = {d.name: d.scope or "required" for d in scan_directory(tmp_path)}
    assert s == {"idna": "required", "PySocks": "optional", "pytest": "excluded"}


def test_groups_and_unusual_locks(tmp_path: Path) -> None:
    """G1: no production section, nothing marked; a runtime group stays.
    G2: once each. G3: an unusual uv.lock does not end the run."""
    a = tmp_path / "a"
    a.mkdir()
    (a / "pyproject.toml").write_text(
        '[project]\nname = "x"\n[dependency-groups]\nprod = ["django>=4"]\n', "utf-8")
    assert {d.name: d.scope for d in scan_directory(a)} == {"django": ""}
    b = tmp_path / "b"
    b.mkdir()
    (b / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["idna>=3"]\n'
        '[dependency-groups]\nserver = ["gunicorn>=21"]\ndev = ["pytest>=7", "idna>=3"]\n',
        "utf-8")
    deps = scan_directory(b)
    assert sorted((d.name, d.scope) for d in deps) == [
        ("gunicorn", ""), ("idna", ""), ("pytest", "excluded")]
    c = tmp_path / "c"
    c.mkdir()
    (c / "uv.lock").write_text('version = 1\npackage = "x"\n', "utf-8")
    scan_directory(c)


def test_optional_groups_and_lock_fallback(tmp_path: Path) -> None:
    a = tmp_path / "a"
    a.mkdir()
    (a / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["idna>=3"]\n'
        '[dependency-groups]\nqa = ["rich>=13"]\ndocs = ["sphinx>=7"]\n', "utf-8")
    assert {d.name: d.scope for d in scan_directory(a)} == {
        "idna": "", "rich": "", "sphinx": "excluded"}
    b = tmp_path / "b"
    b.mkdir()
    (b / "pyproject.toml").write_text(
        '[tool.poetry]\nname = "x"\n[tool.poetry.dependencies]\nrequests = "2.32.3"\n'
        '[tool.poetry.group.gpu]\noptional = true\n'
        '[tool.poetry.group.gpu.dependencies]\ntorch = "2.3.0"\n', "utf-8")
    assert {d.name: d.scope for d in scan_directory(b)}["torch"] == "optional"
    c = tmp_path / "c"
    c.mkdir()
    (c / "uv.lock").write_text('version = 1\npackage = "x"\n', "utf-8")
    (c / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["idna>=3.7"]\n',
                                      "utf-8")
    assert [d.name for d in scan_directory(c)] == ["idna"]
