"""The release lock and the binary's own SBOM (Ivan, 14.11.2026, via the coordination).

- The publish workflow runs pip-audit over the hashed release locks before
  the PyPI and the binary upload; both need the gate; no exception list.
- The binary is built from exactly those locks, nothing resolved on the way.
- ci/release/binary_sbom.py writes the binary's bill from PyInstaller's table
  of contents: every bundled distribution must be pinned, else it fails.
The dry run of the gate on a vulnerable lock runs in CI (tests.yml,
release-gate); it needs the network, these tests do not.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sysconfig
from pathlib import Path
from types import ModuleType
from typing import Any

import click
import pydantic_core
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "ci" / "release"


def _workflow(name: str) -> dict[str, Any]:
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    return doc


def _runs(job: dict[str, Any]) -> str:
    return "\n".join(str(step.get("run", "")) for step in job["steps"])


def test_both_uploads_need_the_gate() -> None:
    jobs = _workflow("publish.yml")["jobs"]
    assert jobs["pypi"]["needs"] == "gate" and jobs["binary"]["needs"] == "gate"
    gate = _runs(jobs["gate"])
    assert "pip install --require-hashes -r ci/release/audit.txt" in gate
    assert "sh ci/release/gate.sh -r ci/release/runtime.txt -r ci/release/build.txt" in gate


def test_the_gate_has_no_exception_list() -> None:
    script = (RELEASE / "gate.sh").read_text(encoding="utf-8")
    command = [line for line in script.splitlines() if line.startswith("exec ")]
    assert command == ["exec pip-audit --strict --require-hashes --disable-pip "
                       '--progress-spinner off "$@"']
    for path in (*(ROOT / ".github" / "workflows").glob("*.yml"), RELEASE / "gate.sh"):
        assert "--ignore-vuln" not in path.read_text(encoding="utf-8"), path


def test_the_binary_and_the_wheel_are_built_from_the_locks() -> None:
    jobs = _workflow("publish.yml")["jobs"]
    binary, wheel = _runs(jobs["binary"]), _runs(jobs["pypi"])
    assert "pip install --require-hashes -r ci/release/runtime.txt -r ci/release/build.txt" \
        in binary
    assert "pip install --no-deps --no-build-isolation ." in binary
    assert "pip install --require-hashes -r ci/release/build.txt" in wheel
    assert "python -m build --no-isolation" in wheel
    assert "binary_sbom.py" in binary and '"$BIN.cdx.json.sha256"' in binary
    release = jobs["binary"]["steps"][-1]["with"]["files"]
    assert release == "dist/jochwacht-sbom-*"            # binary, SBOM and both .sha256


def test_ci_dry_runs_the_gate_on_a_vulnerable_lock() -> None:
    gate = _runs(_workflow("tests.yml")["jobs"]["release-gate"])
    assert "if sh ci/release/gate.sh -r ci/release/selftest-vulnerable.txt; then" in gate
    assert "exit 1" in gate
    vulnerable = (RELEASE / "selftest-vulnerable.txt").read_text(encoding="utf-8")
    assert "requests==2.19.1" in vulnerable and "--hash=sha256:" in vulnerable


@pytest.mark.parametrize("lock", ["runtime.txt", "build.txt", "audit.txt"])
def test_every_pin_has_a_hash_and_no_local_path(lock: str) -> None:
    text = (RELEASE / lock).read_text(encoding="utf-8")
    pins = re.findall(r"^([a-z0-9][a-z0-9._-]*)==\S+ \\$", text, re.M)
    assert pins
    for block in re.split(r"\n(?=[a-z0-9])", text):
        if "==" in block.split("\n", 1)[0]:
            assert "--hash=sha256:" in block, block.split("\n", 1)[0]
    assert not re.search(r"/home/|/tmp/|scratchpad|[A-Z]:\\\\", text)


def test_the_runtime_lock_covers_every_dependency_of_the_tool() -> None:
    import tomllib

    deps = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "dependencies"]
    pinned = set(re.findall(r"^([a-z0-9][a-z0-9._-]*)==",
                            (RELEASE / "runtime.txt").read_text(encoding="utf-8"), re.M))
    for dep in deps:
        name = re.split(r"[<>=!~\[ ;]", dep, maxsplit=1)[0].lower().replace("_", "-")
        assert name in pinned, dep


def test_the_spec_keeps_setuptools_out_of_the_binary() -> None:
    spec = (ROOT / "jochwacht-sbom.spec").read_text(encoding="utf-8")
    for name in ("pydantic.mypy", "setuptools", "_distutils_hack", "pkg_resources"):
        assert f'"{name}"' in spec


# --- binary_sbom.py ---------------------------------------------------------------

def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("binary_sbom", RELEASE / "binary_sbom.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_MOD = _load()


def _module() -> ModuleType:
    return _MOD


def _toc(tmp_path: Path, entries: list[tuple[str, str, str]]) -> Path:
    toc = tmp_path / "build" / "jochwacht-sbom"
    toc.mkdir(parents=True)
    (toc / "Analysis-00.toc").write_text(repr(("x", [("main", "", "OPTION")], entries)),
                                         encoding="utf-8")
    return toc


def _lock(tmp_path: Path, **pins: str) -> Path:
    lock = tmp_path / "lock.txt"
    lock.write_text("".join(f"{k}=={v} \\\n    --hash=sha256:{'0' * 64}\n"
                            for k, v in pins.items()), encoding="utf-8")
    return lock


def _bill(tmp_path: Path, entries: list[tuple[str, str, str]], **pins: str) -> dict[str, Any]:
    binary = tmp_path / "jochwacht-sbom"
    binary.write_bytes(b"\x7fELF")
    mod = _module()
    doc = mod.build_bill(_toc(tmp_path, entries), binary, [_lock(tmp_path, **pins)],
                         "0.21.0", ROOT / "src")
    assert isinstance(doc, dict)
    return doc


def _real_entries() -> list[tuple[str, str, str]]:
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    own = ROOT / "src" / "jochwacht_sbom" / "cli.py"
    return [("click", str(Path(click.__file__)), "PYMODULE"),
            (Path(pydantic_core._pydantic_core.__file__).name,
             str(Path(pydantic_core._pydantic_core.__file__)), "EXTENSION"),
            ("json", str(stdlib / "json" / "__init__.py"), "PYMODULE"),
            ("cli", str(own), "PYSOURCE")]


def _versions() -> dict[str, str]:
    import importlib.metadata as md

    return {"click": md.version("click"), "pydantic-core": md.version("pydantic-core")}


def test_the_binary_bill_names_the_bundled_libraries(tmp_path: Path) -> None:
    doc = _bill(tmp_path, _real_entries(), **_versions())
    by = {c["name"].lower().replace("_", "-"): c for c in doc["components"]}
    assert {"cpython", "pyinstaller", "click", "pydantic-core"} <= set(by)
    assert "json" not in by and "jochwacht-sbom" not in by     # stdlib, own code
    assert by["click"]["purl"] == f"pkg:pypi/click@{_versions()['click']}"
    files = by["pydantic-core"]["components"]
    assert files[0]["type"] == "file" and files[0]["hashes"][0]["alg"] == "SHA-256"
    meta = doc["metadata"]["component"]
    assert (meta["name"], meta["version"]) == ("jochwacht-sbom", "0.21.0")
    assert meta["hashes"][0]["alg"] == "SHA-256"


def test_the_binary_bill_carries_no_path_of_the_build_machine(tmp_path: Path) -> None:
    text = json.dumps(_bill(tmp_path, _real_entries(), **_versions()))
    for needle in (str(tmp_path), str(ROOT), "site-packages", "/usr/", "/home/"):
        assert needle not in text, needle


def test_a_bundled_library_without_a_pin_fails(tmp_path: Path) -> None:
    mod = _module()
    with pytest.raises(mod.SbomError, match="not pinned in the release lock: click"):
        _bill(tmp_path, _real_entries(), **{"pydantic-core": _versions()["pydantic-core"]})


def test_a_pin_other_than_the_built_version_fails(tmp_path: Path) -> None:
    mod = _module()
    with pytest.raises(mod.SbomError, match="but pinned 0.0.1"):
        _bill(tmp_path, _real_entries(), click="0.0.1",
              **{"pydantic-core": _versions()["pydantic-core"]})


def test_a_module_of_no_distribution_fails(tmp_path: Path) -> None:
    stray = tmp_path / "stray.py"
    stray.write_text("", encoding="utf-8")
    mod = _module()
    with pytest.raises(mod.SbomError, match="belongs to no distribution"):
        _bill(tmp_path, [("stray", str(stray), "PYMODULE")])


def test_the_readme_says_where_the_binary_sbom_is() -> None:
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    assert "`jochwacht-sbom-<version>-linux-x86_64.cdx.json`" in readme
