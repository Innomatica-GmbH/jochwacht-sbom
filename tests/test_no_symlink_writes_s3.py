"""No write of the collector follows a symbolic link, part two (sicherheit-2, S3).

The diagnosis file next to the bill, its fallback in the temporary directory,
and the two places --with-tools touched in the scanned folder (the cmake
trace folder and the gradlew wrapper) followed a link. A scanned repository
is foreign input (a pull request from a fork in CI); a marker such as
``SConstruct`` is enough to make the collector write the diagnosis file.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from jochwacht_sbom import diagnosis
from jochwacht_sbom.analyzer.pipeline import tier1_cli
from jochwacht_sbom.cli import main

pytestmark = pytest.mark.skipif(sys.platform == "win32",
                                reason="symbolic links need privileges on Windows")

ORIGINAL = "WICHTIG-ORIGINAL"


def _victim(tmp_path: Path) -> Path:
    victim = tmp_path / "aussen" / "opfer.txt"
    victim.parent.mkdir()
    victim.write_text(ORIGINAL, encoding="utf-8")
    return victim


def _unsupported_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SConstruct").write_text("Program('fw.c')\n", encoding="utf-8")
    return repo


def test_s3_the_diagnosis_file_never_follows_a_link(tmp_path: Path) -> None:
    repo, victim = _unsupported_repo(tmp_path), _victim(tmp_path)
    os.symlink(victim, repo / diagnosis.DIAGNOSIS_FILENAME)
    res = CliRunner().invoke(main, [str(repo)])
    assert victim.read_text(encoding="utf-8") == ORIGINAL
    assert res.exit_code == 2, res.output          # the unsupported-build answer stays


def test_s3_a_dangling_link_as_diagnosis_file_creates_nothing_outside(tmp_path: Path) -> None:
    repo, victim = _unsupported_repo(tmp_path), _victim(tmp_path)
    target = victim.parent / "neu.json"
    os.symlink(target, repo / diagnosis.DIAGNOSIS_FILENAME)
    CliRunner().invoke(main, [str(repo)])
    assert not target.exists()


def test_s3_a_refused_link_still_says_where_the_diagnosis_is(
    tmp_path: Path, monkeypatch: Any,
) -> None:
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmpdir))
    repo, victim = _unsupported_repo(tmp_path), _victim(tmp_path)
    os.symlink(victim, repo / diagnosis.DIAGNOSIS_FILENAME)
    res = CliRunner().invoke(main, [str(repo)])
    written = [p for p in tmpdir.iterdir() if p.suffix == ".json"]
    assert len(written) == 1 and str(written[0]) in "".join(res.output.split())
    assert '"unsupported_build"' in written[0].read_text(encoding="utf-8")


def test_s3_the_fallback_has_a_fresh_name_and_never_follows_a_link(
    tmp_path: Path, monkeypatch: Any,
) -> None:
    """The fallback sat at a fixed name in a shared folder: anyone on the
    machine could place a link there first."""
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmpdir))
    victim = _victim(tmp_path)
    os.symlink(victim, tmpdir / diagnosis.DIAGNOSIS_FILENAME)
    where = diagnosis.write_report({"kind": "tool_error"}, near=tmp_path / "missing")
    assert victim.read_text(encoding="utf-8") == ORIGINAL
    assert where.parent == tmpdir and where.name != diagnosis.DIAGNOSIS_FILENAME
    assert not where.is_symlink() and stat.S_IMODE(where.stat().st_mode) == 0o600
    assert '"tool_error"' in where.read_text(encoding="utf-8")


def test_s3_two_fallbacks_do_not_overwrite_each_other(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    first = diagnosis.write_report({"kind": "a"}, near=tmp_path / "missing")
    second = diagnosis.write_report({"kind": "b"}, near=tmp_path / "missing")
    assert first != second and '"a"' in first.read_text(encoding="utf-8")


def test_s3_the_cmake_trace_folder_is_not_in_the_scanned_folder(
    tmp_path: Path, monkeypatch: Any,
) -> None:
    """cmake wrote CMakeCache.txt, CMakeFiles/ and Makefile through a link
    ``_jochwacht_cmake_trace`` to outside; the folder now is a fresh
    temporary one outside the scanned folder."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "CMakeLists.txt").write_text("project(fw C)\n", encoding="utf-8")
    outside = tmp_path / "aussen"
    outside.mkdir()
    os.symlink(outside, repo / "_jochwacht_cmake_trace")
    seen: list[Path] = []

    def fake_cmake(cmd: list[str], cwd: Path | None = None, timeout: float = 0) -> None:
        assert cwd is not None
        seen.append(cwd)
        (cwd / "CMakeCache.txt").write_text("cache", encoding="utf-8")   # as cmake does
        return None

    monkeypatch.setattr(tier1_cli, "_run_cmd", fake_cmake)
    tier1_cli.CmakeTraceScanner().scan("_project", repo, repo)
    assert list(outside.iterdir()) == []
    assert len(seen) == 1 and not seen[0].resolve().is_relative_to(repo.resolve())
    assert not seen[0].exists()                    # removed after the run


def test_s3_the_gradle_wrapper_is_not_made_executable_through_a_link(
    tmp_path: Path, monkeypatch: Any,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "build.gradle").write_text("", encoding="utf-8")
    victim = _victim(tmp_path)
    victim.chmod(0o600)
    os.symlink(victim, repo / "gradlew")
    ran: list[list[str]] = []
    monkeypatch.setattr(tier1_cli, "_run_cmd", lambda cmd, **_: ran.append(cmd))
    tier1_cli.GradleDepScanner().scan("_project", repo, repo)
    assert stat.S_IMODE(victim.stat().st_mode) == 0o600
    assert all(cmd[0] != str(repo / "gradlew") for cmd in ran)


def test_the_help_and_readme_warn_that_with_tools_runs_the_projects_code() -> None:
    res = CliRunner().invoke(main, ["--help"])
    help_text = " ".join(res.output.split())
    assert "runs the project's own build code" in help_text
    readme = " ".join((Path(__file__).resolve().parents[1] / "README.md")
                      .read_text(encoding="utf-8").split())
    assert "`--with-tools` runs the project's own build code" in readme


def test_the_payload_file_of_output_never_follows_a_link(tmp_path: Path) -> None:
    """--output names the file, but in CI it is often a relative name inside
    the checked-out folder, where a link can wait."""
    repo, victim = tmp_path / "repo", _victim(tmp_path)
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    os.symlink(victim, repo / "payload.json")
    res = CliRunner().invoke(main, [str(repo), "--output", str(repo / "payload.json")])
    assert victim.read_text(encoding="utf-8") == ORIGINAL
    assert res.exit_code != 0 and "symbolic link" in " ".join(res.output.split())
