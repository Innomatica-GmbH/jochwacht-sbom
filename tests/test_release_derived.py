"""The release label without --release (coordination, 13.11.2026).

Order: --release / JOCHWACHT_RELEASE; else the one git tag exactly on HEAD;
else the product version the one build states when it is not a tool
default; else the clear refusal. The source is named in the output. A tool
default (Buildroot's own version, Yocto's PV "1.0") would give every new
firmware the same label, and the same label replaces the previous version
of that release (contract of 27); it is never taken.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from test_build_hebel import _tree
from test_send_status import KEY

from jochwacht_sbom import api
from jochwacht_sbom.cli import main

EXCERPT = Path(__file__).parent / "fixtures" / "yocto_scarthgap4_excerpt"
ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git builds the test repos")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, env=ENV, capture_output=True)


def _tagged(proj: Path, *tags: str) -> None:
    _git(proj, "init", "-q", "-b", "main")
    _git(proj, "add", "-A")
    _git(proj, "commit", "-q", "-m", "c")
    for tag in tags:
        _git(proj, "tag", tag)


def _python(tmp_path: Path) -> Path:
    proj = tmp_path / "repo"
    proj.mkdir()
    (proj / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    return proj


def _buildroot(tmp_path: Path, product_version: str) -> Path:
    root = _tree(tmp_path / "br")
    sbom = root / "output" / "legal-info" / "buildroot.cdx.json"
    doc = json.loads(sbom.read_text(encoding="utf-8"))
    doc["metadata"]["component"].update(name="steuergeraet", version=product_version)
    sbom.write_text(json.dumps(doc), encoding="utf-8")
    (root / "output" / ".config").write_text(
        "#\n# Automatically generated file; DO NOT EDIT.\n"
        "# Buildroot 2025.08.2 Configuration\n#\nBR2_HAVE_DOT_CONFIG=y\n", encoding="utf-8")
    return root


def _send(proj: Path, monkeypatch: Any, *args: str) -> tuple[Any, list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []

    def upload(self: Any, sbom: bytes, *, product: str, release: str = "") -> dict[str, Any]:
        calls.append({"sbom": sbom, "release": release})
        return {"status": "new", "label": release, "mode": "full"}

    monkeypatch.setattr(api.Client, "upload", upload)
    monkeypatch.setenv("JOCHWACHT_API_KEY", KEY)
    monkeypatch.delenv(api.RELEASE_ENV, raising=False)
    res = CliRunner().invoke(main, [str(proj), "--send", "--yes", *args])
    return res, calls


def _out(res: Any) -> str:
    return " ".join(res.output.split())


@needs_git
def test_the_tag_on_head_is_the_release(tmp_path: Path, monkeypatch: Any) -> None:
    proj = _python(tmp_path)
    _tagged(proj, "v1.4.2")
    res, calls = _send(proj, monkeypatch)
    assert res.exit_code == 0, res.output
    assert [c["release"] for c in calls] == ["v1.4.2"]
    assert "Release label v1.4.2 from the git tag on the current commit" in _out(res)


@needs_git
def test_several_tags_on_head_are_named_and_refused(tmp_path: Path, monkeypatch: Any) -> None:
    proj = _python(tmp_path)
    _tagged(proj, "v1.0", "stable")
    res, calls = _send(proj, monkeypatch)
    assert res.exit_code == 1 and calls == []
    assert "stable, v1.0" in _out(res) and "--release" in _out(res)


@needs_git
def test_release_wins_over_the_tag(tmp_path: Path, monkeypatch: Any) -> None:
    proj = _python(tmp_path)
    _tagged(proj, "v1.4.2")
    res, calls = _send(proj, monkeypatch, "--release", "2026.11")
    assert [c["release"] for c in calls] == ["2026.11"]
    assert "from the git tag" not in _out(res)


@needs_git
def test_a_tag_over_100_characters_is_refused_never_shortened(
    tmp_path: Path, monkeypatch: Any,
) -> None:
    proj = _python(tmp_path)
    _tagged(proj, "v" * 101)
    res, calls = _send(proj, monkeypatch)
    assert res.exit_code == 1 and calls == []
    assert "100" in _out(res)


def test_the_customers_buildroot_version_is_the_release(tmp_path: Path, monkeypatch: Any) -> None:
    res, calls = _send(_buildroot(tmp_path, "3.2.0"), monkeypatch)
    assert res.exit_code == 0, res.output
    assert [c["release"] for c in calls] == ["3.2.0"]
    assert "Release label 3.2.0 from the Buildroot build" in _out(res)


def test_buildroots_own_version_is_never_the_release(tmp_path: Path, monkeypatch: Any) -> None:
    res, calls = _send(_buildroot(tmp_path, "2025.08.2"), monkeypatch)
    assert res.exit_code == 1 and calls == []
    assert "Buildroot's own version 2025.08.2" in _out(res)


def test_yoctos_default_pv_is_never_the_release(tmp_path: Path, monkeypatch: Any) -> None:
    proj = tmp_path / "y"
    shutil.copytree(EXCERPT, proj / "build", symlinks=True)
    res, calls = _send(proj, monkeypatch)
    assert res.exit_code == 1 and calls == []
    assert 'PV "1.0"' in _out(res)


def test_without_any_source_the_refusal_says_what_was_looked_for(
    tmp_path: Path, monkeypatch: Any,
) -> None:
    res, calls = _send(_python(tmp_path), monkeypatch)
    assert res.exit_code == 1 and calls == []
    out = _out(res)
    assert "--release" in out and api.RELEASE_ENV in out and "git tag" in out


def test_the_local_bill_keeps_the_version_the_build_states(
    tmp_path: Path, monkeypatch: Any,
) -> None:
    """sicherheit-2 on 2cfd184: the label must not overwrite the build's own
    evidence in the local bill; it stands beside it. The upload carries the
    label as the version."""
    proj = tmp_path / "y"
    shutil.copytree(EXCERPT, proj / "build", symlinks=True)
    res, calls = _send(proj, monkeypatch, "--release", "7.7.7")
    assert res.exit_code == 0, res.output
    local = json.loads((proj / "sbom.cdx.json").read_text(encoding="utf-8"))
    meta = local["metadata"]["component"]
    assert (meta["name"], meta["version"]) == ("core-image-minimal", "1.0")
    assert {"name": "jochwacht:release-label", "value": "7.7.7"} in meta["properties"]
    assert json.loads(calls[0]["sbom"])["metadata"]["component"]["version"] == "7.7.7"
