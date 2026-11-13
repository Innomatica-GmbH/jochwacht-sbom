"""No file the collector writes follows a symbolic link (sicherheit-2, S1 and S2).

A scanned repository is foreign input (a pull request from a fork in CI). If
``sbom.cdx.json``, ``.jochwacht/last-upload.json``, ``.jochwacht/sent.cdx.json``
or the folder ``.jochwacht`` itself is a symbolic link, writing through it
would overwrite any file the runner may write. The collector refuses with a
clear message and leaves the target untouched.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from jochwacht_sbom import api
from jochwacht_sbom.cli import main

pytestmark = pytest.mark.skipif(sys.platform == "win32",
                                reason="symbolic links need privileges on Windows")

ORIGINAL = "WICHTIG-ORIGINAL"


def _project(tmp_path: Path) -> tuple[Path, Path]:
    proj = tmp_path / "repo"
    proj.mkdir()
    (proj / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    victim = tmp_path / "opfer" / "ziel.txt"
    victim.parent.mkdir()
    victim.write_text(ORIGINAL, encoding="utf-8")
    return proj, victim


def _send(proj: Path, monkeypatch: Any) -> Any:
    monkeypatch.setattr(api.Client, "upload", lambda self, sbom, **_: {"status": "ok"})
    monkeypatch.setenv("JOCHWACHT_API_KEY", "jw_test_" + "x" * 32)
    return CliRunner().invoke(main, [str(proj), "--send", "--yes"])


def test_s1_the_sent_copy_never_follows_a_link(tmp_path: Path, monkeypatch: Any) -> None:
    proj, victim = _project(tmp_path)
    (proj / ".jochwacht").mkdir()
    os.symlink(victim, proj / ".jochwacht" / "sent.cdx.json")
    res = _send(proj, monkeypatch)
    assert res.exit_code != 0
    assert victim.read_text(encoding="utf-8") == ORIGINAL
    assert "symbolic link" in " ".join(res.output.split())


def test_s2_the_local_bill_never_follows_a_link(tmp_path: Path) -> None:
    proj, victim = _project(tmp_path)
    os.symlink(victim, proj / "sbom.cdx.json")
    res = CliRunner().invoke(main, [str(proj)])
    assert res.exit_code != 0
    assert victim.read_text(encoding="utf-8") == ORIGINAL


def test_s2_a_dangling_link_creates_nothing_outside(tmp_path: Path) -> None:
    proj, victim = _project(tmp_path)
    target = victim.parent / "neu.txt"
    os.symlink(target, proj / "sbom.cdx.json")
    res = CliRunner().invoke(main, [str(proj)])
    assert res.exit_code != 0
    assert not target.exists()


def test_s2_the_last_upload_never_follows_a_link(tmp_path: Path, monkeypatch: Any) -> None:
    proj, victim = _project(tmp_path)
    (proj / ".jochwacht").mkdir()
    os.symlink(victim, proj / ".jochwacht" / "last-upload.json")
    res = _send(proj, monkeypatch)
    assert res.exit_code != 0
    assert victim.read_text(encoding="utf-8") == ORIGINAL


def test_s2_the_folder_jochwacht_must_not_be_a_link(tmp_path: Path, monkeypatch: Any) -> None:
    proj, victim = _project(tmp_path)
    os.symlink(victim.parent, proj / ".jochwacht")
    res = _send(proj, monkeypatch)
    assert res.exit_code != 0
    assert sorted(p.name for p in victim.parent.iterdir()) == ["ziel.txt"]
    assert victim.read_text(encoding="utf-8") == ORIGINAL


def test_a_regular_old_copy_is_replaced(tmp_path: Path, monkeypatch: Any) -> None:
    proj, _ = _project(tmp_path)
    (proj / ".jochwacht").mkdir()
    (proj / ".jochwacht" / "sent.cdx.json").write_text("old", encoding="utf-8")
    res = _send(proj, monkeypatch)
    assert res.exit_code == 0, res.output
    assert (proj / ".jochwacht" / "sent.cdx.json").read_text(encoding="utf-8").startswith("{")
