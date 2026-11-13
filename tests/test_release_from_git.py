"""The release label from the git tag exactly on HEAD (coordination, 13.11.2026).

Without --release the collector takes the tag that points at the current
commit, as ``git describe --tags --exact-match`` would: lightweight and
annotated, loose and packed. Never the "next" tag, never a commit hash.
The repository is read as files, git itself is never run: a scanned
repository (a pull request from a fork) must not get its configuration
executed. Only ``<path>/.git`` as a folder inside the scanned path counts.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from jochwacht_sbom.release_label import git_tag_on_head

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git builds the test repos")

ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, env=ENV,
                          capture_output=True, text=True).stdout.strip()


def _repo(tmp_path: Path, commits: int = 2) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    for i in range(commits):
        (repo / "f.txt").write_text(str(i), encoding="utf-8")
        _git(repo, "add", "f.txt")
        _git(repo, "commit", "-q", "-m", f"c{i}")
    return repo


def test_a_lightweight_tag_on_head(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _git(repo, "tag", "v1.4.2")
    assert git_tag_on_head(repo) == (["v1.4.2"], "")


def test_an_annotated_tag_on_head(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _git(repo, "tag", "-a", "v2.0", "-m", "release")
    assert git_tag_on_head(repo) == (["v2.0"], "")


@pytest.mark.parametrize("annotated", [False, True])
def test_packed_tags_count_too(tmp_path: Path, annotated: bool) -> None:
    repo = _repo(tmp_path)
    _git(repo, "tag", *(["-a", "-m", "r"] if annotated else []), "v3.1")
    _git(repo, "pack-refs", "--all")
    assert not (repo / ".git" / "refs" / "tags" / "v3.1").exists()
    assert git_tag_on_head(repo) == (["v3.1"], "")


def test_a_detached_head_as_in_ci(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _git(repo, "tag", "v5")
    _git(repo, "checkout", "-q", "--detach", "HEAD")
    assert git_tag_on_head(repo) == (["v5"], "")


def test_a_tag_on_an_older_commit_is_not_the_release(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _git(repo, "tag", "v0.9", "HEAD~1")
    assert git_tag_on_head(repo) == ([], "")


def test_several_tags_on_head_are_all_named(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _git(repo, "tag", "v1.0")
    _git(repo, "tag", "-a", "stable", "-m", "s")
    assert git_tag_on_head(repo) == (["stable", "v1.0"], "")


def test_no_repository_no_tag(tmp_path: Path) -> None:
    assert git_tag_on_head(tmp_path) == ([], "")


@pytest.mark.skipif(sys.platform == "win32", reason="symbolic links need privileges")
def test_a_git_folder_linked_outside_is_not_read(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _git(repo, "tag", "v1")
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    os.symlink(repo / ".git", scanned / ".git")
    tags, note = git_tag_on_head(scanned)
    assert tags == [] and "outside" in note


def test_a_worktree_or_submodule_git_file_is_not_followed(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _git(repo, "tag", "v1")
    wt = tmp_path / "wt"
    _git(repo, "worktree", "add", "-q", str(wt))
    tags, note = git_tag_on_head(wt)
    assert tags == [] and ".git" in note


def test_git_is_never_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path)
    _git(repo, "tag", "v1")

    def no_subprocess(*args: object, **kwargs: object) -> None:
        raise AssertionError("a subprocess was started")

    monkeypatch.setattr(subprocess, "run", no_subprocess)
    monkeypatch.setattr(subprocess, "Popen", no_subprocess)
    assert git_tag_on_head(repo) == (["v1"], "")
