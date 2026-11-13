"""No invisible character as a real character in a tracked text file.

Test sources held U+202E, U+200B, U+2028, U+2029, U+FEFF and U+00AD as
real characters instead of escapes. A reviewer does not see them, and a
direction mark can turn the display of a line around. Python sources
write such a character as an escape
("\\u202e"); a file that must carry the real character is listed below with
the reason.
"""

from __future__ import annotations

import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: Unicode classes that do not show: format (Cf: U+202E, U+200B, U+FEFF,
#: U+00AD), line and paragraph separator (Zl, Zp), private use (Co), and
#: control characters (Cc) except tab and line end.
INVISIBLE_CLASSES = frozenset({"Cf", "Zl", "Zp", "Co"})
ALLOWED_CONTROLS = frozenset("\t\n\r")

#: path → (characters allowed there, reason)
EXCEPTIONS: dict[str, tuple[frozenset[str], str]] = {
    "tests/fixtures/nuget/nano-rtc/packages.config": (
        frozenset("\ufeff"),
        "a customer file as Visual Studio writes it: the UTF-8 byte order mark at the "
        "start is what the NuGet reader must cope with"),
    "tests/fixtures/nuget/siemens-broker/Broker.csproj": (
        frozenset("\ufeff"),
        "a customer file as Visual Studio writes it: the UTF-8 byte order mark at the "
        "start is what the NuGet reader must cope with"),
}


def invisible(char: str) -> bool:
    category = unicodedata.category(char)
    return category in INVISIBLE_CLASSES or (category == "Cc" and char not in ALLOWED_CONTROLS)


def findings(text: str, allowed: frozenset[str] = frozenset()) -> list[tuple[int, str]]:
    """``(line, "U+XXXX …")`` for every line with an invisible character."""
    out = []
    for number, line in enumerate(text.split("\n"), 1):
        chars = [c for c in line if invisible(c) and c not in allowed]
        if chars:
            out.append((number, " ".join(f"U+{ord(c):04X}" for c in chars)))
    return out


#: Folders that are no source when there is no git to ask (a tree from git archive).
_NOT_SOURCE = {".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".ruff_cache",
               ".pytest_cache", "node_modules", "build", "dist", "htmlcov", ".tox"}


def _listed() -> list[str]:
    """The files git tracks. A CI container may run pytest as root in a work
    tree owned by another user; git refuses that as dubious ownership
    (status 128), so it is asked with safe.directory=*. A failing git with
    a .git present fails the test loudly, with code and stderr. Without .git
    (a tree from git archive) every file outside :data:`_NOT_SOURCE` is read."""
    if not (ROOT / ".git").exists():
        return sorted(p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
                      if p.is_file() and not _NOT_SOURCE & set(p.relative_to(ROOT).parts))
    try:
        run = subprocess.run(["git", "-c", "safe.directory=*", "-C", str(ROOT), "ls-files", "-z"],
                             capture_output=True)
    except OSError as exc:
        pytest.fail(f"git ls-files could not run: {exc}")
    if run.returncode != 0:
        pytest.fail(f"git ls-files ended with {run.returncode}: "
                    f"{run.stderr.decode(errors='replace').strip()}")
    return [raw.decode() for raw in run.stdout.split(b"\0") if raw]


def _tracked_texts() -> list[tuple[str, str]]:
    texts = []
    for rel in _listed():
        path = ROOT / rel
        if not path.is_file():
            continue  # a submodule (makeself) or a file deleted in the work tree
        data = path.read_bytes()
        if b"\0" in data[:8192]:
            continue
        try:
            texts.append((rel, data.decode("utf-8")))
        except UnicodeDecodeError:
            continue
    return texts


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ("plain text\n", []),
        ("tab\tand line end\r\n", []),
        ("x\u202ey\n", [(1, "U+202E")]),
        ("a\nb\u200bc\u00add\n", [(2, "U+200B U+00AD")]),
        ("\ufeffstart\n", [(1, "U+FEFF")]),
        ("x\u2028y", [(1, "U+2028")]),
        ("x\u2029y", [(1, "U+2029")]),
        ("x\ue000y", [(1, "U+E000")]),
        ("x\x1b[31my", [(1, "U+001B")]),
        ("x\x9by", [(1, "U+009B")]),
        ('"\\u202e" as an escape', []),
    ],
)
def test_the_guard_sees_what_a_reviewer_does_not(text: str, found: list[tuple[int, str]]) -> None:
    assert findings(text) == found


def test_no_tracked_text_file_holds_an_invisible_character() -> None:
    texts = _tracked_texts()
    assert len(texts) > 100  # the walk itself works
    bad = []
    for rel, text in texts:
        allowed = EXCEPTIONS.get(rel, (frozenset(), ""))[0]
        bad.extend(f"{rel}:{line}: {chars}" for line, chars in findings(text, allowed))
    assert not bad, "write these as escapes (\\u202e) or list the file with a reason:\n" + \
        "\n".join(bad)


def test_every_exception_is_still_needed() -> None:
    texts = dict(_tracked_texts())
    for rel, (allowed, reason) in EXCEPTIONS.items():
        assert reason
        assert rel in texts, f"{rel} is no tracked text file any more"
        assert any(c in texts[rel] for c in allowed), f"{rel} no longer needs its exception"


# --- the walk in a CI container ---------------------------------------------------
# The pod runs pytest as root in a work tree owned by the agent: git refused
# with "detected dubious ownership", status 128, and both tests failed.

def test_git_is_asked_with_safe_directory(tmp_path: Path,
                                         monkeypatch: pytest.MonkeyPatch) -> None:
    me = sys.modules[__name__]

    (tmp_path / ".git").mkdir()
    monkeypatch.setattr(me, "ROOT", tmp_path)

    calls: list[list[str]] = []

    def run(cmd: list[str], **kw: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(me.subprocess, "run", run)
    me._tracked_texts()
    assert calls and calls[0][:3] == ["git", "-c", "safe.directory=*"]


def test_a_failing_git_fails_loudly_with_code_and_stderr(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    me = sys.modules[__name__]

    (tmp_path / ".git").mkdir()
    monkeypatch.setattr(me, "ROOT", tmp_path)

    def run(cmd: list[str], **kw: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(cmd, 128, stdout=b"",
                                           stderr=b"fatal: detected dubious ownership")

    monkeypatch.setattr(me.subprocess, "run", run)
    with pytest.raises(pytest.fail.Exception, match="128.*dubious ownership"):
        me._tracked_texts()


def test_without_git_the_whole_tree_is_read(tmp_path: Path,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    """A tree from git archive has no .git: every file outside caches and
    virtual environments is read."""
    me = sys.modules[__name__]

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
    for skipped in (".venv", "__pycache__", "node_modules", ".pytest_cache"):
        (tmp_path / skipped).mkdir()
        (tmp_path / skipped / "b.py").write_text("y = 2\n", encoding="utf-8")
    monkeypatch.setattr(me, "ROOT", tmp_path)
    assert [rel for rel, _ in me._tracked_texts()] == ["src/a.py"]
