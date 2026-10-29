"""The old product name appears nowhere in what we ship.

The collector was renamed twice and carries its current name since
01.10.2026 (DPMA 302026254573.4). Ivan's acceptance criterion was literal: a
grep for the old spelling returns nothing in the repositories. On 29.10.2026
he extended it to the READ path too ("nein, es gibt keine kunden"), so the
compatibility readers are gone as well — the move is complete rather than
layered.

This test is that criterion, encoded.

**This file does not spell the word it forbids.** It builds the needle from
parts, so it no longer needs to exempt itself — and an exemption is exactly
what this guard exists to prevent.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]

_NOT_OURS = {
    ".git", ".venv", "__pycache__", ".mypy_cache", ".ruff_cache",
    ".pytest_cache", "dist", "build", "node_modules",
}

_TEXT = {
    ".py", ".md", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".json",
    ".txt", ".sh", ".spec", ".html", ".js", ".svg", ".xml", ".css",
    ".csv", ".rst",
}

#: Markup, in dem ein Wort ueber Tag-Grenzen hinweg geschrieben sein kann.
_MARKUP = {".svg", ".html", ".xml", ".md"}

_TAG = re.compile(r"<[^>]*>")

#: A line carrying this marker may name the old spelling. The marker makes
#: every exception visible and countable.
#: Aus Teilen gebaut, sonst stolpert der Waechter ueber seine eigene
#: Definition, seit er sich selbst mitliest.
_MARKER = "alter-name" + "-als-datum"

#: Das verbotene Wort, ebenfalls aus Teilen.
_ALT = "embt" + "race"

#: Where the old spelling is allowed, and why. NOT compatibility: a stamp
#: sits INSIDE a bill that already exists on a disk, written before the rename
#: of 01.10.2026, and cannot be renamed retroactively. Reading it is reading
#: our own past output; the write path never emits it.
#: Leer, und das ist das Ziel. Bis zum 29.10.2026 standen hier fuenf
#: Eintraege: diese Datei selbst, ``sbom_out.py`` (OWN_TOOL_NAMES),
#: ``filenames.py`` (die Pruefung auf alte Dateinamen) und ihre beiden
#: Tests. Keiner wird mehr gebraucht — die Lesepfade sind weg, die Meldung
#: prueft die FORM statt eines Namens, und dieser Waechter buchstabiert das
#: Wort nicht mehr. Ein neuer Eintrag ist ab jetzt eine Entscheidung, die
#: begruendet werden muss, kein Nachtrag.
_ALLOWED_TO_NAME_IT: dict[Path, str] = {}


def _shipped_files() -> list[Path]:
    out = []
    for path in _REPO.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _NOT_OURS for part in path.relative_to(_REPO).parts):
            continue
        if path.resolve() in _ALLOWED_TO_NAME_IT:
            continue
        if path.suffix.lower() in _TEXT:
            out.append(path)
    return out


@pytest.mark.parametrize("needle", [_ALT, _ALT.capitalize(), _ALT.upper()])
def test_no_shipped_file_names_the_old_product(needle: str) -> None:
    hits: list[str] = []
    for path in _shipped_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):  # pragma: no cover - binary
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if needle in line and _MARKER not in line:
                hits.append(f"{path.relative_to(_REPO)}:{number}")
    assert not hits, hits


def test_the_search_would_actually_find_something() -> None:
    files = _shipped_files()
    assert len(files) > 40, len(files)
    assert any(p.suffix == ".py" for p in files)
    assert any(p.suffix == ".md" for p in files)


def _visible_text(markup: str) -> str:
    """What a reader sees: tags removed, whitespace collapsed.

    Measured in the suite on 02.10.2026: its logo files drew the old name
    as ``<tspan>emb</tspan><tspan>trace</tspan>``. A line-wise search over
    the raw markup cannot see that word. The collector has no markup today,
    so this guard is a watch kept, not a fix — and the self-check below
    makes sure it is not a guard that reads nothing.
    """
    return re.sub(r"\s+", "", _TAG.sub(" ", markup)).lower()


def test_no_markup_draws_the_old_name_across_tags() -> None:
    hits: list[str] = []
    for path in _shipped_files():
        if path.suffix.lower() not in _MARKUP:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):  # pragma: no cover - binary
            continue
        if _ALT in _visible_text(text):
            hits.append(str(path.relative_to(_REPO)))
    assert not hits, hits


def test_the_tag_stripper_sees_a_split_word() -> None:
    geteilt = '<text><tspan fill="#1e3a8a">emb</tspan><tspan>trace</tspan></text>'
    assert _ALT in _visible_text(geteilt)
    assert _ALT not in _visible_text("<p>Joch</p><p>wacht</p>")


def test_no_tracked_path_carries_the_old_name() -> None:
    """A file whose NAME carries it is a hit even with clean content."""
    out = subprocess.run(
        ["git", "-C", str(_REPO), "ls-files", "-z"],
        capture_output=True, text=True, check=True,
    ).stdout.split("\0")
    hits = [rel for rel in out if rel and _ALT in rel.lower()]
    assert not hits, hits


def test_every_exception_carries_its_marker_and_its_reason() -> None:
    for path, reason in _ALLOWED_TO_NAME_IT.items():
        assert path.is_file(), path
        assert len(reason) > 30, (path, reason)
        if path == Path(__file__).resolve():
            continue
        assert _MARKER in path.read_text(encoding="utf-8"), (
            f"{path} is allowed but does not say why"
        )


def test_the_exception_is_narrow() -> None:
    """The marker may not spread across the tree."""
    marked = []
    for path in _shipped_files():
        try:
            if _MARKER in path.read_text(encoding="utf-8"):
                marked.append(path.resolve())
        except (UnicodeDecodeError, OSError):  # pragma: no cover - binary
            continue
    unexpected = [str(p.relative_to(_REPO)) for p in marked
                  if p not in _ALLOWED_TO_NAME_IT]
    assert not unexpected, unexpected


def test_the_write_path_signs_only_the_current_name() -> None:
    """The exception is READ-only — that keeps it from being a layer."""
    import json

    from jochwacht_sbom.collector import CheckStats
    from jochwacht_sbom.sbom_out import build_cyclonedx

    doc = build_cyclonedx([], CheckStats(), project_name="demo")
    gezeichnet = {c["name"] for c in doc["metadata"]["tools"]["components"]}
    assert gezeichnet == {"jochwacht-sbom"}
    assert _ALT not in json.dumps(doc)
