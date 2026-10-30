"""Go scanner tests: the LINKED set (go list -deps), go.sum only a fallback.

Ported from the suite (CRA, Ivan 30.10.2026): a go.sum-only bill lists ALL
versions including superseded ones, so it is marked ``versions_unresolved`` and
the collector carries that into the payload for the server's note.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import jochwacht_sbom.sbom.scanner as sc
from jochwacht_sbom.collector import collect_components
from jochwacht_sbom.sbom.scanner import scan_go

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_fallback_ohne_toolchain_markiert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # go.sum present, no go toolchain -> fall back to go.sum + mark each dep.
    (tmp_path / "go.sum").write_text(
        "github.com/gorilla/mux v1.8.1 h1:x=\n"
        "github.com/gorilla/mux v1.8.1/go.mod h1:y=\n"
        "golang.org/x/text v0.14.0 h1:z=\n"
    )
    monkeypatch.setattr(sc.shutil, "which", lambda _: None)
    deps = scan_go(tmp_path / "go.sum")
    assert sorted(d.name for d in deps) == [
        "github.com/gorilla/mux", "golang.org/x/text",
    ]
    assert all(d.versions_unresolved for d in deps)
    assert all(d.ecosystem == "golang" for d in deps)


def test_aufgeloest_via_go_list_deps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # go.mod + toolchain: the resolved linked set, NOT marked. A module
    # replacement resolves to the BUILT module (containous/mux, not the
    # replaced-away gorilla/mux).
    (tmp_path / "go.mod").write_text("module example.test/x\n\ngo 1.21\n")
    (tmp_path / "go.sum").write_text("irrelevant v1.0.0 h1:x=\n")
    monkeypatch.setattr(sc.shutil, "which", lambda _: "/usr/bin/go")

    def fake_run_go(args: list[str], cwd: Path, timeout: float = 180.0):
        if args[:2] == ["list", "-f"]:
            return True, "main\texample.test/x/cmd/app\n"
        if args[:3] == ["list", "-deps", "-json"]:
            return True, (
                '{"Module": {"Path": "github.com/gorilla/mux", "Version": "v1.8.1",'
                ' "Replace": {"Path": "github.com/containous/mux",'
                ' "Version": "v0.0.0-20250523120546-41b6ec3aed59"}}}\n'
                '{"Module": {"Path": "golang.org/x/text", "Version": "v0.14.0"}}\n'
                '{"Standard": true}\n'
                '{"Module": {"Path": "example.test/x", "Main": true}}\n'
            )
        raise AssertionError(args)

    monkeypatch.setattr(sc, "_run_go", fake_run_go)
    deps = scan_go(tmp_path / "go.sum")
    names = sorted(d.name for d in deps)
    assert names == ["github.com/containous/mux", "golang.org/x/text"]
    assert all(not d.versions_unresolved for d in deps)
    # The own main module (empty version) is not listed.
    assert "example.test/x" not in names


def test_collector_traegt_go_vermerk_in_die_statistik(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The go.sum fallback must reach the payload: CheckStats.go_versions_unresolved.
    (tmp_path / "go.sum").write_text(
        "github.com/gorilla/mux v1.8.1 h1:x=\n"
        "github.com/gorilla/mux v1.8.1/go.mod h1:y=\n"
    )
    monkeypatch.setattr(sc.shutil, "which", lambda _: None)
    _components, stats = collect_components(tmp_path)
    assert stats.go_versions_unresolved is True
