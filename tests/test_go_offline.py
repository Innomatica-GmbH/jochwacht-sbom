"""``go list`` never reaches the network (coordination, 14.11.2026).

Since 0.18.0 the default run calls ``go list -deps`` when a Go toolchain is
installed. With the toolchain's defaults go downloads missing modules from
proxy.golang.org, asks sum.golang.org, and a ``toolchain`` line in go.mod can
make it download another Go — the names of the project's dependencies would
leave the machine, against "nothing leaves your machine by default". The
call now runs with a fixed offline environment that overrides the user's
own; when the module cache lacks what the project needs, the run says so by
name and falls back to go.sum.
"""

from __future__ import annotations

import http.server
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

import jochwacht_sbom.sbom.scanner as sc
from jochwacht_sbom.cli import main

OFFLINE = {
    "GOPROXY": "off", "GOTOOLCHAIN": "local", "GOSUMDB": "off", "GOVCS": "*:off",
    "GOFLAGS": "-mod=readonly", "GONOPROXY": "", "GONOSUMDB": "", "GOPRIVATE": "",
}


def _go_project(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "go.mod").write_text(
        "module example.test/fw\n\ngo 1.21\n\nrequire github.com/google/uuid v1.6.0\n",
        encoding="utf-8")
    (root / "go.sum").write_text(
        "github.com/google/uuid v1.6.0 h1:x=\n"
        "github.com/google/uuid v1.6.0/go.mod h1:y=\n", encoding="utf-8")
    (root / "main.go").write_text(
        'package main\n\nimport "github.com/google/uuid"\n\n'
        "func main() { _ = uuid.New() }\n", encoding="utf-8")
    return root


def test_the_go_call_runs_with_the_offline_environment(
    tmp_path: Path, monkeypatch: Any,
) -> None:
    """The user's own settings (a proxy, -mod=mod, a toolchain switch, private
    patterns that go direct) never reach the call."""
    for key, value in {"GOPROXY": "https://proxy.example.invalid", "GOFLAGS": "-mod=mod",
                       "GOTOOLCHAIN": "auto", "GONOPROXY": "*", "GOPRIVATE": "*",
                       "GOSUMDB": "sum.golang.org", "GOVCS": "*:git"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("JOCHWACHT_KEEP_ME", "1")
    seen: list[dict[str, str]] = []

    def fake_run(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        seen.append(kw["env"])
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sc.shutil, "which", lambda _: "/usr/bin/go")
    monkeypatch.setattr(sc.subprocess, "run", fake_run)
    sc._run_go(["list", "./..."], tmp_path)
    assert len(seen) == 1
    env = seen[0]
    assert {k: env.get(k) for k in OFFLINE} == OFFLINE
    assert env["JOCHWACHT_KEEP_ME"] == "1"        # the rest of the environment stays


def test_a_failed_offline_go_list_is_named_in_the_output(
    tmp_path: Path, monkeypatch: Any,
) -> None:
    proj = _go_project(tmp_path / "repo")

    def fake_run(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            cmd, 1, "", "main.go:3:8: github.com/google/uuid@v1.6.0: module lookup "
                        "disabled by GOPROXY=off\n")

    monkeypatch.setattr(sc.shutil, "which", lambda _: "/usr/bin/go")
    monkeypatch.setattr(sc.subprocess, "run", fake_run)
    res = CliRunner().invoke(main, [str(proj)])
    out = " ".join(res.output.split())
    assert res.exit_code == 0, res.output
    assert "Go:" in out and "module cache" in out and "go mod download" in out
    assert "never lets go download" in out


def test_a_newer_toolchain_in_go_mod_is_named(tmp_path: Path, monkeypatch: Any) -> None:
    proj = _go_project(tmp_path / "repo")

    def fake_run(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            cmd, 1, "", "go: go.mod requires go >= 1.99 (running go 1.22.2; "
                        "GOTOOLCHAIN=local)\n")

    monkeypatch.setattr(sc.shutil, "which", lambda _: "/usr/bin/go")
    monkeypatch.setattr(sc.subprocess, "run", fake_run)
    res = CliRunner().invoke(main, [str(proj)])
    assert "newer Go toolchain" in " ".join(res.output.split())


class _Listener(http.server.BaseHTTPRequestHandler):
    seen: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        _Listener.seen.append(self.path)
        self.send_response(404)
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


@pytest.mark.skipif(shutil.which("go") is None, reason="needs a Go toolchain")
@pytest.mark.parametrize("go_line", ["go 1.21", "go 1.99.0"])   # 1.99: a toolchain switch
def test_with_real_go_a_listening_proxy_gets_no_request(
    tmp_path: Path, monkeypatch: Any, go_line: str,
) -> None:
    """Measured with the real toolchain against a local listening proxy
    (sicherheit-2, G-NET): before the fix it received the module's .mod and
    .zip, or golang.org/toolchain; now nothing, the module cache stays empty,
    the run names the gap and the bill falls back to go.sum."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Listener)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _Listener.seen = []
    cache = tmp_path / "modcache"
    cache.mkdir()
    for key in ("GOFLAGS", "GONOPROXY", "GOPRIVATE", "GONOSUMDB", "GOVCS"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GOMODCACHE", str(cache))
    monkeypatch.setenv("GOCACHE", str(tmp_path / "gocache"))
    monkeypatch.setenv("GOPROXY", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("GOSUMDB", "off")
    monkeypatch.setenv("GOTOOLCHAIN", "auto")
    proj = _go_project(tmp_path / "repo")
    gomod = proj / "go.mod"
    gomod.write_text(gomod.read_text(encoding="utf-8").replace("go 1.21", go_line),
                     encoding="utf-8")
    try:
        res = CliRunner().invoke(main, [str(proj)])
    finally:
        server.shutdown()
    assert _Listener.seen == []
    assert res.exit_code == 0, res.output
    assert "Go:" in " ".join(res.output.split())
    # go takes an empty lock file in the cache even offline; nothing else lands.
    landed = [p for p in cache.rglob("*") if p.is_file()]
    assert all(p.suffix == ".lock" and p.stat().st_size == 0 for p in landed), landed
    assert "github.com/google/uuid" in (proj / "sbom.cdx.json").read_text(encoding="utf-8")
