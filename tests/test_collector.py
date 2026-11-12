"""Tests for the check collector (lockfile + pipeline merge)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from jochwacht_sbom.analyzer.normalize import normalize_dep_name
from jochwacht_sbom.collector import collect_components
from jochwacht_sbom.core.exceptions import CheckCollectionError

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def demo_project(tmp_path: Path) -> Path:
    """A minimal polyglot project: Python lockfile + CMake build file."""
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nurllib3==2.2.1\n", encoding="utf-8"
    )
    (tmp_path / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\n"
        "project(demo)\n"
        "find_package(OpenSSL REQUIRED)\n",
        encoding="utf-8",
    )
    return tmp_path


def test_collects_from_lockfile_and_build_file(demo_project: Path) -> None:
    components, stats = collect_components(demo_project)
    names = {normalize_dep_name(c.name) for c in components}
    assert normalize_dep_name("requests") in names
    assert normalize_dep_name("openssl") in names
    assert stats.build_files_scanned >= 1
    assert "pypi" in stats.ecosystems


def test_lockfile_entries_carry_versions_and_win_dedup(demo_project: Path) -> None:
    components, _stats = collect_components(demo_project)
    by_norm = {normalize_dep_name(c.name): c for c in components}
    req = by_norm[normalize_dep_name("requests")]
    assert req.version == "2.31.0"
    assert req.source_type == "lockfile"
    # dedup: every normalized name appears exactly once
    norms = [normalize_dep_name(c.name) for c in components]
    assert len(norms) == len(set(norms))


def test_empty_directory_yields_no_components(tmp_path: Path) -> None:
    components, stats = collect_components(tmp_path)
    assert components == []
    assert stats.ecosystems == []


def test_missing_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(CheckCollectionError):
        collect_components(tmp_path / "does-not-exist")


def test_build_output_yocto_manifest(tmp_path: Path) -> None:
    """the collector reads the
    BUILD OUTPUT — deploy/images manifests (name arch version)."""
    d = tmp_path / "deploy" / "images" / "beaglebone"
    d.mkdir(parents=True)
    (d / "core-image.rootfs.manifest").write_text(
        "alsa-conf cortexa8hf_neon 1.2.15.3\n", encoding="utf-8",
    )
    components, stats = collect_components(tmp_path)
    comp = {c.name: c for c in components}["alsa-conf"]
    assert comp.version == "1.2.15.3"       # arch is never the version
    assert comp.source_type == "build-output"
    assert stats.build_output_sources


def test_west_manifest_modules(tmp_path: Path) -> None:
    (tmp_path / "west.yml").write_text(
        "manifest:\n"
        "  remotes:\n"
        "    - name: upstream\n"
        "      url-base: https://github.com/zephyrproject-rtos\n"
        "  defaults:\n"
        "    remote: upstream\n"
        "  projects:\n"
        "    - name: hal_adi\n"
        "      revision: v1.2.3\n",
        encoding="utf-8",
    )
    components, _ = collect_components(tmp_path)
    comp = {c.name: c for c in components}["hal_adi"]
    assert comp.version == "v1.2.3"


def test_nested_second_version_is_kept(tmp_path: Path) -> None:
    """Identity is (name, version) — nested npm second versions are
    rows, the older one is often the vulnerable one."""
    import json as _json

    lock = {
        "name": "demo", "lockfileVersion": 3,
        "packages": {
            "node_modules/acorn": {"version": "8.15.0"},
            "node_modules/x/node_modules/acorn": {"version": "6.4.2"},
        },
    }
    (tmp_path / "package-lock.json").write_text(_json.dumps(lock), encoding="utf-8")
    components, _ = collect_components(tmp_path)
    assert sorted(
        c.version for c in components if c.name == "acorn"
    ) == ["6.4.2", "8.15.0"]


def test_skip_list_drops_build_tools_never_declared(tmp_path: Path) -> None:
    """paho.mqtt.c delivered "n", anl and Doxygen as components — the
    curated skip list drops discovered build tooling; a customer's own
    declaration is never skipped."""
    (tmp_path / "CMakeLists.txt").write_text(
        "find_package(Doxygen)\nfind_package(OpenSSL REQUIRED)\n",
        encoding="utf-8",
    )
    (tmp_path / "jochwacht-deps.yaml").write_text(
        "dependencies:\n"
        "  - name: doxygen\n"     # absurd, but declared = their statement
        "    version: '1.9'\n"
        "    supplier: Example\n"
        "    license: MIT\n",
        encoding="utf-8",
    )
    components, _ = collect_components(tmp_path)
    names = [(c.name.lower(), c.source_type) for c in components]
    assert ("doxygen", "declared") in names
    assert not any(n == "doxygen" and s != "declared" for n, s in names)
    assert any(n == "openssl" for n, _ in names)
