"""FetchContent: the version from GIT_TAG or from the archive in URL, the same
reader as the suite (analyzer/parsers/cmake.py). Measured 11.11.2026: cJSON
from a URL archive v1.7.17 was written without a version; a URL-only
declaration before a GIT_TAG one took the next declaration's tag."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from jochwacht_sbom.cli import main


def _bill(proj: Path) -> dict[str, dict]:
    res = CliRunner().invoke(main, [str(proj), "--no-send"])
    assert res.exit_code == 0, res.output
    return {c["name"]: c for c in json.loads((proj / "sbom.cdx.json").read_text())["components"]}


def test_url_archive_version_and_no_borrowed_tag(tmp_path: Path) -> None:
    proj = tmp_path / "fw"
    proj.mkdir()
    (proj / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.16)\nproject(fw C)\ninclude(FetchContent)\n"
        "FetchContent_Declare(snap URL https://example.org/snapshot.tar.gz)\n"
        "FetchContent_Declare(cjson URL "
        "https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.17.tar.gz)\n"
        "FetchContent_Declare(fmt GIT_REPOSITORY https://github.com/fmtlib/fmt.git"
        " GIT_TAG 10.2.1)\nFetchContent_MakeAvailable(snap cjson fmt)\n", encoding="utf-8")
    comps = _bill(proj)
    assert comps["cjson"]["version"] == "1.7.17"
    assert comps["cjson"]["purl"] == "pkg:generic/cjson@1.7.17"
    assert comps["fmt"]["version"] == "10.2.1"
    assert comps.get("snap", {}).get("version", "") != "10.2.1"
