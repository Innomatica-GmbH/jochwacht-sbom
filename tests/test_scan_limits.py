"""collector side: oversized lockfiles skipped and named, links
out of the tree not read for FPGA files either, no root = the directory."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from jochwacht_sbom.sbom import scanner
from jochwacht_sbom.sbom.scanner import scan_directory

if TYPE_CHECKING:
    import pytest


def test_an_oversized_lockfile_is_skipped_and_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(scanner, "MAX_LOCKFILE", 64)
    (tmp_path / "requirements.txt").write_text("idna==3.7\n" * 20, encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        assert scan_directory(tmp_path) == []
    assert any("requirements.txt" in r.getMessage() for r in caplog.records)


def test_links_out_of_the_tree_fpga_and_no_root(tmp_path: Path) -> None:
    (tmp_path / "outside.hwh").write_text(
        '<MODULE MODTYPE="leaked_ip" VLNV="xilinx.com:ip:leaked_ip:1.0"/>', encoding="utf-8")
    (tmp_path / "outside.txt").write_text("leaked==1.0\n", encoding="utf-8")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "design.hwh").symlink_to(tmp_path / "outside.hwh")
    (proj / "requirements.txt").symlink_to(tmp_path / "outside.txt")
    assert all("leaked" not in d.name for d in scan_directory(proj))
