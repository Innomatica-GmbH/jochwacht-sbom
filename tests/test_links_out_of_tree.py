"""The tree walk does not leave the scanned tree: a linked directory or
lockfile that resolves outside is not read (same rule as the suite)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from jochwacht_sbom.cli import main


def test_links_out_of_the_tree_are_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    (outside / "proj").mkdir(parents=True)
    (outside / "proj" / "requirements.txt").write_text("leaked-dir==1.0\n", encoding="utf-8")
    (outside / "requirements.txt").write_text("leaked-file==1.0\n", encoding="utf-8")
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "requirements.txt").write_text("idna==3.7\n", encoding="utf-8")
    (root / "linked").symlink_to(outside / "proj", target_is_directory=True)
    (root / "sub" / "requirements.txt").symlink_to(outside / "requirements.txt")
    res = CliRunner().invoke(main, [str(root), "--no-send"])
    assert res.exit_code == 0, res.output
    names = {c["name"] for c in json.loads((root / "sbom.cdx.json").read_text())["components"]}
    assert "idna" in names
    assert "leaked-dir" not in names and "leaked-file" not in names, names
