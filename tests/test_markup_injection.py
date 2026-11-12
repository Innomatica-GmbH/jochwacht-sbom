"""Names from the scanned project are text, never Rich markup.

A dependency named "[link=…]…[/link]" became a terminal link, "[bold red]"
styled the output, and "[/bold]" stopped the run with MarkupError; the
collector printed such names through a plain Rich console.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from click.testing import CliRunner

from jochwacht_sbom import cli as check_cli

if TYPE_CHECKING:
    from pathlib import Path

LINK = "[link=https://evil.example/x]hier klicken[/link]"
BOLD = "[bold red]WARNUNG[/bold red]"
CLOSE = "[/bold]x"


def test_a_project_cannot_inject_markup(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({
        "name": BOLD, "version": "1.0.0",
        "dependencies": {p: "1.0.0" for p in (LINK, BOLD, CLOSE)}}), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "demo", "lockfileVersion": 3, "packages": {
            "": {"name": "demo"},
            **{f"node_modules/{p}": {"version": "1.0.0" + BOLD} for p in (LINK, BOLD, CLOSE)},
        }}), encoding="utf-8")
    # the send preview lists names, versions and the project label; "n" sends nothing
    res = CliRunner().invoke(check_cli.main, [str(tmp_path)], input="n\n",
                             env={"COLUMNS": "2000"})
    assert res.exception is None or isinstance(res.exception, SystemExit), repr(res.exception)
    flat = "".join(res.output.split())
    assert flat.count("WARNUNG") > 0, res.output          # the names are shown
    assert flat.count("WARNUNG") == flat.count("[boldred]WARNUNG[/boldred]"), res.output
    assert flat.count("hierklicken") == flat.count(
        "[link=https://evil.example/x]hierklicken[/link]"), res.output
