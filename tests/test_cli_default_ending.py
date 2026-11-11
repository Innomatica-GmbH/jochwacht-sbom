"""0.9.1 — the default run ends in text, not a question (Ivan, 11.09.2026).

Red before: with a TTY the run asked "Send it to jochwacht now …? Send now?",
printed "Your bill of materials is yours: …" and, on a second run, wrote
sbom.cdx-2.json beside the first file.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from jochwacht_sbom.cli import main


def _project(tmp_path: Path) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    (p / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\nproject(proj)\n"
        "find_package(OpenSSL REQUIRED)\n", encoding="utf-8",
    )
    return p


def _tty_run(args: list[str]):  # noqa: ANN202 — click Result
    with patch("jochwacht_sbom.cli.upload_payload") as up, \
         patch("sys.stdin.isatty", return_value=True), \
         patch("sys.stdout.isatty", return_value=True):
        res = CliRunner().invoke(main, args)
    up.assert_not_called()
    return res


class TestNoQuestion:
    def test_with_a_tty_the_run_ends_in_text(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        res = _tty_run([str(proj)])
        assert res.exit_code == 0, res.output
        assert "Send now?" not in res.output
        assert "Send it to jochwacht" not in res.output
        assert "is yours" not in res.output
        assert "Wrote sbom.cdx.json (1 component)." in res.output
        assert "Nothing was transmitted." in res.output
        # 0.18.1: the free report is no longer offered, so no line advertises it
        assert "free" not in res.output.lower(), res.output
        assert "--send" not in res.output, res.output
        assert "privacy" not in res.output.lower()      # the link belongs to --send

    def test_without_a_tty_the_same_text(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        with patch("jochwacht_sbom.cli.upload_payload"):
            res = CliRunner().invoke(main, [str(proj)])
        assert res.exit_code == 0
        assert "Wrote sbom.cdx.json (1 component)." in res.output
        assert "Send now?" not in res.output

    def test_send_path_keeps_preview_privacy_and_confirmation(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        with patch("jochwacht_sbom.cli.upload_payload") as up:
            res = CliRunner().invoke(
                main, [str(proj), "--send", "--email", "a@b.de"], input="n\n",
            )
        assert res.exit_code == 0, res.output
        up.assert_not_called()
        assert "This would be sent" in res.output
        assert "jochwacht.dev/check-privacy" in res.output
        assert "Nothing was sent" in res.output


class TestSecondRunUpdates:
    def test_own_output_is_replaced_with_a_notice(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        first = _tty_run([str(proj)])
        assert first.exit_code == 0
        serial1 = json.loads((proj / "sbom.cdx.json").read_text(encoding="utf-8"))["serialNumber"]
        second = _tty_run([str(proj)])
        assert second.exit_code == 0, second.output
        assert "previous run replaced" in second.output
        assert not (proj / "sbom.cdx-2.json").exists()
        serial2 = json.loads((proj / "sbom.cdx.json").read_text(encoding="utf-8"))["serialNumber"]
        assert serial1 != serial2                     # really rewritten

    def test_old_tool_name_counts_as_own(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        (proj / "sbom.cdx.json").write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "metadata": {"tools": [{"name": "jochwacht-sbom", "version": "0.8.6"}]},
            "components": [],
        }), encoding="utf-8")
        res = _tty_run([str(proj)])
        assert res.exit_code == 0, res.output
        assert "previous run replaced" in res.output
