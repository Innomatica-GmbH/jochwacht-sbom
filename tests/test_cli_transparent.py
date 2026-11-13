"""0.8.4 — the collector shows first, then sends.

The DEFAULT run generates, shows and SAVES a real CycloneDX
SBOM and transmits nothing; sending is an explicit decision (--send, or the
question after the summary), needs only an e-mail address (the mandatory code
was dropped), and shows exactly what leaves the house before the POST.

The three named tests the order asks for:
- ``default_never_uploads``
- ``send_confirms_before_post``
- ``existing_sbom_not_overwritten``
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from jochwacht_sbom.cli import main

_ENV = {"JOCHWACHT_API_KEY": "jw_test_" + "k" * 24}  # a stand-in, never a real key
_ANSWER = {"status": "new", "product": "prd_1", "version": 5, "components": 1,
           "status_href": "/api/v1/products/prd_1/sbom-versions/5/status"}


def _project(tmp_path: Path) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    (p / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\n"
        "project(proj)\n"
        "find_package(OpenSSL REQUIRED)\n",
        encoding="utf-8",
    )
    return p


class TestDefaultNeverUploads:
    """default_never_uploads: without --send nothing leaves the house."""

    def test_default_run_writes_sbom_and_uploads_nothing(
        self, tmp_path: Path,
    ) -> None:
        proj = _project(tmp_path)
        with patch("jochwacht_sbom.api.Client.upload") as up:
            res = CliRunner().invoke(main, [str(proj)])
        assert res.exit_code == 0, res.output
        up.assert_not_called()                      # nothing transmitted
        sbom = proj / "sbom.cdx.json"
        assert sbom.is_file(), res.output           # …but the SBOM is written
        doc = json.loads(sbom.read_text(encoding="utf-8"))
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.6"
        assert any(c["name"] == "OpenSSL" for c in doc["components"])
        # and the run says so, plus where the file is
        assert "Nothing was transmitted" in res.output
        assert "sbom.cdx.json" in res.output

    def test_non_tty_never_asks(self, tmp_path: Path) -> None:
        # In CI (no TTY) the tool must not block on a question — it prints the
        # invitation and exits.
        proj = _project(tmp_path)
        with patch("jochwacht_sbom.api.Client.upload") as up:
            res = CliRunner().invoke(main, [str(proj)])
        assert res.exit_code == 0
        up.assert_not_called()
        assert "Send now?" not in res.output


class TestSendConfirmsBeforePost:
    """send_confirms_before_post: the summary comes first, then the question."""

    def test_declining_the_confirmation_sends_nothing(
        self, tmp_path: Path,
    ) -> None:
        proj = _project(tmp_path)
        with patch("jochwacht_sbom.api.Client.upload") as up, \
             patch("jochwacht_sbom.cli._stdin_is_terminal", return_value=True):
            res = CliRunner().invoke(
                main, [str(proj), "--send"], input="n\n", env=_ENV,
            )
        assert res.exit_code == 0, res.output
        up.assert_not_called()
        assert "This would be sent" in res.output   # summary shown FIRST
        assert "sbom.cdx.json" in res.output        # the file, exactly as written
        assert "Nothing was sent" in res.output

    def test_confirming_posts_once(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        with patch("jochwacht_sbom.api.Client.upload", return_value=_ANSWER) as up, \
             patch("jochwacht_sbom.cli._stdin_is_terminal", return_value=True):
            res = CliRunner().invoke(
                main, [str(proj), "--send"], input="y\n", env=_ENV,
            )
        assert res.exit_code == 0, res.output
        assert up.call_count == 1
        assert "version 5" in res.output

    def test_yes_skips_the_question(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        with patch("jochwacht_sbom.api.Client.upload", return_value=_ANSWER) as up:
            res = CliRunner().invoke(main, [str(proj), "--send", "--yes"], env=_ENV)
        assert res.exit_code == 0, res.output
        assert up.call_count == 1

    def test_send_sends_the_written_sbom(self, tmp_path: Path) -> None:
        # 12.11.2026: what leaves the house is a file the customer can open.
        # 0.20: it is the slim copy .jochwacht/sent.cdx.json; without build
        # evidence it says the same as the local bill (serial and time aside).
        import json as _json

        proj = _project(tmp_path)
        with patch("jochwacht_sbom.api.Client.upload", return_value=_ANSWER) as up:
            res = CliRunner().invoke(main, [str(proj), "--send", "--yes"], env=_ENV)
        assert res.exit_code == 0, res.output
        sent = (proj / ".jochwacht" / "sent.cdx.json").read_bytes()
        assert up.call_args[0][0] == sent
        local = _json.loads((proj / "sbom.cdx.json").read_text(encoding="utf-8"))
        copy = _json.loads(sent)
        for doc in (local, copy):
            doc.pop("serialNumber")
            doc["metadata"].pop("timestamp")
        assert copy == local

    def test_send_without_key_fails_before_scanning(
        self, tmp_path: Path,
    ) -> None:
        proj = _project(tmp_path)
        with patch("jochwacht_sbom.api.Client.upload") as up:
            res = CliRunner().invoke(main, [str(proj), "--send"],
                                     env={"JOCHWACHT_API_KEY": ""})
        assert res.exit_code == 1
        up.assert_not_called()
        assert not (proj / "sbom.cdx.json").exists()  # failed before the work


class TestExistingSbomNotOverwritten:
    """A FOREIGN file of that name is evidence and is never touched (0.9.1:
    the run stops with a --sbom hint instead of numbering a copy beside it)."""

    def test_foreign_file_is_left_alone(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        existing = proj / "sbom.cdx.json"
        existing.write_text('{"mine": true}', encoding="utf-8")
        res = CliRunner().invoke(main, [str(proj)])
        assert res.exit_code == 1, res.output
        # untouched, and no numbered copy beside it
        assert json.loads(existing.read_text(encoding="utf-8")) == {"mine": True}
        assert not (proj / "sbom.cdx-2.json").exists()
        assert "--sbom" in res.output

    def test_explicit_sbom_path_is_honoured(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        target = tmp_path / "out" / "bill.json"
        target.parent.mkdir()
        res = CliRunner().invoke(main, [str(proj), "--sbom", str(target)])
        assert res.exit_code == 0, res.output
        assert target.is_file()
        assert json.loads(target.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"


class TestNoSend:
    """no_send_never_asks: for anyone who has decided they
    will not send — never ask, never transmit, just write the SBOM."""

    def test_no_send_never_asks_and_writes(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        with patch("jochwacht_sbom.api.Client.upload") as up, \
             patch("sys.stdin.isatty", return_value=True), \
             patch("sys.stdout.isatty", return_value=True):
            res = CliRunner().invoke(main, [str(proj), "--no-send"])
        assert res.exit_code == 0, res.output
        up.assert_not_called()
        assert "Send now?" not in res.output       # even with a TTY present
        assert (proj / "sbom.cdx.json").is_file()

    def test_no_send_with_send_is_a_contradiction(self, tmp_path: Path) -> None:
        proj = _project(tmp_path)
        with patch("jochwacht_sbom.api.Client.upload") as up:
            res = CliRunner().invoke(main, [str(proj), "--no-send", "--send"], env=_ENV)
        assert res.exit_code == 1
        up.assert_not_called()
        assert "contradict" in res.output
