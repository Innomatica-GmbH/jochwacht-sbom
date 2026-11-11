"""0.18.1 — the free CRA readiness report is no longer offered.

Red before: the default run ended with "Free CRA readiness report: …",
--help offered it, a send promised the report "within 24 hours" and the
--output path pointed to check@innomatica.de. --send itself stays until
0.19 so that no script breaks; only the texts change.
"""

from __future__ import annotations

import urllib.error
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from jochwacht_sbom.cli import main
from jochwacht_sbom.core.exceptions import CheckUploadError
from jochwacht_sbom.upload import upload_payload

_GONE = ("free cra readiness report", "free report:", "24 hours", "check@innomatica.de")


def _project(tmp_path: Path) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    (p / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\nproject(proj)\n"
        "find_package(OpenSSL REQUIRED)\n", encoding="utf-8",
    )
    return p


def _assert_gone(text: str) -> None:
    low = text.lower()
    for phrase in _GONE:
        assert phrase not in low, (phrase, text)


def test_help_marks_send_deprecated() -> None:
    res = CliRunner().invoke(main, ["--help"])
    assert res.exit_code == 0
    assert "Deprecated: the free report is no longer offered." in " ".join(res.output.split())
    _assert_gone(res.output)


def test_send_success_promises_nothing(tmp_path: Path) -> None:
    proj = _project(tmp_path)
    with patch("jochwacht_sbom.cli.upload_payload", return_value="CHK-1") as up:
        res = CliRunner().invoke(main, [str(proj), "--send", "--email", "a@b.de", "--yes"])
    assert res.exit_code == 0, res.output
    up.assert_called_once()
    assert "Reference: CHK-1." in res.output
    _assert_gone(res.output)


def test_output_path_names_no_mail_address(tmp_path: Path) -> None:
    proj = _project(tmp_path)
    out = tmp_path / "payload.json"
    res = CliRunner().invoke(main, [str(proj), "--output", str(out)])
    assert res.exit_code == 0, res.output
    assert out.is_file()
    _assert_gone(res.output)


def test_network_error_names_no_mail_address() -> None:
    from jochwacht_sbom.payload import CheckPayload

    payload = CheckPayload.model_construct()
    with patch("jochwacht_sbom.upload.serialize_payload", return_value=b"{}"), \
         patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")), \
         pytest.raises(CheckUploadError) as exc:
        upload_payload(payload, url="https://example.invalid/x")
    _assert_gone(str(exc.value))
