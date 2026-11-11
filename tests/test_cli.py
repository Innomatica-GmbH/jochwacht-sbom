"""Tests for the jochwacht-sbom CLI (no network access).

Status messages go to stderr (rich Console), the dry-run payload JSON goes to
stdout — so ``result.output`` of a dry run is directly ``json.loads``-able.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from jochwacht_sbom import cli as check_cli
from jochwacht_sbom.core.exceptions import CheckUploadError

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def demo_project(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    return tmp_path


def test_dry_run_prints_parseable_payload_and_uploads_nothing(demo_project: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(check_cli.main, [str(demo_project), "--dry-run"])
    assert result.exit_code == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["components"][0]["name"] == "requests"
    assert "nothing was sent" in result.stderr


def test_output_writes_valid_payload_file(demo_project: Path, tmp_path: Path) -> None:
    out = tmp_path / "payload.json"
    runner = CliRunner()
    result = runner.invoke(check_cli.main, [str(demo_project), "--output", str(out)])
    assert result.exit_code == 0, result.stderr
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["schema_version"] == 1
    assert parsed["components"][0]["name"] == "requests"


def test_upload_happy_path_uses_reference(
    demo_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(check_cli, "upload_payload", lambda payload, *, url: "CHK-TEST-1")
    runner = CliRunner()
    result = runner.invoke(
        check_cli.main,
        # 0.8.4: sending is explicit (--send); --yes skips the confirmation.
        [str(demo_project), "--send", "--yes",
         "--voucher", "TEST-1", "--email", "cto@example.com"],
    )
    assert result.exit_code == 0, result.stderr
    assert "CHK-TEST-1" in result.stderr


def test_default_transmits_nothing_and_send_needs_email(demo_project: Path) -> None:
    """0.8.4 (Ivan 09.09.): the default run writes the SBOM and sends NOTHING —
    no code is required any more. Only --send transmits, and it needs an
    address so the report can arrive."""
    runner = CliRunner()
    result = runner.invoke(check_cli.main, [str(demo_project)])
    assert result.exit_code == 0
    assert "Nothing was transmitted" in result.stderr

    result = runner.invoke(check_cli.main, [str(demo_project), "--send"])
    assert result.exit_code == 1
    assert "--email" in result.stderr


def test_code_uploads_without_email(
    demo_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, str] = {}

    def fake_upload(payload, *, url):  # type: ignore[no-untyped-def]
        captured["voucher"] = payload.voucher
        captured["email"] = payload.contact_email
        return "CHK-TEST-2"

    monkeypatch.setattr(check_cli, "upload_payload", fake_upload)
    runner = CliRunner()
    result = runner.invoke(
        check_cli.main,
        [str(demo_project), "--send", "--yes", "--code", "CHK-ACME-7F3A"],
    )
    assert result.exit_code == 0, result.stderr
    assert captured["voucher"] == "CHK-ACME-7F3A"
    assert captured["email"] == ""
    # 0.18.1: the reference only — no promise where or when a report arrives.
    assert "CHK-TEST-2" in result.stderr
    assert "registered address" not in result.stderr


def test_code_and_voucher_together_rejected(demo_project: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        check_cli.main,
        [str(demo_project), "--send", "--yes",
         "--code", "CHK-A-1111", "--voucher", "X", "--email", "a@b.de"],
    )
    assert result.exit_code == 1
    assert "not both" in result.stderr


def test_empty_project_exits_2(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(check_cli.main, [str(tmp_path), "--dry-run"])
    assert result.exit_code == 2
    assert "No supported build system found" in result.stderr
    assert "BUILD directory" in result.stderr


def test_upload_error_maps_to_exit_1(
    demo_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(payload: object, *, url: str) -> str:
        raise CheckUploadError("endpoint down")

    monkeypatch.setattr(check_cli, "upload_payload", _boom)
    runner = CliRunner()
    result = runner.invoke(
        check_cli.main,
        [str(demo_project), "--send", "--yes",
         "--voucher", "TEST-1", "--email", "cto@example.com"],
    )
    assert result.exit_code == 1
    assert "endpoint down" in result.stderr


def test_anonymize_hides_project_name(demo_project: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(check_cli.main, [str(demo_project), "--dry-run", "--anonymize"])
    assert result.exit_code == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["project_label"].startswith("anon-")
    assert demo_project.name not in payload["project_label"]
