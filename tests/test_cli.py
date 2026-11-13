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


_KEY = "jw_test_" + "k" * 24  # a stand-in, never a real key


def _answer() -> dict[str, object]:
    return {"status": "new", "product": "prd_1", "version": 5, "components": 1,
            "status_href": "/api/v1/products/prd_1/sbom-versions/5/status"}


def test_send_happy_path_names_the_version(
    demo_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """12.11.2026: --send sends the SBOM to the subscription (key from the
    environment); the answer names the version."""
    from jochwacht_sbom import api

    monkeypatch.setattr(api.Client, "upload", lambda self, sbom, *, product, release="": _answer())
    monkeypatch.setenv("JOCHWACHT_API_KEY", _KEY)
    result = CliRunner().invoke(check_cli.main, [str(demo_project), "--send", "--yes"])
    assert result.exit_code == 0, result.stderr
    assert "version 5" in result.stderr
    assert _KEY not in result.stderr


def test_default_transmits_nothing_and_send_needs_the_key(
    demo_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default run writes the SBOM and sends NOTHING. --send needs the
    key of the subscription in JOCHWACHT_API_KEY."""
    runner = CliRunner()
    result = runner.invoke(check_cli.main, [str(demo_project)])
    assert result.exit_code == 0
    assert "Nothing was transmitted" in result.stderr

    monkeypatch.delenv("JOCHWACHT_API_KEY", raising=False)
    result = runner.invoke(check_cli.main, [str(demo_project), "--send"])
    assert result.exit_code == 1
    assert "JOCHWACHT_API_KEY" in result.stderr


def test_code_and_voucher_end_with_a_message(
    demo_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The free report is gone: --code, --voucher and --email with --send end
    with a clear message instead of a send."""
    monkeypatch.setenv("JOCHWACHT_API_KEY", _KEY)
    result = CliRunner().invoke(
        check_cli.main,
        [str(demo_project), "--send", "--yes", "--code", "CHK-A-1111", "--voucher", "X"],
    )
    assert result.exit_code == 1
    assert "no longer offered" in " ".join(result.stderr.split())


def test_empty_project_exits_2(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(check_cli.main, [str(tmp_path), "--dry-run"])
    assert result.exit_code == 2
    assert "No supported build system found" in result.stderr
    assert "BUILD directory" in result.stderr


def test_upload_error_maps_to_exit_1(
    demo_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from jochwacht_sbom import api

    def _boom(self: object, sbom: bytes, *, product: str, release: str = "") -> dict[str, object]:
        raise api.ApiError("endpoint down")

    monkeypatch.setattr(api.Client, "upload", _boom)
    monkeypatch.setenv("JOCHWACHT_API_KEY", _KEY)
    result = CliRunner().invoke(check_cli.main, [str(demo_project), "--send", "--yes"])
    assert result.exit_code == 1
    assert "endpoint down" in result.stderr


def test_anonymize_hides_project_name(demo_project: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(check_cli.main, [str(demo_project), "--dry-run", "--anonymize"])
    assert result.exit_code == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["project_label"].startswith("anon-")
    assert demo_project.name not in payload["project_label"]
