"""--release and X-Release (contract of 27, §7.1, portal-releases 68e3e72f).

The customer names the release of the product version they send. The label
travels as UTF-8 in X-Release, cleaned like X-Product; more than 100
characters is refused, never shortened. Without X-Release the server reads
metadata.component.version, and "unspecified" counts as no version (422
release_label_missing). The collector therefore never writes "unspecified"
and refuses --send without a label before anything leaves the house.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from test_send_status import BASE, HREF, KEY, FakeOpener

from jochwacht_sbom import api
from jochwacht_sbom.api import ApiError, Client
from jochwacht_sbom.cli import main
from jochwacht_sbom.collector import collect_components
from jochwacht_sbom.sbom_out import build_cyclonedx, slim_bytes


def _project(tmp_path: Path) -> Path:
    proj = tmp_path / "repo"
    proj.mkdir()
    (proj / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    return proj


# --- the header ---------------------------------------------------------------------

def test_the_label_travels_as_utf8_in_x_release() -> None:
    opener = FakeOpener([(200, {"status": "new", "status_href": HREF}, {})])
    Client(BASE, KEY, opener=opener).upload(b"{}", product="fw", release="  2026.11 Süd  ")
    assert opener.requests[0].get_header("X-release") == "2026.11 Süd".encode()


def test_without_a_label_no_header_is_sent() -> None:
    opener = FakeOpener([(200, {"status": "new", "status_href": HREF}, {})])
    Client(BASE, KEY, opener=opener).upload(b"{}", product="fw")
    assert opener.requests[0].get_header("X-release") is None


@pytest.mark.parametrize("bad", [
    "1.0\nX-Api-Key: x", "1.0\r", "1.0" + chr(0), "1.0" + chr(0x202E), "1.0" + chr(0x2028),
    "1.0" + chr(0x200B), "1.0" + chr(0x1B) + "[31m",
])
def test_a_label_with_a_control_or_invisible_character_is_refused(bad: str) -> None:
    opener = FakeOpener([])
    with pytest.raises(ApiError) as caught:
        Client(BASE, KEY, opener=opener).upload(b"{}", product="fw", release=bad)
    assert "release" in str(caught.value) and not opener.requests


def test_more_than_100_characters_is_refused_never_shortened() -> None:
    opener = FakeOpener([(200, {"status": "new", "status_href": HREF}, {})])
    Client(BASE, KEY, opener=opener).upload(b"{}", product="fw", release="r" * 100)
    assert opener.requests[0].get_header("X-release") == b"r" * 100
    with pytest.raises(ApiError) as caught:
        Client(BASE, KEY, opener=FakeOpener([])).upload(b"{}", product="fw",
                                                         release="r" * 101)
    assert "100" in str(caught.value)


@pytest.mark.parametrize(("code", "words"), [
    ("release_label_missing", "--release"),
    ("release_label_invalid", "100"),
])
def test_the_two_refusals_have_our_own_sentence(code: str, words: str) -> None:
    opener = FakeOpener([(422, {"error": {"status": 422, "code": code,
                                          "message": "server text"}}, {})])
    with pytest.raises(ApiError) as caught:
        Client(BASE, KEY, opener=opener).upload(b"{}", product="fw", release="1.0")
    assert words in str(caught.value) and code in str(caught.value)


# --- the bills ----------------------------------------------------------------------

def test_no_bill_says_unspecified(tmp_path: Path) -> None:
    components, stats = collect_components(_project(tmp_path))
    for doc in (build_cyclonedx(components, stats, project_name="fw"),
                json.loads(slim_bytes(components, stats, project_name="fw"))):
        meta = doc["metadata"]["component"]
        assert meta["name"] == "fw"
        assert "version" not in meta, meta


def test_the_label_is_the_version_in_both_bills(tmp_path: Path) -> None:
    components, stats = collect_components(_project(tmp_path))
    full = build_cyclonedx(components, stats, project_name="fw", release="1.4.2")
    sent = json.loads(slim_bytes(components, stats, project_name="fw", release="1.4.2"))
    assert full["metadata"]["component"]["version"] == "1.4.2"
    assert sent["metadata"]["component"]["version"] == "1.4.2"


# --- the CLI ------------------------------------------------------------------------

def _fake_upload(monkeypatch: Any, calls: list[dict[str, Any]],
                 answer: dict[str, Any] | None = None) -> None:
    def upload(self: Any, sbom: bytes, *, product: str, release: str = "") -> dict[str, Any]:
        calls.append({"sbom": sbom, "product": product, "release": release})
        return answer or {"status": "new"}

    monkeypatch.setattr(api.Client, "upload", upload)
    monkeypatch.setenv("JOCHWACHT_API_KEY", KEY)


def test_send_without_a_label_is_refused_before_anything_leaves(
    tmp_path: Path, monkeypatch: Any,
) -> None:
    calls: list[dict[str, Any]] = []
    _fake_upload(monkeypatch, calls)
    monkeypatch.delenv(api.RELEASE_ENV, raising=False)
    proj = _project(tmp_path)
    res = CliRunner().invoke(main, [str(proj), "--send", "--yes"])
    assert res.exit_code != 0
    assert calls == []
    assert not (proj / ".jochwacht" / "sent.cdx.json").exists()
    out = " ".join(res.output.split())
    assert "--release" in out and api.RELEASE_ENV in out


def test_send_with_a_label_names_it_everywhere(tmp_path: Path, monkeypatch: Any) -> None:
    calls: list[dict[str, Any]] = []
    _fake_upload(monkeypatch, calls, {"status": "new", "release": "rel_7", "label": "1.4.2",
                                      "mode": "watch", "version": 3, "product": "fw"})
    monkeypatch.delenv(api.RELEASE_ENV, raising=False)
    proj = _project(tmp_path)
    res = CliRunner().invoke(main, [str(proj), "--send", "--yes", "--release", "1.4.2"])
    assert res.exit_code == 0, res.output
    assert [c["release"] for c in calls] == ["1.4.2"]
    sent = json.loads(calls[0]["sbom"])
    assert sent["metadata"]["component"]["version"] == "1.4.2"
    local = json.loads((proj / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert local["metadata"]["component"]["version"] == "1.4.2"
    out = " ".join(res.output.split())
    assert "Release 1.4.2 (rel_7): watch only." in out


def test_the_label_comes_from_the_environment_too(tmp_path: Path, monkeypatch: Any) -> None:
    calls: list[dict[str, Any]] = []
    _fake_upload(monkeypatch, calls)
    monkeypatch.setenv(api.RELEASE_ENV, "2026.11")
    res = CliRunner().invoke(main, [str(_project(tmp_path)), "--send", "--yes"])
    assert res.exit_code == 0, res.output
    assert [c["release"] for c in calls] == ["2026.11"]


def test_a_bad_label_is_refused_before_the_copy_is_written(
    tmp_path: Path, monkeypatch: Any,
) -> None:
    calls: list[dict[str, Any]] = []
    _fake_upload(monkeypatch, calls)
    proj = _project(tmp_path)
    res = CliRunner().invoke(main, [str(proj), "--send", "--yes", "--release", "r" * 101])
    assert res.exit_code != 0 and calls == []
    assert not (proj / ".jochwacht" / "sent.cdx.json").exists()
