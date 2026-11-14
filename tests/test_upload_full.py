"""--send uploads the full bill (Ivan, 14.11.2026: "volle sbom immer!").

Since 0.21 the upload is the local bill with every field the TR-03183 check
needs: the delivered files with their SHA-512, manufacturer, licence and CPE
the build proves, the image files. Two things stay local (coordination,
14.11.2026): the text of a patch (it can be the customer's own source code;
the upload names each patch by type, SHA-256 and size), and the name of the
scanned folder (``metadata.component.name`` is the build's product, else
--product, else "product"). No absolute path, host name or user name.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
from pathlib import Path
from typing import Any

from click.testing import CliRunner
from test_build_hebel import _tree
from test_send_status import KEY

from jochwacht_sbom import api
from jochwacht_sbom.cli import main
from jochwacht_sbom.collector import collect_components
from jochwacht_sbom.sbom_out import build_cyclonedx, upload_bytes

PATCH_TEXT = "From 1 Mon\n--- a/geheim.c\n+++ b/geheim.c\n+int kunde_geheim = 42; /* /tmp/x */\n"


def _with_patch(root: Path) -> Path:
    tree = _tree(root)
    sbom = tree / "output" / "legal-info" / "buildroot.cdx.json"
    doc = json.loads(sbom.read_text(encoding="utf-8"))
    doc["components"][0]["pedigree"] = {"patches": [
        {"type": "unofficial", "diff": {"text": {"content": PATCH_TEXT}}}]}
    sbom.write_text(json.dumps(doc), encoding="utf-8")
    return tree


def _upload(root: Path, **kw: Any) -> dict[str, Any]:
    components, stats = collect_components(root)
    return json.loads(upload_bytes(components, stats, **kw))


def _by_name(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["name"]: c for c in doc["components"]}


def _walk(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in components:
        out.append(c)
        out.extend(_walk(c.get("components", [])))
    return out


def test_the_upload_carries_files_hashes_licence_and_cpe(tmp_path: Path) -> None:
    busybox = _by_name(_upload(_tree(tmp_path)))["busybox"]
    files = busybox["components"]
    assert [(f["name"], f["type"]) for f in files] == [("busybox", "file")]
    assert files[0]["hashes"][0]["alg"] == "SHA-512"
    assert busybox["licenses"] and busybox["cpe"].startswith("cpe:2.3:a:busybox:busybox")


def test_every_field_of_the_local_bill_is_in_the_upload_except_patch_text(
    tmp_path: Path,
) -> None:
    """The upload is the local bill; only patch text and the folder name differ."""
    root = _with_patch(tmp_path / "fw-kunde")
    components, stats = collect_components(root)
    local = build_cyclonedx(components, stats, project_name="fw-kunde")
    sent = json.loads(upload_bytes(components, stats))
    for doc in (local, sent):
        for comp in _walk(doc["components"]):
            comp.pop("pedigree", None)
            comp["properties"] = [p for p in comp.get("properties", [])
                                  if not p["name"].startswith("jochwacht:patch")]
            if not comp["properties"]:
                del comp["properties"]
    assert sent["components"] == local["components"]


def test_no_patch_text_leaves_but_each_patch_is_named(tmp_path: Path) -> None:
    root = _with_patch(tmp_path)
    components, stats = collect_components(root)
    raw = upload_bytes(components, stats).decode("utf-8")
    assert "kunde_geheim" not in raw
    sent = json.loads(raw)
    assert all("diff" not in p for c in _walk(sent["components"])
               for p in c.get("pedigree", {}).get("patches", []))
    busybox = _by_name(sent)["busybox"]
    assert busybox["pedigree"]["patches"] == [{"type": "unofficial"}]
    digest = hashlib.sha256(PATCH_TEXT.encode("utf-8")).hexdigest()
    props = {p["name"]: p["value"] for p in busybox["properties"]}
    assert props["jochwacht:patch:1"] == f"sha256:{digest} size:{len(PATCH_TEXT.encode())}"
    local = build_cyclonedx(components, stats, project_name="fw")
    assert "kunde_geheim" in json.dumps(local)          # the local bill keeps the text


def test_the_name_is_the_builds_then_the_product_then_product(tmp_path: Path) -> None:
    built = _upload(_tree(tmp_path / "a" / "geheimer-ordner"), product="Steuergerät")
    assert built["metadata"]["component"]["name"] == "buildroot"   # the build states it
    repo = tmp_path / "geheimer-ordner"
    repo.mkdir()
    (repo / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    assert _upload(repo, product="Steuergerät")["metadata"]["component"]["name"] \
        == "Steuergerät"
    assert _upload(repo)["metadata"]["component"]["name"] == "product"
    assert "geheimer-ordner" not in upload_bytes(*collect_components(repo)).decode()


def test_the_release_label_is_the_version_of_the_upload(tmp_path: Path) -> None:
    meta = _upload(_tree(tmp_path), release="7.7.7")["metadata"]["component"]
    assert meta["version"] == "7.7.7"


def test_no_absolute_path_host_or_user_in_the_upload(tmp_path: Path) -> None:
    raw = upload_bytes(*collect_components(_with_patch(tmp_path))).decode("utf-8")
    for needle in (str(tmp_path), "/tmp/", "/home/", socket.gethostname(),
                   os.environ.get("USER", "") or "\0"):
        assert needle not in raw, needle


def _send(proj: Path, monkeypatch: Any, *args: str) -> tuple[Any, list[bytes]]:
    sent: list[bytes] = []

    def upload(self: Any, sbom: bytes, *, product: str, release: str = "") -> dict[str, Any]:
        sent.append(sbom)
        return {"status": "new", "label": release, "mode": "full"}

    monkeypatch.setattr(api.Client, "upload", upload)
    monkeypatch.setenv("JOCHWACHT_API_KEY", KEY)
    res = CliRunner().invoke(main, [str(proj), "--send", "--yes", *args])
    return res, sent


def test_send_uploads_exactly_the_copy_it_names(tmp_path: Path, monkeypatch: Any) -> None:
    root = _with_patch(tmp_path)
    res, sent = _send(root, monkeypatch)
    assert res.exit_code == 0, res.output
    copy = root / ".jochwacht" / "sent.cdx.json"
    assert sent == [copy.read_bytes()]
    doc = json.loads(sent[0])
    assert _by_name(doc)["busybox"]["components"][0]["type"] == "file"
    assert "kunde_geheim" not in sent[0].decode()


def test_the_summary_and_readme_say_what_goes_up(tmp_path: Path, monkeypatch: Any) -> None:
    root = _tree(tmp_path)
    monkeypatch.setenv("JOCHWACHT_API_KEY", KEY)
    monkeypatch.setattr("jochwacht_sbom.cli._stdin_is_terminal", lambda: False)
    monkeypatch.setattr(api.Client, "upload",
                        lambda self, sbom, **_: {"status": "new", "mode": "full"})
    res = CliRunner().invoke(main, [str(root), "--send"])
    out = " ".join(res.output.split())
    assert "file names and their SHA-512" in out and "the text of your patches" in out
    readme = " ".join((Path(__file__).resolve().parents[1] / "README.md")
                      .read_text(encoding="utf-8").split())
    assert "`--send` uploads the full bill" in readme
    assert "the text of a patch stays on your machine" in readme


def test_the_readme_says_when_an_upload_is_unchanged() -> None:
    """daten, rule live in daten-postgres cf286ae1: the components decide, not the bytes."""
    readme = " ".join((Path(__file__).resolve().parents[1] / "README.md")
                      .read_text(encoding="utf-8").split())
    for sentence in (
        "Whether an upload is a new version is decided by the components alone "
        "(name, version, purl, CPE).",
        "the answer is `unchanged`: no new run, no report, no alarm, and the upload "
        "does not count against the daily limit.",
        "if your package includes the TR-03183 check and the release is fully checked, "
        "that check runs on it again.",
        "The newest 10 file states of each version are kept;",
        "a file state that was in force when a report went to the customer is always kept.",
        "The very same file, byte for byte, sent again adds no file state; "
        "only its receipt is recorded.",
    ):
        assert sentence in readme, sentence
    # sicherheit-2 on ab99784: the check needs the entitlement and a full
    # release; a byte-equal upload still leaves its receipt
    assert "the TR-03183 check runs on it again" not in readme
    assert "creates nothing" not in readme


def test_the_readme_says_the_enrichment_follows_the_file_in_force() -> None:
    """daten, daten-postgres 77af3763: an enrichment names its source file
    (bytes_sha256) and is served only for the file in force."""
    readme = " ".join((Path(__file__).resolve().parents[1] / "README.md")
                      .read_text(encoding="utf-8").split())
    assert ("The enriched bill always belongs to the file in force of the version, "
            "the newest file state.") in readme
    assert ("When a new file state arrives, an older enrichment no longer counts, "
            "not even for an older build; the enrichment is made anew for the new "
            "file.") in readme
