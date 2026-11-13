"""jochwacht-sbom --send and jochwacht-sbom status.

In the upload step the customer chooses: our collector, or an own SBOM sent
with curl. The collector sends the SBOM it wrote to the subscription
(contract §7.1, §16.2) and reads the light of that version (§16.3). Only the
standard library; https only, no redirect, the key never in a log.
"""

from __future__ import annotations

import io
import json
import shutil
import ssl
import subprocess
import threading
import urllib.error
import urllib.request
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from jochwacht_sbom import api
from jochwacht_sbom.api import ApiError, Client

KEY = "jw_test_" + "k" * 24  # a stand-in, never a real key
BASE = "https://api.jochwacht.dev"
HREF = "/api/v1/products/prd_1/sbom-versions/5/status"


class FakeResponse(io.BytesIO):
    def __init__(self, status: int, body: dict[str, Any] | str, headers: dict[str, str]) -> None:
        raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        super().__init__(raw)
        self.status = status
        self.headers = Message()
        for k, v in headers.items():
            self.headers[k] = v

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class FakeOpener:
    """Answers in order; records each request (url, method, headers, body)."""

    def __init__(self, answers: list[tuple[int, dict[str, Any] | str, dict[str, str]]]) -> None:
        self.answers = list(answers)
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float = 0) -> FakeResponse:
        self.requests.append(req)
        status, body, headers = self.answers.pop(0)
        if status >= 400 or status == 503:
            raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
            msg = Message()
            for k, v in headers.items():
                msg[k] = v
            raise urllib.error.HTTPError(req.full_url, status, "x", msg, io.BytesIO(raw))
        return FakeResponse(status, body, headers)


def _status_body(state: str, verdict: str | None, line: str, code: str | None = None,
                 status: int = 200) -> dict[str, Any]:
    body: dict[str, Any] = {"product": "prd_1", "version": 5, "state": state,
                            "verdict": verdict, "line": line, "preliminary": False}
    if code:
        body["error"] = {"code": code, "status": status, "message": "fixed sentence"}
    return body


# --- the address and the key ---------------------------------------------------

@pytest.mark.parametrize("url", ["http://api.jochwacht.dev", "ftp://x", "api.jochwacht.dev",
                                 "https://", "https://user:pw@api.jochwacht.dev",
                                 "file:///etc/passwd"])
def test_only_https_is_accepted(url: str) -> None:
    with pytest.raises(ApiError):
        api.api_base(url)


def test_the_standard_address() -> None:
    assert api.api_base(None) == "https://api.jochwacht.dev"
    assert api.api_base("") == "https://api.jochwacht.dev"
    assert api.api_base("https://api.example.com/") == "https://api.example.com"


def test_a_missing_key_is_an_error_without_a_value() -> None:
    with pytest.raises(ApiError, match="JOCHWACHT_API_KEY"):
        api.api_key({})


def test_a_redirect_is_refused() -> None:
    handler = api.NoRedirect()
    req = urllib.request.Request(BASE + "/x", headers={"X-Api-Key": KEY})
    with pytest.raises(ApiError) as caught:
        handler.redirect_request(req, io.BytesIO(), 302, "Found", Message(),
                                 "https://evil.example/x")
    assert KEY not in str(caught.value)
    assert "redirect" in str(caught.value).lower()


def test_the_opener_has_no_plain_http_and_refuses_redirects() -> None:
    opener = api.build_opener()
    kinds = {type(h).__name__ for h in opener.handlers}
    assert "NoRedirect" in kinds and "HTTPRedirectHandler" not in kinds


# --- upload ----------------------------------------------------------------------

def test_upload_sends_the_raw_sbom_with_key_and_product() -> None:
    answer = {"status": "new", "product": "prd_1", "version": 5, "components": 3,
              "status_href": HREF}
    opener = FakeOpener([(200, answer, {})])
    got = Client(BASE, KEY, opener=opener).upload(b'{"bomFormat":"CycloneDX"}', product="fw")
    assert got == answer
    [req] = opener.requests
    assert req.full_url == BASE + "/api/v1/subscriptions/sbom-versions"
    assert req.get_method() == "POST"
    assert req.data == b'{"bomFormat":"CycloneDX"}'
    assert req.get_header("X-api-key") == KEY
    assert req.get_header("X-product") == b"fw"


def test_upload_without_product_sends_no_product_header() -> None:
    opener = FakeOpener([(200, {"status": "unchanged", "status_href": HREF}, {})])
    Client(BASE, KEY, opener=opener).upload(b"{}", product="")
    assert opener.requests[0].get_header("X-product") is None


@pytest.mark.parametrize(("status", "code"), [(401, "key_missing"), (403, "key_invalid"),
                                              (409, "product_ambiguous"), (413, "too_large"),
                                              (429, "rate_limited"), (500, "internal")])
def test_an_upload_error_names_status_and_code_never_the_key(status: int, code: str) -> None:
    body = {"error": {"code": code, "status": status, "message": "fixed sentence"}}
    opener = FakeOpener([(status, body, {})])
    with pytest.raises(ApiError) as caught:
        Client(BASE, KEY, opener=opener).upload(b"{}", product="")
    text = str(caught.value)
    assert str(status) in text and code in text and KEY not in text


def test_an_unreadable_upload_answer_is_an_error() -> None:
    opener = FakeOpener([(200, "<html>not json</html>", {})])
    with pytest.raises(ApiError):
        Client(BASE, KEY, opener=opener).upload(b"{}", product="")


def test_the_answer_is_saved_without_the_key(tmp_path: Path) -> None:
    where = api.save_last_upload(tmp_path, BASE, {"status": "new", "status_href": HREF})
    assert where == tmp_path / ".jochwacht" / "last-upload.json"
    saved = json.loads(where.read_text(encoding="utf-8"))
    assert saved["api_url"] == BASE and saved["answer"]["status_href"] == HREF
    assert KEY not in where.read_text(encoding="utf-8")
    assert api.load_last_upload(tmp_path)["answer"]["status_href"] == HREF


# --- status -----------------------------------------------------------------------

def _wait(opener: FakeOpener, *, wait: float = 600, preliminary: bool = False,
          href: str | None = HREF, product: str = "") -> tuple[api.StatusResult, list[float]]:
    slept: list[float] = []
    clock = [0.0]

    def sleep(s: float) -> None:
        slept.append(s)
        clock[0] += s

    result = api.wait_for_status(Client(BASE, KEY, opener=opener), href=href, product=product,
                                 preliminary=preliminary, wait=wait, sleep=sleep,
                                 clock=lambda: clock[0])
    return result, slept


@pytest.mark.parametrize(("state", "verdict"), [("released", "green"), ("released", "yellow"),
                                                ("waiting", None)])
def test_200_is_exit_0_with_the_line(state: str, verdict: str | None) -> None:
    opener = FakeOpener([(200, _status_body(state, verdict, "Jochwacht: line 200"), {})])
    result, slept = _wait(opener)
    assert (result.exit_code, result.line) == (0, "Jochwacht: line 200")
    assert slept == []


def test_422_red_is_exit_1_with_the_line() -> None:
    body = _status_body("released", "red", "Jochwacht: 2 findings. Please act", "verdict_red", 422)
    result, _ = _wait(FakeOpener([(422, body, {})]))
    assert (result.exit_code, result.line) == (1, "Jochwacht: 2 findings. Please act")


def test_424_unavailable_is_exit_2_and_never_repeated() -> None:
    body = _status_body("failed", None, "Jochwacht: could not be checked",
                        "verdict_unavailable", 424)
    opener = FakeOpener([(424, body, {})])
    result, slept = _wait(opener)
    assert (result.exit_code, result.line) == (2, "Jochwacht: could not be checked")
    assert len(opener.requests) == 1 and slept == []


@pytest.mark.parametrize(("status", "code", "after"), [(503, "comparison_running", "15"),
                                                       (429, "rate_limited", "60")])
def test_503_and_429_wait_for_retry_after(status: int, code: str, after: str) -> None:
    pending = _status_body("pending", None, "Jochwacht: still running", code, status)
    done = _status_body("released", "green", "Jochwacht: no open findings")
    opener = FakeOpener([(status, pending, {"Retry-After": after}), (200, done, {})])
    result, slept = _wait(opener)
    assert (result.exit_code, result.line) == (0, "Jochwacht: no open findings")
    assert slept == [float(after)]


def test_running_past_wait_is_exit_2() -> None:
    pending = _status_body("pending", None, "Jochwacht: still running", "comparison_running", 503)
    opener = FakeOpener([(503, pending, {"Retry-After": "15"})] * 10)
    result, slept = _wait(opener, wait=40)
    assert result.exit_code == 2
    assert result.line == "Jochwacht: still running"
    assert sum(slept) <= 40


def test_wait_0_asks_once() -> None:
    pending = _status_body("pending", None, "Jochwacht: still running", "comparison_running", 503)
    opener = FakeOpener([(503, pending, {"Retry-After": "15"})])
    result, slept = _wait(opener, wait=0)
    assert result.exit_code == 2 and len(opener.requests) == 1 and slept == []


def test_preliminary_asks_with_the_parameter_and_403_is_exit_2() -> None:
    body = {"error": {"code": "premium_required", "status": 403, "message": "fixed sentence"}}
    opener = FakeOpener([(403, body, {})])
    result, _ = _wait(opener, preliminary=True)
    assert opener.requests[0].full_url == BASE + HREF + "?preliminary=1"
    assert result.exit_code == 2 and "premium_required" in result.line


def test_without_href_the_current_version_route_with_product() -> None:
    opener = FakeOpener([(200, _status_body("released", "green", "ok"), {})])
    _wait(opener, href=None, product="fw")
    [req] = opener.requests
    assert req.full_url == BASE + "/api/v1/subscriptions/sbom-versions/status"
    assert req.get_header("X-product") == b"fw"


@pytest.mark.parametrize("href", ["https://evil.example/api/v1/x", "//evil.example/x",
                                  "api/v1/x", "/api/v1/../../portal/x"])
def test_a_foreign_href_is_refused(href: str) -> None:
    with pytest.raises(ApiError):
        _wait(FakeOpener([]), href=href)


def test_the_status_key_is_sent_and_never_in_the_line() -> None:
    body = {"error": {"code": "key_invalid", "status": 403, "message": f"bad {KEY}"}}
    result, _ = _wait(FakeOpener([(403, body, {})]))
    assert result.exit_code == 2 and KEY not in result.line


# --- the command line ---------------------------------------------------------------

def _project(tmp_path: Path) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    (p / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\nproject(proj)\nfind_package(OpenSSL REQUIRED)\n",
        encoding="utf-8")
    return p


@pytest.mark.parametrize("old", [["--email", "a@b.de"], ["--voucher", "X"], ["--code", "C"]])
def test_the_old_free_report_options_end_with_a_clear_message(
        tmp_path: Path, old: list[str]) -> None:
    from jochwacht_sbom.cli import main

    res = CliRunner().invoke(main, [str(_project(tmp_path)), "--send", *old],
                             env={"JOCHWACHT_API_KEY": KEY})
    assert res.exit_code == 1
    assert "no longer" in res.output and old[0] in res.output


def test_send_without_key_fails_before_scanning(tmp_path: Path) -> None:
    from jochwacht_sbom.cli import main

    proj = _project(tmp_path)
    res = CliRunner().invoke(main, [str(proj), "--send"], env={"JOCHWACHT_API_KEY": ""})
    assert res.exit_code == 1 and "JOCHWACHT_API_KEY" in res.output
    assert not (proj / "sbom.cdx.json").exists()


def test_send_uploads_the_written_sbom_and_saves_the_answer(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from jochwacht_sbom import cli

    proj = _project(tmp_path)
    sent: list[bytes] = []

    def upload(self: Client, sbom: bytes, *, product: str) -> dict[str, Any]:
        sent.append(sbom)
        return {"status": "new", "product": "prd_1", "version": 5, "components": 1,
                "status_href": HREF}

    monkeypatch.setattr(Client, "upload", upload)
    res = CliRunner().invoke(cli.main, [str(proj), "--send", "--yes"],
                             env={"JOCHWACHT_API_KEY": KEY})
    assert res.exit_code == 0, res.output
    assert sent == [(proj / "sbom.cdx.json").read_bytes()]
    saved = json.loads((proj / ".jochwacht" / "last-upload.json").read_text(encoding="utf-8"))
    assert saved["answer"]["status_href"] == HREF
    assert KEY not in res.output
    assert "jochwacht-sbom status" in res.output


def test_send_asks_first_and_no_sends_nothing(tmp_path: Path,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    from jochwacht_sbom import cli

    called: list[int] = []
    monkeypatch.setattr(Client, "upload", lambda *a, **k: called.append(1) or {})
    monkeypatch.setattr(cli, "_stdin_is_terminal", lambda: True)
    res = CliRunner().invoke(cli.main, [str(_project(tmp_path)), "--send"], input="n\n",
                             env={"JOCHWACHT_API_KEY": KEY})
    assert res.exit_code == 0 and called == [] and "Nothing was sent" in res.output


def test_status_command_reads_the_saved_href(tmp_path: Path,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    from jochwacht_sbom import cli

    api.save_last_upload(tmp_path, BASE, {"status": "new", "status_href": HREF})
    seen: list[str | None] = []

    def fake(client: Client, *, href: str | None, product: str, preliminary: bool,
             wait: float, **kw: Any) -> api.StatusResult:
        seen.append(href)
        return api.StatusResult(1, "Jochwacht: red line")

    monkeypatch.setattr(api, "wait_for_status", fake)
    res = CliRunner().invoke(cli.status_command, ["--project-dir", str(tmp_path)],
                             env={"JOCHWACHT_API_KEY": KEY})
    assert res.exit_code == 1 and seen == [HREF] and "Jochwacht: red line" in res.output


def test_status_is_reached_as_the_first_argument(monkeypatch: pytest.MonkeyPatch) -> None:
    from jochwacht_sbom import cli

    calls: list[list[str]] = []
    monkeypatch.setattr(cli, "status_command", lambda args, **kw: calls.append(args))
    monkeypatch.setattr(cli, "main", lambda *a, **kw: calls.append(["main"]))
    cli.entry(["status", "--wait", "5"])
    cli.entry(["."])
    assert calls == [["--wait", "5"], ["main"]]


# --- end to end over a real local https server ------------------------------------

@pytest.fixture
def https_server(tmp_path: Path):  # type: ignore[no-untyped-def]
    if not shutil.which("openssl"):
        pytest.skip("openssl not installed: no certificate for the local https server")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    seen: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:
            pass

        def _send(self, status: int, body: dict[str, Any], headers: dict[str, str] | None = None
                  ) -> None:
            raw = json.dumps(body).encode()
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            raw_product = self.headers.get("X-Product")
            seen.append({"path": self.path, "key": self.headers.get("X-Api-Key"), "len": len(body),
                         # http.server reads header bytes as latin-1, like the API does
                         "product": (raw_product.encode("latin-1").decode("utf-8")
                                     if raw_product is not None else None)})
            if self.headers.get("X-Product") == "redirect-me":
                self.send_response(307)
                self.send_header("Location", "https://evil.example/steal")
                self.end_headers()
                return
            self._send(200, {"status": "new", "version": 5, "status_href": HREF})

        def do_GET(self) -> None:
            seen.append({"path": self.path, "key": self.headers.get("X-Api-Key")})
            pending = sum(1 for s in seen if s["path"] == HREF) == 1
            if pending:
                self._send(503, _status_body("pending", None, "still running",
                                             "comparison_running", 503), {"Retry-After": "1"})
            else:
                self._send(422, _status_body("released", "red", "Jochwacht: red",
                                             "verdict_red", 422))

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"https://127.0.0.1:{server.server_address[1]}", cert, seen
    server.shutdown()


def test_end_to_end_over_https(https_server: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    base, cert, seen = https_server
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    client = Client(api.api_base(base), KEY)
    answer = client.upload(b'{"bomFormat":"CycloneDX"}', product="")
    assert answer["status_href"] == HREF
    result = api.wait_for_status(client, href=answer["status_href"], product="",
                                 preliminary=False, wait=30)
    assert (result.exit_code, result.line) == (1, "Jochwacht: red")
    assert [s["key"] for s in seen] == [KEY, KEY, KEY]


def test_end_to_end_a_redirect_is_not_followed(https_server: Any,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
    base, cert, seen = https_server
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    client = Client(api.api_base(base), KEY)
    with pytest.raises(ApiError) as caught:
        client.upload(b"{}", product="redirect-me")
    assert "redirect" in str(caught.value).lower() and KEY not in str(caught.value)
    assert len(seen) == 1  # nothing went to the redirect target


def test_end_to_end_an_unknown_certificate_is_refused(https_server: Any) -> None:
    base, _, _ = https_server
    with pytest.raises(ApiError):
        Client(api.api_base(base), KEY).upload(b"{}", product="")


# --- the question only at a terminal -------------------

def test_without_a_terminal_send_goes_without_a_question(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """In a pipeline --send stands in the line on purpose: no question that
    hangs or fails, but a line that says it."""
    from jochwacht_sbom import cli

    sent: list[bytes] = []
    monkeypatch.setattr(Client, "upload", lambda self, sbom, *, product: sent.append(sbom)
                        or {"status": "new", "version": 5, "status_href": HREF})
    monkeypatch.setattr(cli, "_stdin_is_terminal", lambda: False)
    res = CliRunner().invoke(cli.main, [str(_project(tmp_path)), "--send"],
                             env={"JOCHWACHT_API_KEY": KEY})
    assert res.exit_code == 0, res.output
    assert len(sent) == 1
    assert "sending without confirmation (no terminal)" in res.output
    assert "Send this SBOM" not in res.output


def test_at_a_terminal_send_asks_and_yes_skips_it(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from jochwacht_sbom import cli

    sent: list[bytes] = []
    monkeypatch.setattr(Client, "upload", lambda self, sbom, *, product: sent.append(sbom)
                        or {"status": "new", "version": 5, "status_href": HREF})
    monkeypatch.setattr(cli, "_stdin_is_terminal", lambda: True)
    proj = _project(tmp_path)
    asked = CliRunner().invoke(cli.main, [str(proj), "--send"], input="n\n",
                               env={"JOCHWACHT_API_KEY": KEY})
    assert asked.exit_code == 0 and sent == [] and "Send this SBOM" in asked.output
    assert "no terminal" not in asked.output
    yes = CliRunner().invoke(cli.main, [str(proj), "--send", "--yes"],
                             env={"JOCHWACHT_API_KEY": KEY})
    assert yes.exit_code == 0 and len(sent) == 1 and "Send this SBOM" not in yes.output


# --- hardening of the send and status path ---------------------------------------

def test_s1_a_foreign_address_in_the_saved_file_stops_before_sending(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A checked-in .jochwacht/last-upload.json of a foreign repo or fork must
    not send the key to its host: the address comes only from the
    environment or the default."""
    from jochwacht_sbom import cli

    (tmp_path / ".jochwacht").mkdir()
    (tmp_path / ".jochwacht" / "last-upload.json").write_text(json.dumps(
        {"api_url": "https://evil.example", "answer": {"status_href": HREF}}), encoding="utf-8")
    opened: list[object] = []
    monkeypatch.setattr(api, "build_opener", lambda: opened.append(1) or FakeOpener([]))
    res = CliRunner().invoke(cli.status_command, ["--project-dir", str(tmp_path)],
                             env={"JOCHWACHT_API_KEY": KEY, "JOCHWACHT_API_URL": ""})
    assert res.exit_code == 2
    assert "evil.example" in res.output and opened == []
    assert KEY not in res.output


def test_s1_the_same_address_in_file_and_environment_is_fine(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from jochwacht_sbom import cli

    api.save_last_upload(tmp_path, "https://api.example.com", {"status_href": HREF})
    seen: list[str] = []

    def fake(client: Client, *, href: str | None, **kw: Any) -> api.StatusResult:
        seen.append(client.base)
        return api.StatusResult(0, "ok")

    monkeypatch.setattr(api, "wait_for_status", fake)
    res = CliRunner().invoke(cli.status_command, ["--project-dir", str(tmp_path)],
                             env={"JOCHWACHT_API_KEY": KEY,
                                  "JOCHWACHT_API_URL": "https://api.example.com"})
    assert res.exit_code == 0 and seen == ["https://api.example.com"]


@pytest.mark.parametrize("bad", [KEY[:5] + "\n" + KEY[5:], KEY + "\r\nX-Evil: 1",
                                 KEY[:3] + "\x00" + KEY[3:], KEY + " tail", "é" + KEY])
def test_s2_a_key_with_unprintable_characters_is_refused_before_the_request(bad: str) -> None:
    with pytest.raises(ApiError) as caught:
        api.api_key({"JOCHWACHT_API_KEY": bad})
    assert bad not in str(caught.value) and KEY[5:] not in str(caught.value)


@pytest.mark.parametrize("bad", ["fw\nX-Evil: 1", "fw\r", "fw\x00"])
def test_s2_a_product_with_control_characters_is_refused(bad: str) -> None:
    opener = FakeOpener([])
    with pytest.raises(ApiError):
        Client(BASE, KEY, opener=opener).upload(b"{}", product=bad)
    assert opener.requests == []


def test_s2_status_with_a_bad_key_ends_without_traceback_and_key(tmp_path: Path) -> None:
    from jochwacht_sbom import cli

    bad = KEY[:5] + "\n" + KEY[5:]
    res = CliRunner().invoke(cli.status_command, ["--status-href", HREF],
                             env={"JOCHWACHT_API_KEY": bad})
    assert res.exit_code == 2
    assert "Traceback" not in res.output and KEY[5:] not in res.output


def test_s3_an_unexpected_error_in_status_is_exit_2_never_1(
        monkeypatch: pytest.MonkeyPatch) -> None:
    from jochwacht_sbom import cli

    def boom(*a: Any, **kw: Any) -> api.StatusResult:
        raise RuntimeError(f"boom {KEY}")

    monkeypatch.setattr(api, "wait_for_status", boom)
    res = CliRunner().invoke(cli.status_command, ["--status-href", HREF],
                             env={"JOCHWACHT_API_KEY": KEY})
    assert res.exit_code == 2
    assert "RuntimeError" in res.output
    assert "Traceback" not in res.output and KEY not in res.output


@pytest.mark.parametrize("url", ["https://api.jochwacht.dev/api", "https://api.jochwacht.dev/?x=1",
                                 "https://api.jochwacht.dev/#f", "https://api.jochwacht.dev/a/b/"])
def test_an_address_with_path_query_or_fragment_is_refused(url: str) -> None:
    with pytest.raises(ApiError):
        api.api_base(url)


def test_enter_at_the_question_sends_nothing(tmp_path: Path,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    from jochwacht_sbom import cli

    called: list[int] = []
    monkeypatch.setattr(Client, "upload", lambda *a, **k: called.append(1) or {})
    monkeypatch.setattr(cli, "_stdin_is_terminal", lambda: True)
    res = CliRunner().invoke(cli.main, [str(_project(tmp_path)), "--send"], input="\n",
                             env={"JOCHWACHT_API_KEY": KEY})
    assert res.exit_code == 0 and called == [] and "Nothing was sent" in res.output


# --- keys per company (Ivan, 13.11.2026): the product by its name ------------------

def test_the_product_name_is_trimmed_and_may_hold_umlauts() -> None:
    opener = FakeOpener([(200, {"status": "new", "status_href": HREF}, {})])
    Client(BASE, KEY, opener=opener).upload(b"{}", product="  Steuergerät Süd  ")
    assert opener.requests[0].get_header("X-product") == "Steuergerät Süd".encode()


@pytest.mark.parametrize("bad", ["fw\nX-Api-Key: x", "fw\r", "fw\x00", "fw\u202e", "fw\u2028",
                                 "fw\u200b"])
def test_a_name_with_a_line_break_or_an_invisible_character_is_refused(bad: str) -> None:
    opener = FakeOpener([])
    with pytest.raises(ApiError) as caught:
        Client(BASE, KEY, opener=opener).upload(b"{}", product=bad)
    assert "portal" in str(caught.value) and not opener.requests


def test_a_blank_product_sends_no_header() -> None:
    opener = FakeOpener([(200, {"status": "new", "status_href": HREF}, {})])
    Client(BASE, KEY, opener=opener).upload(b"{}", product="   ")
    assert opener.requests[0].get_header("X-product") is None


def _refused(status: int, error: dict[str, Any]) -> str:
    opener = FakeOpener([(status, {"error": {"status": status, **error}}, {})])
    with pytest.raises(ApiError) as caught:
        Client(BASE, KEY, opener=opener).upload(b"{}", product="fw")
    return str(caught.value)


@pytest.mark.parametrize(("status", "code", "words"), [
    (403, "api_key_invalid", "unknown or blocked"),
    (403, "api_key_scope", "limited to other products"),
    (404, "product_unknown", "Create it in the portal"),
    (403, "subscription_inactive", "subscription is not active"),
])
def test_the_new_codes_get_a_clear_sentence(status: int, code: str, words: str) -> None:
    text = _refused(status, {"code": code, "message": "server sentence"})
    assert f"HTTP {status} {code}" in text and words in text and KEY not in text


def test_product_required_lists_the_reachable_products() -> None:
    text = _refused(409, {"code": "product_required", "message": "server sentence",
                          "products": [{"public_id": "prd_1", "name": "Gateway"},
                                       {"public_id": "prd_2", "name": "Steuergerät"}]})
    assert "--product" in text and "JOCHWACHT_PRODUCT" in text
    assert "Gateway" in text and "Steuergerät" in text


def test_product_required_with_a_long_or_hostile_list_stays_short_and_clean() -> None:
    products = [{"public_id": f"prd_{i}", "name": f"P{i}\x1b[31m"} for i in range(50)]
    text = _refused(409, {"code": "product_required", "message": "", "products": products})
    assert "\x1b" not in text and "and 40 more" in text


def test_an_unknown_code_keeps_the_servers_sentence() -> None:
    assert "server sentence" in _refused(422, {"code": "sbom_unreadable",
                                               "message": "server sentence"})


def test_end_to_end_a_name_with_umlauts_arrives_as_utf8(https_server: Any,
                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    base, cert, seen = https_server
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    Client(api.api_base(base), KEY).upload(b"{}", product="Steuergerät Süd")
    assert seen[0]["product"] == "Steuergerät Süd"


# --- Contract of 27, docs/portal-api-contract.md §7.1 and §16.3 (pakete 176dcaba) -----

@pytest.mark.parametrize(("status", "code", "words"), [
    (401, "api_key_missing", "JOCHWACHT_API_KEY"),
    (403, "product_inactive", "product is not active"),
    (422, "product_name_invalid", "200 characters"),
])
def test_the_contract_codes_of_the_upload_get_a_clear_sentence(
    status: int, code: str, words: str,
) -> None:
    text = _refused(status, {"code": code, "message": "server sentence"})
    assert f"HTTP {status} {code}" in text and words in text and KEY not in text


def test_a_product_name_over_200_characters_is_refused_before_the_request() -> None:
    with pytest.raises(ApiError, match="200 characters"):
        api.check_product("x" * 201)
    assert api.check_product("x" * 200) == "x" * 200


@pytest.mark.parametrize(("status", "code", "words"), [
    (404, "not_found", "this key"),
    (409, "product_required", "--product"),
    (403, "premium_required", "Premium"),
])
def test_the_status_codes_get_a_clear_sentence_and_exit_2(
    status: int, code: str, words: str,
) -> None:
    body = {"error": {"code": code, "status": status, "message": "fixed sentence"}}
    opener = FakeOpener([(status, body, {})])
    result, _ = _wait(opener, preliminary=(code == "premium_required"))
    assert result.exit_code == 2
    assert words in result.line and code in result.line and KEY not in result.line


def test_server_text_is_cleaned_at_the_source() -> None:
    """sicherheit-2 on 6ba235a: an escape sequence in an unknown code's sentence or
    in a status line never reaches a log, not only the terminal."""
    text = _refused(422, {"code": "weird_code", "message": "a\x1b]8;;http://x\x07b"})
    assert "\x1b" not in text and "\x07" not in text
    body = {"line": "Jochwacht: \x1b[31mred\x1b[0m"}
    line = Client(BASE, KEY, opener=FakeOpener([])).line_of(body, 200)
    assert "\x1b" not in line and "red" in line
