"""Send the SBOM to Jochwacht and read the light of its version (stdlib only).

In the upload step the customer chooses our collector or an
own SBOM sent with curl. This is the collector's way: the SBOM it wrote goes
to the subscription (contract §7.1/§16.2), the answer with ``status_href`` is
kept in ``.jochwacht/last-upload.json``, and ``jochwacht-sbom status`` reads
the light of that version (§16.3): 200 green, yellow or waiting for a person,
422 red, 424 not checkable, 503 still running, 429 over a budget.

The rules of the curl line hold here too (§16.4): https only, no redirect is
followed, the key comes from the environment and is never printed, logged,
saved or part of an address.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import ssl
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jochwacht_sbom import __version__
from jochwacht_sbom.core.exceptions import JochwachtError

DEFAULT_API_URL = "https://api.jochwacht.dev"
KEY_ENV = "JOCHWACHT_API_KEY"
URL_ENV = "JOCHWACHT_API_URL"
PRODUCT_ENV = "JOCHWACHT_PRODUCT"
UPLOAD_PATH = "/api/v1/subscriptions/sbom-versions"
#: The product's current version, named like the upload names it (§16.3).
CURRENT_STATUS_PATH = "/api/v1/subscriptions/sbom-versions/status"
LAST_UPLOAD = Path(".jochwacht") / "last-upload.json"

_TIMEOUT_SECONDS = 60
_RETRY_DEFAULT = {503: 15.0, 429: 60.0}
#: A key is printable ASCII without blanks. Checked before any request: a line
#: break in a header value would make the HTTP library fail with the value in
#: its message.
_KEY_FORM = re.compile(r"[\x21-\x7e]+")
#: Not allowed in a product name: control and format characters (invisible ones
#: like U+200B or U+202E among them), line and paragraph separators, surrogates.
_NAME_FORBIDDEN = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})
#: How many reachable products a "product_required" answer names at most.
_PRODUCTS_SHOWN = 10
_HREF_PREFIX = "/api/v1/"


class ApiError(JochwachtError):
    """The send or the status call failed; the message never holds the key."""


def api_base(value: str | None) -> str:
    """The address of the API: https only, no user part, no trailing slash."""
    url = (value or "").strip() or DEFAULT_API_URL
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        msg = f"{URL_ENV} must be an https address (got {parts.scheme or 'no'} scheme)."
        raise ApiError(msg)
    if parts.username or parts.password:
        msg = f"{URL_ENV} must not carry a user or password."
        raise ApiError(msg)
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        msg = f"{URL_ENV} must be the bare address of the API, without a path or query."
        raise ApiError(msg)
    return url.rstrip("/")


def api_key(environ: Mapping[str, str] | None = None) -> str:
    """The key from the environment — never from the command line."""
    key = (os.environ if environ is None else environ).get(KEY_ENV, "").strip()
    if not key:
        msg = (f"The API key of your subscription is missing: set the environment variable "
               f"{KEY_ENV} (create the key in the portal; never pass it on the command line).")
        raise ApiError(msg)
    if not _KEY_FORM.fullmatch(key):
        msg = (f"{KEY_ENV} holds characters a key never has (a line break, a blank or a "
               f"control character); copy the key from the portal again.")
        raise ApiError(msg)
    return key


def check_product(product: str) -> str:
    """The product's name as it stands in the portal, or its id ``prd_…``, without
    blanks at the edges. It goes into the X-Product header as UTF-8 bytes, so a line
    break, a control or an invisible character is refused before any request."""
    name = product.strip(" \t")     # blanks only: a trailing line break is refused
    if any(unicodedata.category(c) in _NAME_FORBIDDEN for c in name):
        msg = ("The product name holds a line break, a control or an invisible character; "
               "copy the name from the portal again.")
        raise ApiError(msg)
    return name


def _clean(text: object) -> str:
    """A server text for the terminal: control and invisible characters removed."""
    return "".join(c for c in str(text) if unicodedata.category(c) not in _NAME_FORBIDDEN)


def _upload_refusal(code: str, raw: bytes) -> str:
    """Our own sentence for the codes of the keys per company; "" for any other code."""
    if code == "api_key_invalid":
        return (f"The API key is unknown or blocked. Create a key in the portal and set "
                f"{KEY_ENV}.")
    if code == "api_key_scope":
        return ("This API key is limited to other products. Use a key for this product, "
                "or extend the key in the portal.")
    if code == "product_unknown":
        return (f"This product does not exist. Create it in the portal, or check the name "
                f"in --product or {PRODUCT_ENV}.")
    if code == "subscription_inactive":
        return "The subscription is not active. Check it in the portal."
    if code == "product_required":
        names: list[str] = []
        try:
            err = json.loads(raw.decode("utf-8", errors="replace")).get("error", {})
            products = err.get("products") if isinstance(err, dict) else None
        except (json.JSONDecodeError, AttributeError):
            products = None
        for item in products if isinstance(products, list) else []:
            if isinstance(item, dict):
                name = _clean(item.get("name") or item.get("public_id") or "").strip()
                if name:
                    names.append(name[:80])
        listed = ", ".join(names[:_PRODUCTS_SHOWN])
        if len(names) > _PRODUCTS_SHOWN:
            listed += f" and {len(names) - _PRODUCTS_SHOWN} more"
        return (f"Your key reaches several products. Name one with --product or "
                f"{PRODUCT_ENV}" + (f": {listed}." if listed else "."))
    return ""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is never followed: the key would travel to another address."""

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> urllib.request.Request | None:
        target = urllib.parse.urlsplit(newurl)
        message = (f"Jochwacht answered with a redirect (HTTP {code}) to "
                   f"{target.scheme}://{target.hostname or '?'}; it is not followed.")
        raise ApiError(message)


def build_opener() -> urllib.request.OpenerDirector:
    """An opener that verifies the certificate (honours SSL_CERT_FILE) and
    never follows a redirect."""
    context = ssl.create_default_context()
    return urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))


def _redact(text: str, key: str) -> str:
    return text.replace(key, "***") if key else text


def _error_text(raw: bytes, status: int, key: str) -> tuple[str, str]:
    """``(code, sentence)`` from the error shape of §4, the key removed."""
    try:
        body = json.loads(raw.decode("utf-8", errors="replace"))
        err = body.get("error") if isinstance(body, dict) else None
    except json.JSONDecodeError:
        err = None
    if isinstance(err, dict):
        code = str(err.get("code") or "")
        sentence = str(err.get("message") or "")
    else:
        code, sentence = "", raw.decode("utf-8", errors="replace")[:200]
    return _redact(code, key), _redact(sentence, key)


@dataclass(frozen=True)
class StatusResult:
    exit_code: int
    line: str


class Client:
    """One base address and one key; the opener can be replaced in tests."""

    def __init__(self, base: str, key: str, *, opener: Any = None) -> None:
        self.base = base
        self._key = key
        self._opener = opener if opener is not None else build_opener()

    def _request(self, path: str, *, data: bytes | None = None, product: str = "",
                 accept: str = "application/json") -> urllib.request.Request:
        headers: dict[str, Any] = {"X-Api-Key": self._key, "Accept": accept,
                                   "User-Agent": f"jochwacht-sbom/{__version__}"}
        name = check_product(product)
        if name:
            # UTF-8 bytes: http.client would encode a str as latin-1 and fail on
            # any other character; the API reads the bytes back (contract of 27).
            headers["X-Product"] = name.encode("utf-8")
        if data is not None:
            headers["Content-Type"] = "application/vnd.cyclonedx+json"
        return urllib.request.Request(  # noqa: S310 — https checked in api_base
            self.base + path, data=data, headers=headers,
            method="POST" if data is not None else "GET")

    def upload(self, sbom: bytes, *, product: str) -> dict[str, Any]:
        """POST the SBOM bytes as written (§7.1); the answer of §16.2."""
        req = self._request(UPLOAD_PATH, data=sbom, product=product)
        try:
            with self._opener.open(req, timeout=_TIMEOUT_SECONDS) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            code, sentence = _error_text(raw, exc.code, self._key)
            ours = _redact(_upload_refusal(code, raw), self._key)
            msg = f"Jochwacht refused the SBOM (HTTP {exc.code} {code}): {ours or sentence}"
            raise ApiError(msg) from None
        except (urllib.error.URLError, ssl.SSLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            msg = f"Could not reach {self.base}: {_redact(str(reason), self._key)}"
            raise ApiError(msg) from None
        except (ValueError, http.client.HTTPException) as exc:
            msg = f"The request to {self.base} failed ({type(exc).__name__})."
            raise ApiError(msg) from None
        try:
            answer = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            answer = None
        if not isinstance(answer, dict):
            msg = f"Jochwacht answered something that is no upload answer from {self.base}."
            raise ApiError(msg)
        return answer

    def status_once(self, path: str, *, product: str) -> tuple[int, dict[str, Any], float | None]:
        """One status call: ``(HTTP status, body, Retry-After seconds)``."""
        req = self._request(path, product=product)
        try:
            with self._opener.open(req, timeout=_TIMEOUT_SECONDS) as resp:
                status, raw, headers = resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as exc:
            status, raw, headers = exc.code, exc.read(), exc.headers
        except (urllib.error.URLError, ssl.SSLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            msg = f"Could not reach {self.base}: {_redact(str(reason), self._key)}"
            raise ApiError(msg) from None
        except (ValueError, http.client.HTTPException) as exc:
            msg = f"The request to {self.base} failed ({type(exc).__name__})."
            raise ApiError(msg) from None
        try:
            body = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        after: float | None = None
        value = headers.get("Retry-After") if headers is not None else None
        if value:
            try:
                after = max(0.0, float(value))
            except ValueError:
                after = None
        return status, body, after

    def line_of(self, body: dict[str, Any], status: int) -> str:
        """The ready line of the body (§16.3); without one the error code and
        sentence — the key removed in every case."""
        line = body.get("line")
        if isinstance(line, str) and line:
            return _redact(line, self._key)
        raw_err = body.get("error")
        err: dict[str, Any] = raw_err if isinstance(raw_err, dict) else {}
        code = str(err.get("code") or "")
        sentence = str(err.get("message") or "")
        return _redact(f"Jochwacht answered HTTP {status} {code}: {sentence}".strip(), self._key)


def status_path(href: str | None, *, preliminary: bool) -> str:
    """The path to ask: the saved ``status_href`` (a path of this API, never
    another host) or the current version's route."""
    if href:
        parts = urllib.parse.urlsplit(href)
        clean = urllib.parse.urljoin("/", parts.path)
        if (parts.scheme or parts.netloc or not href.startswith(_HREF_PREFIX)
                or clean != parts.path):
            msg = f"The status address {href!r} is no path of the Jochwacht API."
            raise ApiError(msg)
        path = parts.path
    else:
        path = CURRENT_STATUS_PATH
    return path + ("?preliminary=1" if preliminary else "")


def wait_for_status(
    client: Client,
    *,
    href: str | None,
    product: str,
    preliminary: bool,
    wait: float,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> StatusResult:
    """Ask until there is a light or *wait* seconds are over. 200 → 0,
    422 → 1, 424 and every other answer → 2 at once; 503 and 429 are asked
    again after Retry-After while time is left, then 2."""
    path = status_path(href, preliminary=preliminary)
    deadline = clock() + max(0.0, wait)
    while True:
        status, body, after = client.status_once(path, product=product)
        line = client.line_of(body, status)
        if status == 200:
            return StatusResult(0, line)
        raw_err = body.get("error")
        if status == 422 and isinstance(raw_err, dict) and raw_err.get("code") == "verdict_red":
            return StatusResult(1, line)
        if status in _RETRY_DEFAULT:
            delay = after if after is not None else _RETRY_DEFAULT[status]
            if clock() + delay > deadline:
                return StatusResult(2, line)
            sleep(delay)
            continue
        return StatusResult(2, line)


def save_last_upload(project_dir: Path, base: str, answer: dict[str, Any]) -> Path:
    """Keep the upload answer for a later ``jochwacht-sbom status`` — never the key."""
    where = project_dir / LAST_UPLOAD
    where.parent.mkdir(parents=True, exist_ok=True)
    where.write_text(json.dumps({"api_url": base, "answer": answer}, indent=2) + "\n",
                     encoding="utf-8")
    return where


def load_last_upload(project_dir: Path) -> dict[str, Any]:
    where = project_dir / LAST_UPLOAD
    try:
        data = json.loads(where.read_text(encoding="utf-8"))
    except FileNotFoundError:
        msg = (f"No {LAST_UPLOAD} in {project_dir}: run `jochwacht-sbom . --send` in this "
               f"directory first, or give --status-href.")
        raise ApiError(msg) from None
    except (OSError, json.JSONDecodeError) as exc:
        msg = f"{where} is not readable: {exc}"
        raise ApiError(msg) from None
    if not isinstance(data, dict):
        msg = f"{where} is not an upload answer."
        raise ApiError(msg)
    return data
