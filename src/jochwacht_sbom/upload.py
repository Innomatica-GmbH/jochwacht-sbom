"""Upload client for the check submit endpoint (stdlib urllib, no extra deps)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from jochwacht_sbom import __version__
from jochwacht_sbom.core.exceptions import CheckUploadError
from jochwacht_sbom.payload import MAX_PAYLOAD_BYTES, CheckPayload

DEFAULT_SUBMIT_URL = "https://api.jochwacht.dev/api/v1/check/submit"

_TIMEOUT_SECONDS = 30


def serialize_payload(payload: CheckPayload) -> bytes:
    """Serialise a payload to UTF-8 JSON, enforcing the size limit.

    Args:
        payload: The assembled check payload.

    Returns:
        UTF-8 encoded JSON bytes.

    Raises:
        CheckUploadError: If the payload exceeds :data:`MAX_PAYLOAD_BYTES`.
    """
    raw = payload.model_dump_json(indent=2).encode("utf-8")
    if len(raw) > MAX_PAYLOAD_BYTES:
        msg = (
            f"Payload is {len(raw)} bytes, limit is {MAX_PAYLOAD_BYTES}. "
            "Split the project or contact support@innomatica.de."
        )
        raise CheckUploadError(msg)
    return raw


def upload_payload(payload: CheckPayload, *, url: str = DEFAULT_SUBMIT_URL) -> str:
    """POST the payload to the submit endpoint and return the reference id.

    Args:
        payload: The assembled check payload.
        url: Submit endpoint (override for testing / staging).

    Returns:
        Server-assigned reference (e.g. ``CHK-2026-0001``).

    Raises:
        CheckUploadError: On network errors, non-2xx responses, or an
            unparseable server response.
    """
    raw = serialize_payload(payload)
    req = urllib.request.Request(  # noqa: S310 — fixed https endpoint
        url,
        data=raw,
        headers={
            "Content-Type": "application/json",
            # Default urllib UA ("Python-urllib/…") trips Cloudflare's browser
            # integrity check (error 1010); identify honestly instead.
            "User-Agent": f"jochwacht-sbom/{__version__}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:  # noqa: S310
            body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:200]
        msg = f"Server rejected the upload (HTTP {exc.code}): {detail}"
        raise CheckUploadError(msg) from exc
    except urllib.error.URLError as exc:
        msg = f"Could not reach {url}: {exc.reason}."
        raise CheckUploadError(msg) from exc

    try:
        parsed = json.loads(body)
        reference = str(parsed["reference"])
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        msg = f"Unexpected server response: {body[:200]}"
        raise CheckUploadError(msg) from exc
    return reference
