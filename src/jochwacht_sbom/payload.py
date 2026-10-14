"""Payload models for the CRA Readiness Check upload (schema version 1).

The payload deliberately carries dependency *metadata only*: component names,
versions and ecosystems — plus, for components you declared yourself in
``jochwacht-deps.yaml``, the supplier/license/purl/cpe you wrote there (the
declaration was written FOR SBOM purposes; discovered components never carry
these fields). No file paths, no source code, no hostnames. This is the
data-minimisation promise shown to the prospect via ``--dry-run``; declared
metadata can be withheld with ``--no-declared-metadata``.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Final, Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION: Final = 1

#: Hard upper bound for a serialised payload (bytes) — mirrored server-side.
MAX_PAYLOAD_BYTES = 2_000_000


class CheckComponent(BaseModel):
    """One detected third-party component (metadata only).

    ``supplier``/``license``/``purl``/``cpe`` are filled ONLY for
    components declared by the customer in ``jochwacht-deps.yaml``
    (``source_type == "declared"``) — never for discovered ones.
    """

    name: str
    version: str = ""
    ecosystem: str = ""
    source_type: str = ""  # e.g. "lockfile", "declared", "regex-cmake"
    tier: int = 0
    confidence: float = 1.0
    supplier: str = ""
    license: str = ""
    purl: str = ""
    cpe: str = ""
    #: CycloneDX scope — "excluded" marks test/example material and dev
    #: tooling: listed, but never gating.
    scope: str = ""
    #: Why a resolution is not shipped (a PEP 508 marker that is false for
    #: every declared target environment) and the markers themselves.
    #:
    #: ``exclude=True`` on purpose: these never leave the machine. The
    #: promise of this tool is that only names and versions travel, and the
    #: preview before ``--send`` shows exactly that. The information is for
    #: the LOCAL bill, where it tells the customer why a component of their
    #: own lockfile is marked as not shipped. The payload carries the
    #: consequence (``scope="excluded"``), which is what stops a finding
    #: from being counted as shipped — the reason is not needed for that.
    scope_reason: str = Field(default="", exclude=True)
    markers: tuple[str, ...] = Field(default_factory=tuple, exclude=True)
    marker_note: str = Field(default="", exclude=True)
    #: A CMake find_package behind an off-by-default option is an ALTERNATIVE,
    #: not a component of the default build (Befund 38/44). When set, this
    #: carries the plain-text guard ("nur bei: PAHO_WITH_LIBRESSL"): the
    #: component travels MARKED so the report can say "your project can be
    #: built with OpenSSL or LibreSSL — configure once", but it is never
    #: counted as a present component and never gates the traffic light.
    condition: str = ""


class CheckStats(BaseModel):
    """Aggregate statistics about the scan (no paths, counts only)."""

    build_files_scanned: int = 0
    ecosystems: list[str] = Field(default_factory=list)
    #: Human-readable build-output sources (file NAMES only, never paths).
    build_output_sources: list[str] = Field(default_factory=list)
    #: Number of conditional ALTERNATIVES carried in the payload (Befund 44) —
    #: not part of the component count, surfaced so the report can prompt the
    #: customer to pick a backend / configure the build.
    conditional: int = 0
    #: CycloneDX lifecycle phase of what was read (Befund 52 — the collector
    #: must carry the same statement as the suite): "build" when a configured
    #: build (CMakeCache.txt) or resolved output (lockfile/build output) was
    #: read, "design" when only declarations were, "" when nothing was found.
    lifecycle: str = ""


class CheckPayload(BaseModel):
    """Complete upload payload for ``POST /api/v1/check/submit``."""

    schema_version: Literal[1] = SCHEMA_VERSION
    voucher: str
    contact_email: str
    collected_at: str
    tool_version: str
    project_label: str
    components: list[CheckComponent]
    stats: CheckStats
    #: Report language chosen by the customer ("de"/"en"). "" = not
    #: chosen at the CLI — the server then uses the language of the
    #: landing page the code was issued on, falling back to German.
    lang: str = ""


def anonymize_label(label: str) -> str:
    """Replace a project label with a short stable hash.

    Args:
        label: Human-readable project label (usually the directory name).

    Returns:
        First 12 hex chars of the SHA-256 of the label, prefixed for clarity.
    """
    digest = hashlib.sha256(label.encode("utf-8")).hexdigest()[:12]
    return f"anon-{digest}"


def build_payload(
    *,
    voucher: str,
    contact_email: str,
    tool_version: str,
    project_label: str,
    components: list[CheckComponent],
    stats: CheckStats,
    anonymize: bool = False,
    lang: str = "",
) -> CheckPayload:
    """Assemble the upload payload with a UTC collection timestamp.

    Args:
        voucher: Partner voucher / campaign code.
        contact_email: Where the report should be sent.
        tool_version: jochwacht-sbom version string.
        project_label: Project name; hashed when ``anonymize`` is set.
        components: Detected components (deduplicated).
        stats: Aggregate scan statistics.
        anonymize: Replace the project label with a stable hash.

    Returns:
        A validated :class:`CheckPayload`.
    """
    label = anonymize_label(project_label) if anonymize else project_label
    return CheckPayload(
        voucher=voucher,
        contact_email=contact_email,
        collected_at=datetime.now(UTC).isoformat(timespec="seconds"),
        tool_version=tool_version,
        project_label=label,
        components=sorted(components, key=lambda c: (c.name.lower(), c.ecosystem)),
        stats=stats,
        lang=lang,
    )
