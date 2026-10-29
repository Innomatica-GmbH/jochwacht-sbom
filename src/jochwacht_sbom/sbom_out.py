"""CycloneDX output (1.6 by default, 1.7 on request) — the customer's own
result, written locally.

Order collector-transparent-machen (Ivan, 09.09.2026): the default run
GENERATES, SHOWS and SAVES; it uploads nothing. What it saves must be a real
SBOM the customer can use with any other tool — not our upload payload. So
this writer emits CycloneDX JSON from the same components the check
collected, with the honest markings the suite uses:

- ``scope`` travels ("excluded" = test material / build tooling — listed,
  never gating),
- a conditional alternative behind an off-by-default build option is
  ``scope: optional`` with its guard as a property (Befund 44: marked, never
  silently counted as present),
- ``metadata.lifecycles`` states whether this was read from a configured
  build or from declarations only (Befund 41).

No network, no upload, no telemetry: this function only formats what is
already on the customer's disk.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from jochwacht_sbom import __version__, properties
from jochwacht_sbom.core.exceptions import JochwachtError
from jochwacht_sbom.licenses import cyclonedx_licenses

if TYPE_CHECKING:
    from pathlib import Path

    from jochwacht_sbom.payload import CheckComponent, CheckStats

#: CycloneDX spec versions this tool emits.
#:
#: 1.7 was released in October 2025 (ECMA-424, 2nd edition) and is backward
#: compatible with 1.4-1.6. The document this writer produces is identical
#: either way apart from the ``specVersion`` string — it uses only fields
#: both versions define the same way.
SPEC_VERSIONS: tuple[str, ...] = ("1.6", "1.7")

#: What we emit when the caller says nothing.
#:
#: Stays at 1.6: that is the minimum BSI TR-03183-2 v2.1.0 section 4 names,
#: and it is what the installed base of customer tooling reads. A default is
#: a promise to whoever passes no flag.
SPEC_VERSION = "1.6"


def _component(comp: CheckComponent) -> dict[str, object]:
    """One CycloneDX component entry from a collected component."""
    out: dict[str, object] = {"type": "library", "name": comp.name}
    if comp.version:
        out["version"] = comp.version
    if comp.purl:
        out["purl"] = comp.purl
    if comp.cpe:
        out["cpe"] = comp.cpe
    if comp.supplier:
        out["supplier"] = {"name": comp.supplier}
    if comp.license:
        # Not straight into ``license.id``: that field takes an SPDX
        # identifier and nothing else. "BSD License" — what a PyPI
        # classifier yields — made the whole document invalid.
        licenses = cyclonedx_licenses(comp.license)
        if licenses:
            out["licenses"] = licenses
    # A conditional alternative is OPTIONAL, never required: no default build
    # contains it, and mutually exclusive ones never both ship (Befund 44).
    if comp.condition:
        out["scope"] = "optional"
    elif comp.scope in ("required", "optional", "excluded"):
        out["scope"] = comp.scope

    props: list[dict[str, str]] = []
    if comp.condition:
        props.append({"name": properties.name("condition"), "value": comp.condition})
    if comp.ecosystem:
        props.append({"name": properties.name("ecosystem"), "value": comp.ecosystem})
    if comp.source_type:
        props.append({"name": properties.name("detected-by"), "value": comp.source_type})
    # Environment markers: local only. These fields are excluded from the
    # payload on purpose (see payload.CheckComponent) — they belong in the
    # customer's own bill, where they explain why a resolution of their own
    # lockfile is marked as not shipped.
    if comp.markers:
        props.append({
            "name": properties.name("environment-markers"),
            "value": " | ".join(comp.markers),
        })
    if comp.scope_reason:
        props.append({
            "name": properties.name("not-shipped-reason"),
            "value": comp.scope_reason,
        })
    if comp.marker_note:
        props.append({
            "name": properties.name("marker-not-evaluated"),
            "value": comp.marker_note,
        })
    if props:
        out["properties"] = props
    return out


def build_cyclonedx(
    components: list[CheckComponent],
    stats: CheckStats,
    *,
    project_name: str,
    spec_version: str = SPEC_VERSION,
) -> dict[str, object]:
    """Build the CycloneDX document for *components*.

    Args:
        components: What the check collected.
        stats: Run statistics; supplies the lifecycle phase.
        project_name: Name for ``metadata.component``.
        spec_version: One of :data:`SPEC_VERSIONS`.

    Raises:
        JochwachtError: On a version this tool does not emit.
    """
    if spec_version not in SPEC_VERSIONS:
        raise JochwachtError(
            f"Unsupported CycloneDX version: {spec_version!r}. "
            f"Use one of {', '.join(SPEC_VERSIONS)}."
        )
    lifecycle = stats.lifecycle or "design"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(tz=UTC).isoformat(timespec="seconds"),
            # What this bill was read FROM: "build" = a configured build /
            # resolved output, "design" = declarations only (Befund 41).
            "lifecycles": [{"phase": lifecycle}],
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "jochwacht-sbom",
                    "version": __version__,
                    "publisher": "Innomatica GmbH",
                }],
            },
            "component": {
                "type": "application",
                "name": project_name,
                "version": "unspecified",
            },
        },
        "components": [_component(c) for c in components],
    }


#: Jeder Name, mit dem dieses Werkzeug seine Ausgabe signiert. Seit dem
#: 29.10.2026 ist es genau einer: Ivans Entscheidung "nein, es gibt keine
#: kunden" hat die Namen der Vorgaengerfassungen entfernt.
#:
#: Die Folge ist LAUT, nicht still, und sie steht als Test fest: eine
#: Stueckliste, die eine Fassung vor 0.12.0 geschrieben hat, gilt jetzt als
#: FREMD. ``write_cyclonedx`` weigert sich dann, sie zu ueberschreiben, und
#: verweist auf ``--sbom PATH``. Das ist kein Datenverlust — aber es heisst,
#: dass wir unsere eigene aeltere Ausgabe nicht mehr als unsere erkennen.
OWN_TOOL_NAMES = frozenset({
    "jochwacht-sbom",   # since 0.12.0
})


def classify_existing(path: Path) -> str:
    """What is at *path*: ``"none"``, ``"own"`` (written by this tool — the
    ``metadata.tools`` stamp says so) or ``"foreign"`` (anything else)."""
    if not path.exists():
        return "none"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        tools = doc.get("metadata", {}).get("tools")
    except (OSError, ValueError, AttributeError):
        return "foreign"
    entries: list[object] = []
    if isinstance(tools, dict):                     # CycloneDX 1.5+ form
        entries = list(tools.get("components") or [])
    elif isinstance(tools, list):                   # legacy form
        entries = tools
    names = {str(e.get("name", "")) for e in entries if isinstance(e, dict)}
    return "own" if names & OWN_TOOL_NAMES else "foreign"


def write_cyclonedx(
    path: Path,
    components: list[CheckComponent],
    stats: CheckStats,
    *,
    project_name: str,
    spec_version: str = SPEC_VERSION,
) -> Path:
    """Write the SBOM to *path*.

    This tool's own earlier output at *path* is UPDATED (the stamp in
    ``metadata.tools`` identifies it) — a second run refreshes the bill
    instead of leaving ``sbom.cdx-2.json`` behind (Ivan, 11.09.2026: a
    wandering file name is a graveyard and breaks CI). A file that was not
    written by this tool is never touched: that is someone's evidence, and
    the caller must choose another name (``--sbom``).

    Returns the path written.
    """
    kind = classify_existing(path)
    if kind == "foreign":
        raise JochwachtError(
            f"{path} exists and was not written by jochwacht-sbom — it is left "
            f"untouched. Write the bill elsewhere with --sbom PATH.",
            exit_code=1,
        )
    doc = build_cyclonedx(
        components, stats, project_name=project_name, spec_version=spec_version,
    )
    path.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
    )
    return path
