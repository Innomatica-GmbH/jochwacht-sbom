"""CycloneDX output (1.6 by default, 1.7 on request) — the customer's own
result, written locally.

the default run
GENERATES, SHOWS and SAVES; it uploads nothing. What it saves must be a real
SBOM the customer can use with any other tool — not our upload payload. So
this writer emits CycloneDX JSON from the same components the check
collected, with the honest markings the suite uses:

- ``scope`` travels ("excluded" = test material / build tooling — listed,
  never gating),
- a conditional alternative behind an off-by-default build option is
  ``scope: optional`` with its guard as a property (marked, never
  silently counted as present),
- ``metadata.lifecycles`` states whether this was read from a configured
  build or from declarations only.

No network, no upload, no telemetry: this function only formats what is
already on the customer's disk.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from jochwacht_sbom import __version__, properties
from jochwacht_sbom.core.exceptions import JochwachtError
from jochwacht_sbom.sbom import cdx_files
from jochwacht_sbom.sbom.licenses import cyclonedx_licenses
from jochwacht_sbom.sbom.scanner import _make_purl

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


def _purl(comp: CheckComponent) -> str:
    """The purl of the local bill: the declared one, else the one the reader
    found, else built the way the suite builds it (same ``_make_purl``)."""
    if comp.purl or comp.local_purl:
        return comp.purl or comp.local_purl
    if not comp.name:
        return ""
    return _make_purl(comp.ecosystem, comp.name, comp.version)


def _bom_ref(comp: CheckComponent) -> str:
    """The suite's rule: purl, else name@version, else name."""
    purl = _purl(comp)
    if purl:
        return purl
    return f"{comp.name}@{comp.version}" if comp.version else comp.name


def _components_with_refs(
    components: list[CheckComponent], *, creator_ok: bool = True,
) -> list[dict[str, object]]:
    """Components with unique ``bom-ref`` values; a repeat gets ``#n``,
    with what a build directory proves (shared writer ``sbom/cdx_files.py``).
    """
    out: list[dict[str, object]] = []
    seen: dict[str, int] = {}
    for comp in components:
        base = _bom_ref(comp)
        n = seen.get(base, 0)
        seen[base] = n + 1
        ref = base if n == 0 else f"{base}#{n + 1}"
        entry = _with_build_evidence(_component(comp), comp, ref=ref, creator_ok=creator_ok)
        entry["bom-ref"] = ref
        out.append(entry)
    return out


def _with_build_evidence(
    entry: dict[str, object], comp: CheckComponent, *, ref: str, creator_ok: bool,
) -> dict[str, object]:
    """The local bill: licence, CPE, patches, delivered files and creator that
    the build directory proves, written by the shared writer and marked."""
    if comp.delivered_image is not None:
        return cdx_files.image_component(comp.delivered_image, name=comp.name,
                                         version=comp.version)
    props = entry.setdefault("properties", [])
    if comp.local_license and "licenses" not in entry:
        licences = cyclonedx_licenses(comp.local_license, as_text=comp.local_license_is_text)
        if licences:
            entry["licenses"] = licences
            if isinstance(props, list):
                props.append({"name": properties.name("evidence:license"),
                              "value": comp.local_license_origin})
    if comp.local_cpe and "cpe" not in entry:
        entry["cpe"] = comp.local_cpe
    if comp.patches:
        entry["pedigree"] = {"patches": list(comp.patches)}
    if comp.delivered_files:
        entry["components"] = cdx_files.file_components(
            comp.delivered_files, parent_ref=ref, package_name=comp.name,
            version=comp.version, package_license=comp.local_license or comp.license,
            to_licenses=lambda text: cyclonedx_licenses(
                text, as_text=comp.local_license_is_text and text == comp.local_license))
    cdx_files.apply_creator(entry, package_name=comp.name, url=comp.creator_url,
                            origin=comp.creator_origin, gap=comp.creator_gap,
                            field_ok=creator_ok)
    if cdx_files.is_logical(excluded=comp.scope == "excluded", is_image=False,
                            has_files=bool(comp.delivered_files),
                            not_evidenced=comp.not_evidenced):
        cdx_files.mark_logical(entry)
    if comp.not_evidenced and isinstance(props, list):
        props.append({"name": properties.name("not-evidenced"), "value": comp.not_evidenced})
    if not props:
        entry.pop("properties", None)
    return entry


def _component(comp: CheckComponent) -> dict[str, object]:
    """One CycloneDX component entry from a collected component."""
    out: dict[str, object] = {"type": "library", "name": comp.name}
    if comp.version:
        out["version"] = comp.version
    purl = _purl(comp)
    if purl:
        out["purl"] = purl
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
    # contains it, and mutually exclusive ones never both ship.
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
    if comp.declared_range:
        # Same property as the suite: what stood where a version belongs.
        props.append({"name": properties.name("declared-range"), "value": comp.declared_range})
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
    release: str = "",
) -> dict[str, object]:
    """Build the CycloneDX document for *components*: the local bill, with
    the build evidence (what ``--send`` uploads is :func:`upload_bytes`).

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
    # No "unspecified": the server counts it as no version (contract of 27);
    # a version is only written when someone states it. The customer's
    # release label first (their own word, in both bills), else in the local
    # bill the product version the one build names, as the suite writes it.
    name, version = project_name, release
    if stats.build_product:
        # The local bill keeps what the build states (sicherheit-2 on
        # 2cfd184); a label that differs stands beside it as a property.
        name = stats.build_product[0]
        version = stats.build_product[1] or release
    product: dict[str, object] = {"type": "application", "name": name}
    if version:
        product["version"] = version
    if release and release != version:
        product["properties"] = [{"name": "jochwacht:release-label", "value": release}]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(tz=UTC).isoformat(timespec="seconds"),
            # What this bill was read FROM: "build" = a configured build /
            # resolved output, "design" = declarations only.
            "lifecycles": [{"phase": lifecycle}],
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "jochwacht-sbom",
                    "version": __version__,
                    "publisher": "Innomatica GmbH",
                }],
            },
            "component": product,
        },
        "components": _components_with_refs(
            components, creator_ok=spec_version not in ("1.5",)),
    }


#: The name of the upload's product when the build states none and no
#: --product is given: never the scanned folder's name (coordination,
#: 14.11.2026).
UPLOAD_PRODUCT_FALLBACK = "product"


def _patch_text(patch: dict[str, Any]) -> bytes | None:
    """The text of a CycloneDX patch as bytes (base64 decoded), or None."""
    diff = patch.get("diff")
    text = diff.get("text") if isinstance(diff, dict) else None
    content = text.get("content") if isinstance(text, dict) else None
    if not isinstance(content, str):
        return None
    if isinstance(text, dict) and text.get("encoding") == "base64":
        try:
            return base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError):
            return content.encode("utf-8")
    return content.encode("utf-8")


def _patches_named_not_shown(entry: dict[str, Any]) -> None:
    """In the upload a patch keeps its type and ``resolves``; its text stays
    in the local bill and is named by SHA-256 and size (coordination,
    14.11.2026: the text can be the customer's own source code, and
    TR-03183 asks for none)."""
    pedigree = entry.get("pedigree")
    patches = pedigree.get("patches") if isinstance(pedigree, dict) else None
    if isinstance(pedigree, dict) and isinstance(patches, list) and patches:
        props = entry.setdefault("properties", [])
        kept: list[dict[str, Any]] = []
        for n, patch in enumerate(patches, start=1):
            if not isinstance(patch, dict):
                continue
            kept.append({k: v for k, v in patch.items() if k != "diff"})
            data = _patch_text(patch)
            value = (f"sha256:{hashlib.sha256(data).hexdigest()} size:{len(data)}"
                     if data is not None else "no text")
            if isinstance(props, list):
                props.append({"name": properties.name(f"patch:{n}"), "value": value})
        pedigree["patches"] = kept
    for child in entry.get("components", []) or []:
        if isinstance(child, dict):
            _patches_named_not_shown(child)


def upload_doc(
    components: list[CheckComponent],
    stats: CheckStats,
    *,
    product: str = "",
    spec_version: str = SPEC_VERSION,
    release: str = "",
) -> dict[str, Any]:
    """What ``--send`` uploads: the full bill (Ivan, 14.11.2026, "volle sbom
    immer!"), with every field TR-03183 and the check need: the delivered
    files with their SHA-512, manufacturer, licence, CPE, the image files.

    Two things differ from the local bill: a patch is named by type, SHA-256
    and size instead of its text, and ``metadata.component`` names the
    product the build states, else *product* (--product), else
    :data:`UPLOAD_PRODUCT_FALLBACK` — never the scanned folder. Its version
    is the release label; a differing version the build states stands
    beside it as a property.
    """
    doc: dict[str, Any] = build_cyclonedx(
        components, stats, project_name=UPLOAD_PRODUCT_FALLBACK,
        spec_version=spec_version, release=release)
    built_name, built_version = stats.build_product or ("", "")
    product_entry: dict[str, Any] = {
        "type": "application",
        "name": built_name or product or UPLOAD_PRODUCT_FALLBACK,
    }
    version = release or built_version
    if version:
        product_entry["version"] = version
    if built_version and built_version != version:
        product_entry["properties"] = [
            {"name": properties.name("build-product-version"), "value": built_version}]
    doc["metadata"]["component"] = product_entry
    for entry in doc["components"]:
        _patches_named_not_shown(entry)
    return doc


def upload_bytes(
    components: list[CheckComponent],
    stats: CheckStats,
    *,
    product: str = "",
    spec_version: str = SPEC_VERSION,
    release: str = "",
) -> bytes:
    """:func:`upload_doc` as the bytes ``--send`` writes and uploads."""
    doc = upload_doc(components, stats, product=product, spec_version=spec_version,
                     release=release)
    return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


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
    release: str = "",
) -> Path:
    """Write the SBOM to *path*.

    This tool's own earlier output at *path* is UPDATED (the stamp in
    ``metadata.tools`` identifies it) — a second run refreshes the bill
    instead of leaving ``sbom.cdx-2.json`` behind (a
    wandering file name is a graveyard and breaks CI). A file that was not
    written by this tool is never touched: that is someone's evidence, and
    the caller must choose another name (``--sbom``).

    Returns the path written.
    """
    from jochwacht_sbom.safe_write import write_file

    if path.is_symlink():  # a dangling link would create a file elsewhere (S2)
        raise JochwachtError(
            f"{path} is a symbolic link; the bill is not written through it. Remove "
            f"the link, or write the bill elsewhere with --sbom PATH.",
            exit_code=1,
        )
    kind = classify_existing(path)
    if kind == "foreign":
        raise JochwachtError(
            f"{path} exists and was not written by jochwacht-sbom — it is left "
            f"untouched. Write the bill elsewhere with --sbom PATH.",
            exit_code=1,
        )
    doc = build_cyclonedx(
        components, stats, project_name=project_name, spec_version=spec_version,
        release=release,
    )
    write_file(path, (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    return path
