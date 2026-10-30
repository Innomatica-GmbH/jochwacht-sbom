"""Dependency scanner — detects dependencies from lockfiles and manifests.

Supports:
- conan.lock / conanfile.txt  (C/C++ via Conan)
- requirements.txt            (Python pip)
- pyproject.toml              (Python — PEP 621/735 + Poetry; skipped when a lockfile exists)
- poetry.lock                 (Python Poetry)
- uv.lock                     (Python uv — resolved workspace closure)
- Pipfile.lock                (Python Pipenv)
- vcpkg.json                  (C/C++ vcpkg)
- CMakeLists.txt              (CMake FetchContent/find_package, best-effort)
- Cargo.lock                  (Rust Cargo)
- package-lock.json           (npm)
- yarn.lock                   (Yarn Classic)
- pnpm-lock.yaml              (pnpm)
- gradle.lockfile             (Gradle)
- pom.xml                     (Maven)
- go.sum                      (Go Modules)
- alire.lock                  (Ada/SPARK Alire)
- jochwacht-deps.yaml          (manual declaration for proprietary libs)
- *.hwh / *.xci / *.tcl       (FPGA IP cores — Vivado IP-XACT VLNV, Libero
                               core_vlnv, Quartus *_hw.tcl; matched by suffix)
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import shutil
import subprocess
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote

import yaml
from pydantic import BaseModel, Field

from jochwacht_sbom import filenames as file_names
from jochwacht_sbom.core.log import get_logger
from jochwacht_sbom.diagnosis import record_failure
from jochwacht_sbom.sbom import markers as markers_mod
from jochwacht_sbom.sbom.cmake_conditions import (
    CMakeContext,
    build_cmake_context,
    find_packages,
    version_from_cache,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from jochwacht_sbom.sbom.markers import TargetEnv

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Dependency model
# ---------------------------------------------------------------------------

_RANGE_CHARS = re.compile(r"[\^~<>=*|,]|\s")


def is_version_range(version: str) -> bool:
    """True when *version* is a declaration range, not a concrete version.

    ``^4.18.0``, ``~6.5.2``, ``>=2.0``, ``1.2 || 2.0``, ``4.x``, ``*`` —
    CycloneDX demands a concrete version; a range in that field is a
    false statement an assessor cannot check (Befund 30).
    """
    v = version.strip()
    if not v:
        return False
    return bool(_RANGE_CHARS.search(v)) or v.endswith(".x") or v.lower() in ("x", "latest")


class Dependency(BaseModel):
    """A single software dependency detected by scanning.

    Base fields cover CycloneDX / SPDX identity. The trailing block of fields
    carry BSI TR-03183-2 v2.1.0 specific metadata and stay ``None`` when no
    scanner / enricher has populated them yet — this keeps every existing
    scanner backward compatible.
    """

    name: str
    version: str
    ecosystem: str  # conan, pypi, cmake, vcpkg, manual
    #: True for a NESTED npm copy (node_modules/a/node_modules/b): it
    #: is installed and belongs in the SBOM, but it must never be
    #: compared against the project's own declaration — that invented
    #: the "globals 14.0.0 erfüllt ^15.12.0 nicht"-conflict (Befund 28).
    nested: bool = False
    #: The DECLARED range when no resolved version exists ("^4.18.0",
    #: "~6.5.2", ">=2.0"). A range is a wish, not a version — it never
    #: goes into the CycloneDX version field (Befund 30); the generator
    #: emits it as the property ``jochwacht:declared-range`` instead.
    declared_range: str = ""
    license: str | None = None
    supplier: str | None = None
    purl: str | None = None
    cpe: str | None = None
    description: str | None = None
    #: Go only: True when the versions could not be resolved to the LINKED
    #: set (no toolchain / no buildable package / error) and the scan fell
    #: back to go.sum, which lists ALL versions including superseded ones.
    #: The collector carries this into the payload so the server records the
    #: note (CRA, Ivan 30.10.2026).
    versions_unresolved: bool = False
    # Provenance class of the version: "" = resolved/pinned (lockfile or
    # exact pin), "manifest" = a constraint-derived minimum from a manifest
    # (pyproject `>=`, requirements `>=`, CMake find_package). Manifest
    # versions lose against a resolved version of the same package
    # (see prefer_locked) — they are floors, not facts.
    source_kind: str = ""
    # CycloneDX component.scope ("required" | "optional" | "excluded"),
    # "" = unknown. npm lockfile v2/v3 marks pure build tooling with
    # dev/devOptional → "excluded" (never ships in the artefact); this is
    # SBOM honesty, NOT a query filter — dev components are still checked
    # for vulnerabilities (order osv-chunking A4).
    scope: str = ""
    #: Why ``scope`` was set, when the lockfile alone does not show it —
    #: today: a PEP 508 marker that is false for every declared target
    #: environment. Travels into the bill as a property.
    scope_reason: str = ""
    #: The PEP 508 markers of this resolution, as the lockfile wrote them.
    markers: tuple[str, ...] = Field(default_factory=tuple)
    #: Why a marker could NOT be decided, when the resolution is therefore
    #: counted as shipped. Kept apart from ``scope_reason``: a component
    #: that ships must not carry a "not-shipped-reason".
    marker_note: str = ""
    # True only for entries the customer wrote into jochwacht-deps.yaml.
    # A declaration is authoritative (its supplier/license/purl/cpe were
    # stated on purpose, they beat anything a database could guess) and,
    # for the check collector, it is the ONLY class of component whose
    # metadata may travel in the payload (order report-vollstaendigkeit).
    declared: bool = False
    #: Version of the DISTRIBUTION package the build links against
    #: (``3.0.13-0ubuntu3.15``) — the patch level that decides which CVEs
    #: are actually fixed (Reihe 19, Increment 2). Upstream stays in
    #: ``version``; both are shown, neither replaces the other.
    distro_version: str = ""
    #: Where the system resolver got its answer ("pkg-config (Host)" /
    #: "pkg-config (Sysroot)"), "" when nothing was resolved.
    resolved_from: str = ""
    #: Distribution SOURCE package (dpkg ${source:Package}: "openssl", not
    #: "libssl-dev") — OSV Ubuntu/Debian advisories key by it (Rest 1).
    distro_source: str = ""
    #: OSV ecosystem of the resolving system ("Ubuntu:24.04") — the distro
    #: view whose advisories decide the shipped patch level.
    distro_ecosystem: str = ""
    #: A CMake find_package guarded by an off-by-default option() is an
    #: ALTERNATIVE, not a present component (Befund 38). When set, this
    #: carries the plain-text guard ("nur bei: PAHO_WITH_LIBRESSL") and the
    #: entry must never be reported as confirmed — the customer decides
    #: which backend they build. Empty for unconditional dependencies.
    condition: str = ""

    # ------------------------------------------------------------------
    # BSI TR-03183-2 v2.1.0 metadata (all optional, populated on demand)
    # ------------------------------------------------------------------
    # Hash of the deployable component. BSI mandates SHA-512 explicitly;
    # we accept the raw hex digest here.
    hash_sha512: str | None = None
    # Hash of the source form, when distinct from the deployable (optional per TR).
    hash_source_sha512: str | None = None
    # Filename of the component artefact on disk (required per TR §5).
    filename: str | None = None
    # Component creator, either an RFC 5322 email or a URL (required per TR §5).
    creator: str | None = None
    # Classification properties (required per TR §5; default to ``None`` = unknown).
    is_executable: bool | None = None
    is_archive: bool | None = None
    is_structured: bool | None = None
    # Source code URI (optional per TR §5).
    source_uri: str | None = None
    # URI of deployable form (optional per TR §5).
    deployable_uri: str | None = None
    # URL of security.txt (RFC 9116) (optional per TR §5).
    security_txt_url: str | None = None
    # Effective licence distinct from declared licences (optional per TR §5).
    effective_license: str | None = None
    # List of component names this component DEPENDS_ON (for BSI-relationship).
    dependencies: list[str] | None = None


def _make_purl(ecosystem: str, name: str, version: str) -> str:
    """Build a Package URL string."""
    type_map = {
        "conan": "conan",
        "pypi": "pypi",
        "vcpkg": "vcpkg",
        "cmake": "generic",
        "meson": "generic",
        "autotools": "generic",
        "configure": "generic",
        "make": "generic",
        "manual": "generic",
        "cargo": "cargo",
        "npm": "npm",
        "golang": "golang",
        "maven": "maven",
        "gradle": "maven",
        "alire": "alire",
        "nuget": "nuget",
    }
    purl_type = type_map.get(ecosystem, "generic")

    if ecosystem == "pypi":
        # PURL names are lowercase for pypi
        purl_name = name.lower().replace("_", "-")
    elif ecosystem == "npm":
        # Scoped packages: @scope/name → %40scope/name
        purl_name = quote(name, safe="/")
    elif ecosystem == "golang":
        # Go module paths: URL-encode slashes
        purl_name = quote(name, safe="")
    elif ecosystem in ("maven", "gradle"):
        # Maven: group/artifact (name should already contain the slash)
        purl_name = name
    else:
        purl_name = name

    # No version, no "@": "pkg:npm/express@" is not a valid purl, and a
    # range there would be a false statement (Befund 30).
    if not version or version == "*" or is_version_range(version):
        return f"pkg:{purl_type}/{purl_name}"
    return f"pkg:{purl_type}/{purl_name}@{version}"


# ---------------------------------------------------------------------------
# Individual scanners
# ---------------------------------------------------------------------------

def scan_conan_lock(path: Path) -> list[Dependency]:
    """Parse a Conan 2.x conan.lock (JSON) file."""
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    if not isinstance(data, dict):
        # A JSON file whose top level is not an object is not this manifest:
        # measured on grpc (16.09.2026), examples/node/package.json holds a
        # STRING ("these examples have moved"). json.loads succeeds, and the
        # reader then crashed with AttributeError on data.get. Say it in the
        # same words as a parse failure, so it is visible, and carry on.
        logger.warning(
            "Failed to parse %s: top level is %s, not an object",
            path, type(data).__name__,
        )
        return deps

    # Conan 2.x lock format: {"requires": ["zlib/1.3.1#hash", ...]}
    for ref in data.get("requires", []):
        # Format: name/version#revision or name/version
        clean = ref.split("#")[0]
        parts = clean.split("/", 1)
        if len(parts) == 2:
            name, version = parts
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="conan",
                purl=_make_purl("conan", name, version),
            ))

    # Also handle build_requires
    for ref in data.get("build_requires", []):
        clean = ref.split("#")[0]
        parts = clean.split("/", 1)
        if len(parts) == 2:
            name, version = parts
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="conan",
                purl=_make_purl("conan", name, version),
            ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_conanfile_txt(path: Path) -> list[Dependency]:
    """Parse a conanfile.txt [requires] section."""
    deps: list[Dependency] = []
    in_requires = False
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            in_requires = stripped.lower() in ("[requires]", "[build_requires]")
            continue
        if in_requires and "/" in stripped and not stripped.startswith("#"):
            parts = stripped.split("/", 1)
            if len(parts) == 2:
                name = parts[0]
                version = parts[1].split("@")[0].split("#")[0].strip()
                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem="conan",
                    purl=_make_purl("conan", name, version),
                ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_requirements_txt(
    path: Path, *, target_envs: list[TargetEnv] | None = None,
) -> list[Dependency]:
    """Parse a pip requirements.txt file.

    A line may carry a PEP 508 marker after a semicolon
    (``onnx==1.19.0 ; python_version >= "3.13"``). With declared target
    environments a line no target can reach is marked ``scope="excluded"``
    with a reason instead of being listed as shipped. Without them nothing
    is evaluated and the output is unchanged.
    """
    deps: list[Dependency] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        # pip treats "#" as a comment, and it has to be cut BEFORE the
        # marker is split off: otherwise "pkg ; marker  # note" makes the
        # marker unparsable and "pkg  # ticket #12; reason" invents one.
        ohne_kommentar = _strip_requirement_comment(stripped)
        if not ohne_kommentar:
            continue
        anforderung, _, marker_text = ohne_kommentar.partition(";")
        # Match: package==version or package>=version etc.
        match = re.match(
            r"^([a-zA-Z0-9_.-]+)\s*([=~!<>]=*)\s*([a-zA-Z0-9._*-]+)", anforderung.strip()
        )
        if match:
            name, operator, version = match.group(1), match.group(2), match.group(3)
            dep = Dependency(
                name=name,
                version=version,
                ecosystem="pypi",
                purl=_make_purl("pypi", name, version),
                # ">=1.2" names a floor, not the deployed version.
                source_kind="" if operator == "==" else "manifest",
            )
            _apply_markers(dep, [marker_text.strip()] if marker_text.strip() else [],
                           target_envs, path)
            deps.append(dep)

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


# Matches a PEP 508 requirement with a version constraint:
# "click>=8.1", "uvicorn[standard]==0.23", "pydantic >= 2.0, <3" …
_PYPROJECT_REQ_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*[=~!<>]=*\s*([A-Za-z0-9._*-]+)"
)


def _poetry_spec_version(spec: object) -> str:
    """Extract a concrete version from a Poetry dependency specifier.

    Handles plain strings (``"^8.1"``, ``">=1.0,<2"``) and tables with a
    ``version`` key. Git / path / URL specifiers yield ``""``.
    """
    if isinstance(spec, dict):
        spec = spec.get("version", "")
    if not isinstance(spec, str):
        return ""
    match = re.match(r"[\^~=<>!\s]*([0-9][A-Za-z0-9._*-]*)", spec)
    return match.group(1) if match else ""


def scan_pyproject_toml(path: Path) -> list[Dependency]:
    """Parse a pyproject.toml (PEP 621, PEP 735 dependency-groups, Poetry).

    Skipped entirely when a ``poetry.lock`` or ``uv.lock`` sits next to it —
    those lockfiles carry the fully resolved closure for the same dependency
    set and win. Requirement entries without any version constraint are
    skipped (no concrete version to put into an SBOM).
    """
    deps: list[Dependency] = []
    for lockfile in ("poetry.lock", "uv.lock"):
        if path.with_name(lockfile).is_file():
            logger.info("Skipping %s — %s present", path, lockfile)
            return deps

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    def _add(name: str, version: str) -> None:
        if name and version and version != "*":
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="pypi",
                purl=_make_purl("pypi", name, version),
                # pyproject constraints are floors/ranges, not resolved
                # versions — only a lockfile knows what is deployed.
                source_kind="manifest",
            ))

    # PEP 621 [project.dependencies] / [project.optional-dependencies]
    # and PEP 735 [dependency-groups]
    project = data.get("project", {})
    req_lists: list[object] = [project.get("dependencies", [])]
    req_lists.extend(project.get("optional-dependencies", {}).values())
    req_lists.extend(data.get("dependency-groups", {}).values())
    for req_list in req_lists:
        if not isinstance(req_list, list):
            continue
        for req in req_list:
            if not isinstance(req, str):
                continue  # PEP 735 include-group tables
            match = _PYPROJECT_REQ_RE.match(req.strip())
            if match:
                _add(match.group(1), match.group(2))

    # Poetry: [tool.poetry.dependencies] / dev-dependencies / group.*.dependencies
    poetry = data.get("tool", {}).get("poetry", {})
    poetry_tables: list[object] = [
        poetry.get("dependencies", {}),
        poetry.get("dev-dependencies", {}),
    ]
    poetry_tables.extend(
        group.get("dependencies", {})
        for group in poetry.get("group", {}).values()
        if isinstance(group, dict)
    )
    for table in poetry_tables:
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if name == "python":
                continue
            _add(name, _poetry_spec_version(spec))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_poetry_lock(
    path: Path, *, target_envs: list[TargetEnv] | None = None,
) -> list[Dependency]:
    """Parse a Poetry poetry.lock (TOML) file."""
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if name and version:
            dep = Dependency(
                name=name,
                version=version,
                ecosystem="pypi",
                purl=_make_purl("pypi", name, version),
                description=pkg.get("description"),
            )
            # Poetry writes ONE marker string per package ("markers = …").
            _apply_markers(dep, [str(pkg.get("markers") or "")], target_envs, path)
            deps.append(dep)

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def _strip_requirement_comment(line: str) -> str:
    """A requirements line without its trailing ``#`` comment.

    pip starts a comment at a ``#`` that begins the line or follows
    whitespace; a ``#`` glued to text is part of the value.
    """
    if line.startswith("#"):
        return ""
    treffer = re.search(r"\s#", line)
    return line[: treffer.start()].strip() if treffer else line.strip()


def _normalise_package_name(name: str) -> str:
    """PEP 503: ``Foo_Bar`` and ``foo.bar`` are the same project as ``foo-bar``.

    ``.lower()`` alone made them three different nodes in the graph. uv
    normalises, so all 15 lockfiles on this machine are unaffected — but an
    unnormalised name produced a real false exclusion in a constructed case
    (found in review), and that is the one error class this function must
    never commit.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def _mark_unreachable_under_markers(
    deps: list[Dependency],
    marked_edges: dict[str, list[tuple[str, str]]],
    roots: set[str],
    target_envs: list[TargetEnv],
) -> None:
    """Mark packages that only a false edge condition leads to.

    uv writes a condition in two places: on the package entry
    (``resolution-markers``, handled per entry) and on a dependency EDGE
    (``dependencies = [{ name = "colorama", marker = "sys_platform ==
    'win32'" }]``). Reading only the first missed the second kind — on the
    measured lockfile (python=3.10, linux, x86_64) THREE packages reach the
    bill solely through an edge no target environment satisfies: colorama
    (win32), setuptools (>= 3.12) and opencv-python (uv's ``sys_platform ==
    '_'`` idiom for "never", written by an ``override-dependencies`` entry).
    An earlier count of five named joblib and threadpoolctl too; measured,
    their edge is ``python_full_version < '3.11'``, which is TRUE for 3.10 —
    they ship.

    The difference of TWO traversals, not one. Reachability alone would also
    catch every development dependency — mypy, ruff, playwright are
    unreachable from the production roots for an entirely different reason,
    and calling those "not shipped into your target environment" would be a
    false statement about the customer's project (measured: 11 unreachable
    without markers, 14 with — the difference of 3 is the marker effect).
    So: reachable when markers are
    ignored, NOT reachable when they are honoured. Only that difference is a
    marker exclusion. This reader has no dev-scope closure at all (a
    deliberate simplification of the twin), and the two-traversal rule is
    exactly what makes that safe: development material is unreachable in
    BOTH traversals, so it never appears in the difference.

    In doubt, shipped: an undecidable edge marker counts as satisfiable.
    """
    def erreichbar(*, beachte_marker: bool) -> set[str]:
        gesehen: set[str] = set()
        rand = list(roots)
        while rand:
            knoten = rand.pop()
            if knoten in gesehen:
                continue
            gesehen.add(knoten)
            for kind, marker in marked_edges.get(knoten, []):
                if kind in gesehen:
                    continue
                erfuellbar = (
                    not beachte_marker
                    or not marker
                    or markers_mod.evaluate([marker], target_envs).shipped
                )
                if erfuellbar:
                    rand.append(kind)
        return gesehen

    mit = erreichbar(beachte_marker=True)
    nur_marker = erreichbar(beachte_marker=False) - mit
    if not nur_marker:
        return
    ziele = "; ".join(e.label for e in target_envs)
    for dep in deps:
        schluessel = _normalise_package_name(dep.name)
        if schluessel not in nur_marker or dep.scope:
            continue
        # Only the packages a FALSE edge points at may be told so. One that
        # falls out because its parent does not ship gets the true reason
        # instead — the first version said "only reached through a condition
        # that is false" and printed a marker that was TRUE beside it
        # (found in review). In a liability document a wrong reason is worse
        # than no reason.
        bedingungen = sorted({
            m for eltern, kanten in marked_edges.items()
            for kind, m in kanten
            if kind == schluessel and m and eltern in mit
        })
        if bedingungen:
            dep.scope_reason = (
                f"only reached through a dependency condition that is false "
                f"for every target environment ({ziele})"
            )
            # Never overwrite the entry's OWN resolution-markers: they are
            # what the lockfile wrote at this entry, and replacing them with
            # an edge condition loses the trace back to the file.
            if not dep.markers:
                dep.markers = tuple(bedingungen)
        else:
            dep.scope_reason = (
                f"every package that depends on it is itself not shipped into "
                f"any target environment ({ziele})"
            )
        dep.scope = "excluded"
        # A component cannot be "counted as shipped" and excluded at once.
        dep.marker_note = ""
        logger.info("%s %s not shipped: %s", dep.name, dep.version, dep.scope_reason)


def _apply_markers(
    dep: Dependency, roh: list[str], target_envs: list[TargetEnv] | None, path: Path,
) -> None:
    """Record what the markers of one entry mean for *dep*.

    Nothing happens without declared target environments — the output then
    stays bit-identical to the release before this feature.
    """
    roh = [m for m in roh if m.strip()]
    if not roh or not target_envs:
        return
    dep.markers = tuple(roh)
    urteil = markers_mod.evaluate(roh, target_envs)
    if urteil.undecidable:
        logger.warning("%s %s (%s): %s", dep.name, dep.version, path.name, urteil.reason)
        dep.marker_note = urteil.reason
    elif not urteil.shipped:
        dep.scope = "excluded"
        dep.scope_reason = urteil.reason
        logger.info("%s %s not shipped: %s", dep.name, dep.version, urteil.reason)


def scan_uv_lock(
    path: Path, *, target_envs: list[TargetEnv] | None = None,
) -> list[Dependency]:
    """Parse a uv uv.lock (TOML) file.

    The lockfile carries the fully resolved transitive closure of a uv
    project or workspace. Workspace members themselves (``source`` is
    ``editable``/``virtual``/``directory``) are the scanned project's own
    code, not third-party dependencies, and are skipped.
    """
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    # Edges only when they are needed: the marker question. This reader
    # still has no dev-scope closure — that difference to the suite is a
    # deliberate simplification of the twin and stays.
    marked_edges: dict[str, list[tuple[str, str]]] = {}
    roots: set[str] = set()
    members = 0

    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        source = pkg.get("source", {})
        kanten: list[tuple[str, str]] = []
        if target_envs:
            for gruppe in [pkg.get("dependencies") or []] + list(
                (pkg.get("optional-dependencies") or {}).values()
            ):
                for rel in gruppe or []:
                    if isinstance(rel, dict) and rel.get("name"):
                        kanten.append((
                            _normalise_package_name(str(rel["name"])),
                            str(rel.get("marker") or ""),
                        ))
            if name:
                marked_edges.setdefault(
                    _normalise_package_name(name), []).extend(kanten)
        if isinstance(source, dict) and (
            "editable" in source or "virtual" in source or "directory" in source
        ):
            members += 1
            roots.update(k for k, _ in kanten)
            continue
        if name and version:
            dep = Dependency(
                name=name,
                version=version,
                ecosystem="pypi",
                purl=_make_purl("pypi", name, version),
            )
            # One package entry per RESOLUTION: uv writes the same package
            # several times, each with the markers that select it.
            roh = [str(m) for m in (pkg.get("resolution-markers") or []) if str(m).strip()]
            _apply_markers(dep, roh, target_envs, path)
            deps.append(dep)

    if target_envs and members and roots:
        _mark_unreachable_under_markers(deps, marked_edges, roots, target_envs)

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_pipfile_lock(path: Path) -> list[Dependency]:
    """Parse a Pipenv Pipfile.lock (JSON) file."""
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    if not isinstance(data, dict):
        # A JSON file whose top level is not an object is not this manifest:
        # measured on grpc (16.09.2026), examples/node/package.json holds a
        # STRING ("these examples have moved"). json.loads succeeds, and the
        # reader then crashed with AttributeError on data.get. Say it in the
        # same words as a parse failure, so it is visible, and carry on.
        logger.warning(
            "Failed to parse %s: top level is %s, not an object",
            path, type(data).__name__,
        )
        return deps

    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            version = info.get("version", "").lstrip("=")
            if name and version:
                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    purl=_make_purl("pypi", name, version),
                ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_vcpkg_json(path: Path) -> list[Dependency]:
    """Parse a vcpkg.json manifest."""
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    if not isinstance(data, dict):
        # A JSON file whose top level is not an object is not this manifest:
        # measured on grpc (16.09.2026), examples/node/package.json holds a
        # STRING ("these examples have moved"). json.loads succeeds, and the
        # reader then crashed with AttributeError on data.get. Say it in the
        # same words as a parse failure, so it is visible, and carry on.
        logger.warning(
            "Failed to parse %s: top level is %s, not an object",
            path, type(data).__name__,
        )
        return deps

    for entry in data.get("dependencies", []):
        if isinstance(entry, str):
            # No pinned version — "" is the honest value, never "*"
            # (order collector-embedded-buildsysteme Punkt 5).
            deps.append(Dependency(
                name=entry,
                version="",
                ecosystem="vcpkg",
                purl=f"pkg:vcpkg/{entry}",
            ))
        elif isinstance(entry, dict):
            name = entry.get("name", "")
            version = entry.get("version>=", entry.get("version", ""))
            if name:
                deps.append(Dependency(
                    name=name,
                    version=str(version),
                    ecosystem="vcpkg",
                    purl=_make_purl("vcpkg", name, str(version)),
                ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


_CMAKE_FETCH_CONTENT = re.compile(
    r"FetchContent_Declare\s*\(\s*(\w+).*?GIT_TAG\s+([v]?[\w._-]+)",
    re.DOTALL | re.IGNORECASE,
)


def scan_cmake(
    path: Path, *, cmake_ctx: CMakeContext | None = None,
) -> list[Dependency]:
    """Best-effort scan of CMakeLists.txt for FetchContent and find_package.

    ``find_package`` is classified branch-, option- and cache-aware (Befund 38):
    a call behind an off-by-default ``option()`` is an ALTERNATIVE — it carries
    its guard in :attr:`Dependency.condition` and is never reported as present.
    A ``CMakeCache.txt`` in the tree decides the build: branches not taken are
    dropped. *cmake_ctx* is the project-wide option/cache context; when omitted
    it is built from *path*'s directory (covers a standalone single-file scan).
    """
    deps: list[Dependency] = []
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    for match in _CMAKE_FETCH_CONTENT.finditer(content):
        name, version = match.group(1), match.group(2)
        deps.append(Dependency(
            name=name,
            version=version,
            ecosystem="cmake",
            purl=_make_purl("cmake", name, version),
        ))

    ctx = cmake_ctx if cmake_ctx is not None else build_cmake_context(path.parent)
    from jochwacht_sbom.sbom.classify import is_build_tool

    for hit in find_packages(content, ctx):
        if hit.state == "absent":
            continue  # the cache decides this branch is not built
        version = hit.version
        # find_package(X 1.2) declares a MINIMUM, not the linked version.
        source_kind = "manifest"
        scope = ""
        condition = ""
        # Tooling is never a decision for the customer (Befund 57): a known
        # build tool (Git) or a project Find module that only locates a
        # PROGRAM (OpenSSLbins) travels marked excluded — listed, never asked.
        if hit.name in ctx.program_modules or is_build_tool(hit.name):
            scope = "excluded"
        if hit.state == "conditional":
            # An alternative behind an off-by-default option — surfaced with
            # its guard, never confirmed; optional in the generated SBOM.
            condition = hit.condition
            scope = "optional"
        elif ctx.has_cache:
            # The build is CONFIGURED — the branch was decided by the cache, so
            # this is a build-provenance component even when the cache carries
            # no version for it (Befund 41/45: lifecycle hangs on the cache
            # FILE, not on a variable hit — libwebsockets detects TLS in its own
            # lib/tls/CMakeLists.txt, so the cache has no OPENSSL_VERSION).
            source_kind = ""
            cache_ver = version_from_cache(hit.name, ctx)
            if cache_ver:
                version = cache_ver
        deps.append(Dependency(
            name=hit.name,
            version=version,
            ecosystem="cmake",
            purl=_make_purl("cmake", hit.name, version),
            source_kind=source_kind,
            condition=condition,
            scope=scope,
        ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_west_manifest(path: Path) -> list[Dependency]:
    """Parse a Zephyr ``west.yml`` manifest (the authoritative module list).

    The west manifest is the registry of the Zephyr world: every module
    with its repository and pinned revision (order
    wissensdatenbank-abdeckung-embedded, Stufe 4 — without this parser
    a Zephyr workspace scan missed its entire dependency declaration).
    The revision is taken verbatim as the version: tags are meaningful
    versions, commit hashes are at least an exact pin — never a guess.
    """
    deps: list[Dependency] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    manifest = data.get("manifest") if isinstance(data, dict) else None
    if not isinstance(manifest, dict):
        return deps

    remotes = {
        str(r.get("name", "")): str(r.get("url-base", ""))
        for r in manifest.get("remotes", []) or []
        if isinstance(r, dict)
    }
    default_remote = str(
        (manifest.get("defaults") or {}).get("remote", "")
    ) or (next(iter(remotes), ""))

    for project in manifest.get("projects", []) or []:
        if not isinstance(project, dict):
            continue
        name = str(project.get("name", ""))
        revision = str(project.get("revision", ""))
        if not name or not revision:
            continue
        repo_path = str(project.get("repo-path", "") or name)
        base = remotes.get(str(project.get("remote", "")) or default_remote, "")
        purl = None
        if base.startswith("https://github.com/"):
            org = base[len("https://github.com/"):].strip("/")
            purl = f"pkg:github/{org}/{repo_path}@{revision}"
        deps.append(Dependency(
            name=name,
            version=revision,
            ecosystem="github",
            purl=purl or _make_purl("generic", name, revision),
        ))

    logger.info("Found %d west modules in %s", len(deps), path)
    return deps


def scan_jochwacht_deps(path: Path) -> list[Dependency]:
    """Parse a jochwacht-deps.yaml manual dependency declaration."""
    deps: list[Dependency] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    if not isinstance(data, dict):
        return deps

    for entry in data.get("dependencies", []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "")
        version = entry.get("version", "")
        if name and version:
            # Optional per-entry ecosystem (e.g. written by jochwacht_sbom.check.convert);
            # defaults to "manual" so existing declarations behave unchanged.
            ecosystem = str(entry.get("ecosystem") or "manual")
            # A declared purl/cpe wins over anything synthesized — the Zynq
            # demo declared 57 purls and 3 CPEs that this parser silently
            # dropped (order report-vollstaendigkeit P0).
            deps.append(Dependency(
                name=name,
                version=str(version),
                ecosystem=ecosystem,
                license=entry.get("license"),
                supplier=entry.get("supplier"),
                description=entry.get("description"),
                purl=str(entry.get("purl") or "") or _make_purl(ecosystem, name, str(version)),
                cpe=entry.get("cpe"),
                scope=str(entry.get("scope") or ""),
                declared=True,
            ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_cargo_lock(path: Path) -> list[Dependency]:
    """Parse a Rust Cargo.lock (TOML) file."""
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        # Skip local workspace crates (no source field)
        if name and version and "source" in pkg:
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="cargo",
                purl=_make_purl("cargo", name, version),
            ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_package_lock_json(path: Path) -> list[Dependency]:
    """Parse an npm package-lock.json (v1/v2/v3) file."""
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    if not isinstance(data, dict):
        # A JSON file whose top level is not an object is not this manifest:
        # measured on grpc (16.09.2026), examples/node/package.json holds a
        # STRING ("these examples have moved"). json.loads succeeds, and the
        # reader then crashed with AttributeError on data.get. Say it in the
        # same words as a parse failure, so it is visible, and carry on.
        logger.warning(
            "Failed to parse %s: top level is %s, not an object",
            path, type(data).__name__,
        )
        return deps

    # v2/v3 format: "packages" dict with node_modules paths
    packages = data.get("packages", {})
    if packages:
        for pkg_path, info in packages.items():
            if not pkg_path:  # Skip root entry ""
                continue
            # Skip workspace links (local packages, not external deps)
            if info.get("link"):
                continue
            version = info.get("version", "")
            if not version:
                continue
            # Extract name from path: "node_modules/@scope/name" → "@scope/name"
            parts = pkg_path.split("node_modules/")
            name = parts[-1] if parts else pkg_path
            # More than one "node_modules/" = a nested copy another
            # package pins for itself (Befund 28: position in the tree,
            # not the name, decides what a declaration compares against).
            nested = len(parts) > 2
            # npm lockfile v2/v3 provenance: dev/devOptional = build
            # tooling that never ships (CycloneDX "excluded"), optional =
            # may be absent at runtime ("optional"); else production tree.
            if info.get("dev") or info.get("devOptional"):
                scope = "excluded"
            elif info.get("optional"):
                scope = "optional"
            else:
                scope = "required"
            if name:
                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    purl=_make_purl("npm", name, version),
                    scope=scope,
                    nested=nested,
                ))
    else:
        # v1 fallback: "dependencies" dict
        for name, info in data.get("dependencies", {}).items():
            version = info.get("version", "")
            if name and version:
                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    purl=_make_purl("npm", name, version),
                ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


_YARN_ENTRY = re.compile(r'^"?(@?[^@\s"][^"]*?)@')
_YARN_VERSION = re.compile(r'^\s+version\s+"(.+)"')
#: Yarn Berry (v2+, ``__metadata: version: N``) writes ``version: 4.4.0`` —
#: a colon, no quotes. Without this line the reader saw NOTHING in a Berry
#: lockfile: measured on streamlit's frontend (1,591 entries) the collector
#: reported 0 from yarn.lock and 167 from package.json manifests, the suite
#: 1,573 (twin comparison, kettenlauf schnell #67, 15.09.2026).
_YARN_VERSION_BERRY = re.compile(r'^\s+version:\s+"?([^"\s]+)"?\s*$')
#: Berry protocols that point at the customer's OWN tree, never at a
#: third-party package: workspace members, links and portals.
_YARN_LOCAL_PROTOCOLS = ("@workspace:", "@link:", "@portal:")


def scan_yarn_lock(path: Path) -> list[Dependency]:
    """Parse a yarn.lock — Yarn Classic (v1) and Berry (v2+) text formats.

    Only names and resolved versions are read (the twin stays simpler than
    the suite: no dependency edges, no dev-scope closure).
    """
    deps: list[Dependency] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    current_name: str | None = None
    seen: set[str] = set()

    for line in lines:
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" "):
            # Entry header: classic "name@range, name@range:" (quoted or
            # bare), berry "name@npm:range": — or __metadata / a local
            # workspace entry, which name nothing third-party.
            entry_match = _YARN_ENTRY.match(line)
            if entry_match is None or any(p in line for p in _YARN_LOCAL_PROTOCOLS):
                current_name = None
            else:
                current_name = entry_match.group(1)
            continue
        # Version line under current entry (classic or berry spelling)
        version_match = _YARN_VERSION.match(line) or _YARN_VERSION_BERRY.match(line)
        if version_match and current_name:
            version = version_match.group(1)
            key = f"{current_name}@{version}"
            if key not in seen:
                seen.add(key)
                deps.append(Dependency(
                    name=current_name,
                    version=version,
                    ecosystem="npm",
                    purl=_make_purl("npm", current_name, version),
                ))
            current_name = None

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_pnpm_lock_yaml(path: Path) -> list[Dependency]:
    """Parse a pnpm pnpm-lock.yaml file (v6 and v9 formats)."""
    deps: list[Dependency] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    if not isinstance(data, dict):
        return deps

    packages = data.get("packages", {})
    for key in packages:
        # v9 format: "name@version" (e.g. "lodash@4.17.21")
        # v6 format: "/name/version" (e.g. "/lodash/4.17.21")
        if key.startswith("/"):
            # v6: /name/version or /@scope/name/version
            parts = key.lstrip("/").rsplit("/", 1)
            if len(parts) == 2:
                name, version = parts
                # Clean version suffixes like "_peer-deps"
                version = version.split("_")[0]
            else:
                continue
        elif "@" in key and not key.startswith("@"):
            # v9: name@version
            name, _, version = key.rpartition("@")
        elif key.startswith("@") and key.count("@") >= 2:
            # v9 scoped: @scope/name@version
            name, _, version = key.rpartition("@")
        else:
            continue

        if not name or not version:
            continue
        # Skip workspace/local packages (file: protocol, link: protocol)
        if version.startswith(("file:", "link:")):
            continue
        deps.append(Dependency(
            name=name,
            version=version,
            ecosystem="npm",
            purl=_make_purl("npm", name, version),
        ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_gradle_lockfile(path: Path) -> list[Dependency]:
    """Parse a Gradle gradle.lockfile (text format)."""
    deps: list[Dependency] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Format: group:artifact:version=configuration(s)
        entry = stripped.split("=")[0].strip()
        parts = entry.split(":")
        if len(parts) == 3:
            group, artifact, version = parts
            name = f"{group}/{artifact}"
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="maven",
                purl=_make_purl("maven", name, version),
            ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


_MAVEN_NS = "{http://maven.apache.org/POM/4.0.0}"


def _get_pom_own_group_id(root: ET.Element, ns: str) -> str:
    """Extract the project's own groupId from a pom.xml root element.

    Falls back to the parent groupId if the project does not declare its own.
    Returns an empty string if neither is found.
    """
    # Direct <groupId> at the project level (not inside <dependencies>)
    group_el = root.find(f"{ns}groupId")
    if group_el is not None and group_el.text:
        return group_el.text.strip()
    # Inherit from <parent><groupId>
    parent_el = root.find(f"{ns}parent")
    if parent_el is not None:
        parent_group_el = parent_el.find(f"{ns}groupId")
        if parent_group_el is not None and parent_group_el.text:
            return parent_group_el.text.strip()
    return ""


def scan_pom_xml(path: Path) -> list[Dependency]:
    """Parse a Maven pom.xml file for <dependency> elements.

    Skips:
    - Dependencies with unresolved ``${...}`` property placeholders in
      groupId, artifactId, or version.
    - Self-references: dependencies whose groupId matches the project's
      own groupId (internal submodule references).
    """
    deps: list[Dependency] = []
    try:
        tree = ET.parse(path)  # noqa: S314
    except (ET.ParseError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    root = tree.getroot()
    # Detect namespace — some pom.xml files use the Maven namespace, some don't
    ns = _MAVEN_NS if root.tag.startswith("{") else ""

    own_group_id = _get_pom_own_group_id(root, ns)

    for dep_elem in root.iter(f"{ns}dependency"):
        group_el = dep_elem.find(f"{ns}groupId")
        artifact_el = dep_elem.find(f"{ns}artifactId")
        version_el = dep_elem.find(f"{ns}version")

        group_id = group_el.text if group_el is not None and group_el.text else ""
        artifact_id = artifact_el.text if artifact_el is not None and artifact_el.text else ""
        version = version_el.text if version_el is not None and version_el.text else ""

        if not group_id or not artifact_id:
            continue
        # Skip unresolved Maven property references (${...})
        if "${" in group_id or "${" in artifact_id or "${" in version:
            continue
        # Skip self-references (project's own submodules)
        if own_group_id and group_id == own_group_id:
            continue

        name = f"{group_id}/{artifact_id}"
        deps.append(Dependency(
            name=name,
            version=version if version else "",
            ecosystem="maven",
            purl=(_make_purl("maven", name, version) if version
                  else f"pkg:maven/{name}"),
        ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_go_sum(path: Path) -> list[Dependency]:
    """Parse a Go go.sum file."""
    deps: list[Dependency] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    seen: set[tuple[str, str]] = set()
    for line in lines:
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        module = parts[0]
        version = parts[1]
        # Remove /go.mod suffix from version
        version = version.split("/go.mod")[0]
        # Remove v prefix
        version = version.lstrip("v")
        key = (module, version)
        if key not in seen:
            seen.add(key)
            deps.append(Dependency(
                name=module,
                version=version,
                ecosystem="golang",
                purl=_make_purl("golang", module, version),
            ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


_GO_EXCLUDE_SEGMENTS = frozenset({"testdata", "examples", "example"})


def _run_go(args: list[str], cwd: Path, timeout: float = 180.0) -> tuple[bool, str]:
    """Run ``go <args>`` in *cwd*, non-writing (``-mod=readonly``). (ok, stdout)."""
    if shutil.which("go") is None:
        return False, ""
    try:
        proc = subprocess.run(  # noqa: S603,S607 — fixed args, no user text
            ["go", *args], cwd=str(cwd), capture_output=True, text=True,
            timeout=timeout, env={**os.environ, "GOFLAGS": "-mod=readonly"},
        )
    except (subprocess.SubprocessError, OSError) as exc:
        logger.info("go %s unusable (%s)", args[0] if args else "", exc)
        return False, ""
    if proc.returncode != 0:
        logger.info("go %s exit %s: %s", " ".join(args[:2]),
                    proc.returncode, proc.stderr[:200])
        return False, ""
    return True, proc.stdout


def _go_packages(directory: Path) -> list[tuple[str, str]] | None:
    """All buildable packages of the module as (name, import path).

    ``go list ./...`` skips testdata and ``_``/``.`` directories itself and
    honours build tags. ``None`` = go unusable (fall back); an EMPTY list = a
    module with no buildable package (only go.mod/go.sum, no source) → the
    caller falls back to go.sum, since no linked set can be derived from
    nothing.
    """
    ok, out = _run_go(
        ["list", "-f", "{{.Name}}\t{{.ImportPath}}", "./..."], directory,
    )
    if not ok:
        return None
    pkgs: list[tuple[str, str]] = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        pkgs.append((parts[0].strip(), parts[1].strip()))
    return pkgs


def _go_main_packages(pkgs: list[tuple[str, str]]) -> list[str]:
    """The ``package main`` from *pkgs*, without testdata/examples/_ dirs."""
    mains: list[str] = []
    for name, path in pkgs:
        if name != "main" or not path:
            continue
        segs = path.split("/")
        if any(seg in _GO_EXCLUDE_SEGMENTS or (seg.startswith("_") and len(seg) > 1)
               for seg in segs):
            continue
        mains.append(path)
    return mains


def _go_deps_modules(
    directory: Path, targets: list[str],
) -> list[Dependency] | None:
    """The modules IMPORTED by *targets* (``go list -deps -json``, no tests) —
    the actually linked set, one version per module.

    - ``replace`` directives (``Module.Replace``): name/version name the BUILT
      module (a module replacement resolves to the replacement; a local path
      replace keeps the original, since that is the main module's own code).
    - A partial result (a package carrying ``Error``/``Incomplete``) is NOT
      silently treated as complete → ``None`` (fall back to go.sum).
    - ``None`` = go unusable / error / partial. The own main module (empty
      version, no replace) drops out.
    """
    ok, out = _run_go(["list", "-deps", "-json", *targets], directory)
    if not ok:
        return None
    deps: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    decoder = json.JSONDecoder()
    i, n = 0, len(out)
    while i < n:
        while i < n and out[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        try:
            obj, j = decoder.raw_decode(out, i)
        except json.JSONDecodeError:
            break
        i = j
        if not isinstance(obj, dict):
            continue
        if obj.get("Error") or obj.get("Incomplete"):
            logger.info("go list -deps: package error in %s — fall back", directory)
            return None
        module = obj.get("Module")
        if not isinstance(module, dict):
            continue  # stdlib has no module
        orig_path = module.get("Path", "")
        orig_version = module.get("Version", "") or ""
        repl = module.get("Replace")
        if isinstance(repl, dict):
            r_path = repl.get("Path", "") or ""
            r_version = repl.get("Version", "") or ""
            if r_version:  # module replacement: the built module counts
                name, version = r_path or orig_path, r_version
            else:  # local replacement (directory): the main module's own code
                name, version = orig_path, orig_version
        else:
            name, version = orig_path, orig_version
        if not name or not version:  # own main module / unresolvable
            continue
        version = version.lstrip("v")
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        deps.append(Dependency(
            name=name, version=version, ecosystem="golang",
            purl=_make_purl("golang", name, version),
        ))
    return deps


def resolve_go_linked(directory: Path) -> list[Dependency] | None:
    """The LINKED Go set for *directory*: ``go list -deps`` from the found
    ``package main`` (pure library: ``./...``), no tests, replaces resolved.
    ``None`` when there is no toolchain / go.mod / buildable package / on an
    error — then the caller falls back to go.sum with a marker.
    """
    if not (directory / "go.mod").is_file() or shutil.which("go") is None:
        return None
    pkgs = _go_packages(directory)
    if not pkgs:  # None (go unusable) or no buildable package
        return None
    mains = _go_main_packages(pkgs)
    targets = mains if mains else ["./..."]
    return _go_deps_modules(directory, targets)


def scan_go(path: Path) -> list[Dependency]:
    """Go dependencies — the LINKED set (``go list -deps``), go.sum only as a
    fallback. On the fallback every component is marked ``versions_unresolved``
    so the uploaded payload carries the note and the server records it (CRA).
    """
    resolved = resolve_go_linked(path.parent)
    if resolved is not None:
        logger.info("go list -deps: %d linked modules in %s", len(resolved), path.parent)
        return resolved
    deps = scan_go_sum(path)
    for dep in deps:
        dep.versions_unresolved = True
    logger.info("go.sum fallback: %d modules in %s (versions unresolved)",
                len(deps), path)
    return deps


def scan_alire_lock(path: Path) -> list[Dependency]:
    """Parse an Ada/SPARK Alire alire.lock (TOML) file."""
    deps: list[Dependency] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    # Primary: solution.state.<crate>.version
    solution = data.get("solution", {})
    state = solution.get("state", {})
    for crate_name, info in state.items():
        if isinstance(info, dict):
            version = info.get("version", "")
            if version:
                deps.append(Dependency(
                    name=crate_name,
                    version=version,
                    ecosystem="alire",
                    purl=_make_purl("alire", crate_name, version),
                ))

    # Fallback: depends-on list
    if not deps:
        for entry in data.get("depends-on", []):
            if isinstance(entry, dict):
                for crate_name, version_spec in entry.items():
                    version = str(version_spec).strip("=^~>< ")
                    if crate_name and version:
                        deps.append(Dependency(
                            name=crate_name,
                            version=version,
                            ecosystem="alire",
                            purl=_make_purl("alire", crate_name, version),
                        ))

    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


# ---------------------------------------------------------------------------
# NuGet / .NET (order nuget-scanner, Ivan 14.09.2026)
# ---------------------------------------------------------------------------

#: MSBuild project files that may carry ``<PackageReference>`` (SDK style).
_MSBUILD_PROJECT_SUFFIXES = (".csproj", ".fsproj", ".vbproj")
#: Central Package Management: ``<PackageVersion Include= Version=>`` lives
#: in the nearest Directory.Packages.props above the project.
_NUGET_CPM_FILE = "Directory.Packages.props"
_NUGET_CPM_MAX_UP = 8
#: NuGet version syntax — a bare version is a FLOOR (``>=``), brackets are
#: intervals, ``*`` floats, ``$(...)`` is an MSBuild property.
_NUGET_INTERVAL = re.compile(r"^\s*([\[(])\s*([^,\])\s]*)\s*(?:,\s*([^\])\s]*)\s*)?([\])])\s*$")


def _msbuild_tag(el: ET.Element) -> str:
    """Local tag name — old-style project files carry the MSBuild namespace."""
    tag = el.tag if isinstance(el.tag, str) else ""
    return tag.rsplit("}", 1)[-1]


def _nuget_content_hash(content_hash: object) -> str | None:
    """NuGet ``contentHash`` = base64 SHA-512 of the .nupkg → hex digest."""
    if not isinstance(content_hash, str) or not content_hash.strip():
        return None
    try:
        digest = base64.b64decode(content_hash.strip(), validate=True).hex()
    except (ValueError, binascii.Error):
        return None
    return digest if len(digest) == 128 else None


def scan_packages_lock_json(path: Path) -> list[Dependency]:
    """Parse a NuGet ``packages.lock.json`` (RestorePackagesWithLockFile).

    The lockfile is the resolved truth: per target framework every package
    with ``resolved`` version, ``contentHash`` (SHA-512 of the .nupkg —
    Befund 97) and its own ``dependencies`` map (the edges, rest list C2).
    ``type: Project`` entries are ProjectReferences of the same solution —
    internal, never a third-party component. The same package resolved
    identically for several frameworks is ONE component.
    """
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps
    frameworks = data.get("dependencies") if isinstance(data, dict) else None
    if not isinstance(frameworks, dict):
        logger.warning("No dependencies section in %s", path)
        return deps
    seen: dict[tuple[str, str], Dependency] = {}
    for packages in frameworks.values():
        if not isinstance(packages, dict):
            continue
        for name, info in packages.items():
            if not isinstance(info, dict) or not name:
                continue
            if str(info.get("type", "")).lower() == "project":
                continue
            resolved = str(info.get("resolved") or "").strip()
            if not resolved:
                continue
            key = (name.lower(), resolved)
            rel = info.get("dependencies")
            edges = sorted(str(k) for k in rel) if isinstance(rel, dict) and rel else []
            dep = seen.get(key)
            if dep is None:
                dep = Dependency(
                    name=name,
                    version=resolved,
                    ecosystem="nuget",
                    purl=_make_purl("nuget", name, resolved),
                )
                dep.hash_sha512 = _nuget_content_hash(info.get("contentHash"))
                if edges:
                    dep.dependencies = edges
                seen[key] = dep
                deps.append(dep)
            elif edges:
                dep.dependencies = sorted(set(dep.dependencies or []) | set(edges))
    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def nuget_version_fields(raw: str) -> tuple[str, str]:
    """(floor version, declared range) for a ``<PackageReference>`` version.

    NuGet reads a bare ``13.0.3`` as ``>= 13.0.3`` — a floor, honest as a
    manifest minimum. ``[1.2.3]`` is exact, ``[1.0, 2.0)`` has the floor
    ``1.0`` and keeps the range. A floating ``1.0.*``/``*``, an exclusive
    lower bound ``(1.0, )`` or an MSBuild property ``$(PkgVersion)`` carries
    no version we could state — the reference is UNRESOLVED (empty version,
    range kept; order nuget-scanner: never invent a version).
    """
    text = (raw or "").strip()
    if not text:
        return "", ""
    if "$(" in text or "*" in text:
        return "", text
    m = _NUGET_INTERVAL.match(text)
    if m is None:
        return ("", text) if is_version_range(text) else (text, "")
    open_br, low, high, _close = m.groups()
    low = (low or "").strip()
    high = (high or "").strip()
    if high is None or m.group(3) is None:
        # "[1.2.3]" exact pin (single element) — or "[1.2.3" garbage
        return (low, "") if open_br == "[" and low and not is_version_range(low) else ("", text)
    if open_br == "[" and low and not is_version_range(low):
        return low, text
    return "", text


def _central_package_versions(start: Path) -> dict[str, str]:
    """``PackageVersion`` entries of the nearest Directory.Packages.props."""
    current = start
    for _ in range(_NUGET_CPM_MAX_UP):
        props = current / _NUGET_CPM_FILE
        if props.is_file():
            versions: dict[str, str] = {}
            try:
                root = ET.parse(props).getroot()  # noqa: S314
            except (ET.ParseError, OSError) as exc:
                logger.warning("Failed to parse %s: %s", props, exc)
                return versions
            for el in root.iter():
                if _msbuild_tag(el) == "PackageVersion" and el.get("Include"):
                    versions[el.get("Include", "").lower()] = el.get("Version", "") or ""
            return versions
        if current.parent == current:
            break
        current = current.parent
    return {}


def scan_msbuild_project(path: Path) -> list[Dependency]:
    """Parse ``<PackageReference>`` from a .csproj/.fsproj/.vbproj or a
    Directory.Build.props — declared references, i.e. manifest floors.

    Version comes from the ``Version`` attribute, a ``<Version>`` child, a
    ``VersionOverride``, or Central Package Management
    (Directory.Packages.props). ``Update=`` items only edit references
    declared elsewhere and add nothing. A range, floating or property
    version is kept as ``declared_range`` with an empty version (Befund 30).
    Where a packages.lock.json exists, :func:`prefer_locked` drops these
    floors in favour of the resolved versions.
    """
    deps: list[Dependency] = []
    try:
        root = ET.parse(path).getroot()  # noqa: S314
    except (ET.ParseError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps
    central: dict[str, str] | None = None
    for el in root.iter():
        if _msbuild_tag(el) not in ("PackageReference", "GlobalPackageReference"):
            continue
        name = (el.get("Include") or "").strip()
        if not name:
            continue
        raw = (el.get("VersionOverride") or el.get("Version") or "").strip()
        if not raw:
            for child in el:
                if _msbuild_tag(child) == "Version" and child.text:
                    raw = child.text.strip()
                    break
        if not raw:
            if central is None:
                central = _central_package_versions(path.parent)
            raw = central.get(name.lower(), "")
        version, declared_range = nuget_version_fields(raw)
        deps.append(Dependency(
            name=name,
            version=version,
            ecosystem="nuget",
            purl=_make_purl("nuget", name, version),
            source_kind="manifest",
            declared_range=declared_range,
        ))
    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def scan_packages_config(path: Path) -> list[Dependency]:
    """Parse the classic NuGet ``packages.config`` (``<package id= version=>``).

    The old format still lives in industrial .NET Framework and
    nanoFramework projects. Versions are the installed ones (resolved);
    ``developmentDependency="true"`` marks build tooling that never ships
    (scope excluded, the npm dev rule).
    """
    deps: list[Dependency] = []
    try:
        root = ET.parse(path).getroot()  # noqa: S314
    except (ET.ParseError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps
    for el in root.iter():
        if _msbuild_tag(el) != "package":
            continue
        name = (el.get("id") or "").strip()
        version = (el.get("version") or "").strip()
        if not name or not version:
            continue
        dep = Dependency(
            name=name,
            version=version,
            ecosystem="nuget",
            purl=_make_purl("nuget", name, version),
        )
        if (el.get("developmentDependency") or "").strip().lower() == "true":
            dep.scope = "excluded"
        deps.append(dep)
    logger.info("Found %d dependencies in %s", len(deps), path)
    return deps


def _fpga_purl(vendor: str, name: str, version: str) -> str:
    """purl for an FPGA IP core — vendor as namespace keeps same-named cores
    from different suppliers distinguishable. Version omitted when unknown."""
    base = f"pkg:generic/{quote(vendor, safe='')}/{quote(name, safe='')}"
    return f"{base}@{quote(version, safe='')}" if version else base


def _vlnv_to_dep(
    vlnv: str,
    seen: set[str],
    *,
    allow_missing_version: bool = False,
    note: str = "",
) -> Dependency | None:
    """Turn a VLNV string (``vendor:library:name:version``) into a Dependency.

    VLNV is the IP-XACT / IEEE-1685 identifier every FPGA IP core carries.
    Bus *interface* definitions (library ``interface``) are specifications,
    not delivered components, and multiple instantiations of the same core
    are one component — deduplicated over ``vendor:name:version``.

    ``allow_missing_version`` covers Libero's ``*`` wildcard: the core is
    reported with an EMPTY version (the audit then flags it honestly)
    instead of being dropped or guessed.
    """
    parts = vlnv.split(":")
    if len(parts) != 4:
        return None
    vendor, library, name, version = (p.strip() for p in parts)
    if version == "*":
        version = ""
    if not name or library.lower() == "interface":
        return None
    if not version and not allow_missing_version:
        return None
    key = f"{vendor}:{name}:{version}"
    if key in seen:
        return None
    seen.add(key)
    description = (
        f"FPGA IP core ({vendor}, library {library})" if vendor else "FPGA IP core"
    )
    if note:
        description = f"{description} — {note}"
    return Dependency(
        name=name,
        version=version,
        ecosystem="fpga-ip",
        supplier=vendor or None,
        purl=(_fpga_purl(vendor, name, version) if vendor
              else _make_purl("manual", name, version or "0")),
        description=description,
    )


def scan_vivado_hwh(path: Path) -> list[Dependency]:
    """Parse a Vivado hardware handoff (.hwh) — the full IP list of a design.

    The handoff carries one ``VLNV="vendor:library:name:version"`` attribute
    per instantiated IP core, so a single file yields the complete inventory
    of a block design including third-party cores.
    """
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    seen: set[str] = set()
    for vlnv in re.findall(r'VLNV="([^"]+)"', text):
        dep = _vlnv_to_dep(vlnv, seen)
        if dep is not None:
            deps.append(dep)
    logger.info("Found %d FPGA IP cores in %s", len(deps), path)
    return deps


def scan_vivado_xci(path: Path) -> list[Dependency]:
    """Parse a single Vivado IP configuration file (.xci, IP-XACT XML).

    Consulted only when no handoff file exists — one ``.xci`` describes one
    IP core via its ``spirit:componentRef``.
    """
    deps: list[Dependency] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    seen: set[str] = set()
    for m in re.finditer(
        r'<spirit:componentRef\b[^>]*'
        r'spirit:vendor="([^"]*)"[^>]*'
        r'spirit:library="([^"]*)"[^>]*'
        r'spirit:name="([^"]*)"[^>]*'
        r'spirit:version="([^"]*)"',
        text,
    ):
        dep = _vlnv_to_dep(":".join(m.groups()), seen)
        if dep is not None:
            deps.append(dep)
    return deps


_LIBERO_NOTE = (
    "version not pinned in the project (Libero '*' wildcard) — resolved at "
    "generation time; declare the built version via jochwacht-deps.yaml"
)


def scan_fpga_tcl(path: Path) -> list[Dependency]:
    """Parse FPGA tool TCL files — Libero component scripts and Quartus
    Platform Designer ``*_hw.tcl`` definitions.

    Measured formats (real reference designs, 2026-08-27):

    - Libero (Microchip PolarFire):
      ``create_and_configure_core -core_vlnv {Actel:DirectCore:COREI2C:*}``
      — the version is a ``*`` wildcard; the core is reported with an empty
      version and an explanatory note, never with a guessed version.
    - Quartus (Intel/Altera): ``set_module_property NAME/VERSION/GROUP`` —
      one IP definition per ``*_hw.tcl`` file.
    """
    deps: list[Dependency] = []
    try:
        if path.stat().st_size > 5_000_000:
            return deps
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return deps

    seen: set[str] = set()
    for vlnv in re.findall(r"-core_vlnv\s*\{([^}]+)\}", text):
        dep = _vlnv_to_dep(
            vlnv, seen, allow_missing_version=True, note=_LIBERO_NOTE,
        )
        if dep is not None:
            deps.append(dep)

    if not deps and path.name.endswith("_hw.tcl"):
        props = dict(re.findall(
            r'^\s*set_module_property\s+(\w+)\s+"?([^"\n]+?)"?\s*$', text, re.M,
        ))
        name = props.get("NAME", "")
        version = props.get("VERSION", "")
        if name and version:
            vendor = props.get("GROUP", "")
            deps.append(Dependency(
                name=name,
                version=version,
                ecosystem="fpga-ip",
                supplier=vendor or None,
                purl=_fpga_purl(vendor, name, version) if vendor
                else _make_purl("manual", name, version),
                description=props.get(
                    "DESCRIPTION", "FPGA IP core (Quartus Platform Designer)",
                ),
            ))

    if deps:
        logger.info("Found %d FPGA IP cores in %s", len(deps), path)
    return deps


def scan_libero_cxf(path: Path) -> list[Dependency]:
    """Parse a Libero component description (.cxf) from generated project data.

    Generation resolves the ``*`` version wildcard of the project scripts —
    the .cxf carries the actually-built VLNV as XML elements (measured on
    real PolarFire and SmartFusion2 projects; namespace actel.com/sweng/afi).
    First-party SmartDesigns carry EMPTY vendor/library/version elements
    first and are skipped — they are the user's own code, not supplied IP.
    """
    deps: list[Dependency] = []
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return deps

    fields: dict[str, str] = {}
    for child in root:
        local = child.tag.rsplit("}", 1)[-1]
        if local in ("name", "vendor", "library", "version") and local not in fields:
            fields[local] = (child.text or "").strip()

    name = fields.get("name", "")
    vendor = fields.get("vendor", "")
    library = fields.get("library", "")
    version = fields.get("version", "")
    if not (name and vendor and library and version):
        return deps

    deps.append(Dependency(
        name=name,
        version=version,
        ecosystem="fpga-ip",
        supplier=vendor,
        purl=_fpga_purl(vendor, name, version),
        description=(
            f"FPGA IP core ({vendor}, library {library}) — resolved from "
            f"generated component data"
        ),
    ))
    return deps


#: Directories never descended into when sweeping for FPGA tool output.
_FPGA_EXCLUDE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", ".venv", "venv",
    "__pycache__", ".tox", ".jochwacht",
}


def _find_fpga_files(
    path: Path, *, max_depth: int = 8,
) -> tuple[list[Path], list[Path], list[Path], list[Path]]:
    """Locate FPGA tool output below *path* (bounded depth, VCS/venv pruned).

    FPGA tool output is named after the design and sits deep in the build
    tree (``src/bd/<design>/hw_handoff/``, ``script_support/components/``),
    so unlike the manifest scanners it is matched recursively by suffix.
    Returns ``(hwh, xci, tcl, cxf)`` — Vivado handoffs, Vivado IP configs,
    Libero/Quartus TCL candidates, and generated Libero component data.
    """
    hwh: list[Path] = []
    xci: list[Path] = []
    tcl: list[Path] = []
    cxf: list[Path] = []
    base_depth = len(path.resolve().parts)
    for root, dirnames, filenames in os.walk(path):
        root_path = Path(root)
        if len(root_path.resolve().parts) - base_depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [
                d for d in dirnames
                if d not in _FPGA_EXCLUDE_DIRS and not d.startswith(".")
            ]
        for filename in filenames:
            if filename.endswith(".hwh"):
                hwh.append(root_path / filename)
            elif filename.endswith(".xci"):
                xci.append(root_path / filename)
            elif filename.endswith(".tcl"):
                tcl.append(root_path / filename)
            elif filename.endswith(".cxf"):
                cxf.append(root_path / filename)
    return sorted(hwh), sorted(xci), sorted(tcl), sorted(cxf)


# ---------------------------------------------------------------------------
# Auto-detect scanner
# ---------------------------------------------------------------------------

_SCANNERS: dict[str, tuple[str, type[object] | None]] = {
    "conan.lock": ("conan_lock", None),
    "conanfile.txt": ("conanfile_txt", None),
    "requirements.txt": ("requirements_txt", None),
    "pyproject.toml": ("pyproject_toml", None),
    "poetry.lock": ("poetry_lock", None),
    "uv.lock": ("uv_lock", None),
    "Pipfile.lock": ("pipfile_lock", None),
    "vcpkg.json": ("vcpkg_json", None),
    "CMakeLists.txt": ("cmake", None),
    file_names.DEPS: ("jochwacht_deps", None),
    "west.yml": ("west_manifest", None),
    "Cargo.lock": ("cargo_lock", None),
    "package-lock.json": ("package_lock_json", None),
    "yarn.lock": ("yarn_lock", None),
    "pnpm-lock.yaml": ("pnpm_lock_yaml", None),
    "gradle.lockfile": ("gradle_lockfile", None),
    "pom.xml": ("pom_xml", None),
    "go.sum": ("go", None),
    "alire.lock": ("alire_lock", None),
    # NuGet / .NET (order nuget-scanner, nachgezogen aus der Suite 0.15.66):
    # the lockfile is the resolved truth, packages.config the classic
    # installed set, Directory.Build.props a solution-wide manifest.
    # *.csproj/*.fsproj/*.vbproj are matched by suffix in scan_directory.
    "packages.lock.json": ("packages_lock_json", None),
    "packages.config": ("packages_config", None),
    "Directory.Build.props": ("msbuild_project", None),
}

_SCANNER_FUNCS = {
    "conan_lock": scan_conan_lock,
    "conanfile_txt": scan_conanfile_txt,
    "requirements_txt": scan_requirements_txt,
    "pyproject_toml": scan_pyproject_toml,
    "poetry_lock": scan_poetry_lock,
    "uv_lock": scan_uv_lock,
    "pipfile_lock": scan_pipfile_lock,
    "vcpkg_json": scan_vcpkg_json,
    # "cmake" is handled specially in scan_directory (it needs the project
    # option/cache context) — deliberately not in this uniform-signature map.
    "jochwacht_deps": scan_jochwacht_deps,
    "west_manifest": scan_west_manifest,
    "cargo_lock": scan_cargo_lock,
    "package_lock_json": scan_package_lock_json,
    "yarn_lock": scan_yarn_lock,
    "pnpm_lock_yaml": scan_pnpm_lock_yaml,
    "gradle_lockfile": scan_gradle_lockfile,
    "pom_xml": scan_pom_xml,
    "go": scan_go,
    "packages_lock_json": scan_packages_lock_json,
    "packages_config": scan_packages_config,
    "msbuild_project": scan_msbuild_project,
    "alire_lock": scan_alire_lock,
}


def _read_with(
    reader: str,
    pattern: str,
    func: Callable[..., list[Dependency]],
    filepath: Path,
    **kwargs: object,
) -> list[Dependency]:
    """Call one reader on one file; a crash inside it is a defect of THIS tool.

    Readers handle unreadable input themselves (a warning, an empty list).
    Anything else that escapes — a ``KeyError`` on a shape we did not
    expect, an ``IndexError`` in our own logic — is recorded for the local
    diagnosis file (:mod:`jochwacht_sbom.diagnosis`) under the reader's key
    and the file PATTERN from our tables, and the scan continues with the
    next file. Never silent, never a traceback on the customer's screen,
    never the file's real name or path in the record.
    """
    try:
        return func(filepath, **kwargs)
    except Exception as exc:  # noqa: BLE001 — every reader defect, whatever its type
        record_failure(reader, pattern, exc)
        logger.debug("Reader %s crashed on %s", reader, filepath, exc_info=True)
        return []


#: Readers that evaluate PEP 508 environment markers.
_MARKER_AWARE = frozenset({"uv_lock", "poetry_lock", "requirements_txt"})


def scan_directory(
    path: Path, *, fpga_recursive: bool = True,
    cmake_ctx: CMakeContext | None = None,
    cmake_extra_cache: Path | None = None,
    target_envs: list[TargetEnv] | None = None,
) -> list[Dependency]:
    """Auto-detect and scan all supported dependency files in a directory.

    Args:
        path: Directory to scan.
        fpga_recursive: Sweep subdirectories for FPGA tool output (Vivado
            names its files after the design and buries them in the build
            tree, so they are matched by suffix, not by fixed filename).
            :func:`scan_directory_recursive` disables this — its own walk
            visits every directory anyway.
        cmake_ctx: Project-wide CMake option/cache context (Befund 41). When
            omitted it is built from *path* — the recursive scanner passes a
            single context so a ``find_package`` in a sub-directory sees the
            ``option()`` defaults declared in the root ``CMakeLists.txt``.

    Returns:
        Combined list of all discovered dependencies (may contain duplicates).
    """
    all_deps: list[Dependency] = []
    if cmake_ctx is None and (path / "CMakeLists.txt").is_file():
        cmake_ctx = build_cmake_context(path, extra_cache=cmake_extra_cache)

    for filename, (scanner_key, _) in _SCANNERS.items():
        filepath = path / filename
        if filepath.is_file():
            logger.info("Detected %s", filepath)
            if scanner_key == "cmake":
                all_deps.extend(_read_with(
                    "cmake", filename, scan_cmake, filepath, cmake_ctx=cmake_ctx,
                ))
            elif scanner_key in _MARKER_AWARE:
                all_deps.extend(_read_with(
                    scanner_key, filename, _SCANNER_FUNCS[scanner_key], filepath,
                    target_envs=target_envs,
                ))
            else:
                all_deps.extend(_read_with(
                    scanner_key, filename, _SCANNER_FUNCS[scanner_key], filepath,
                ))
    # MSBuild project files are named after the project — matched by suffix.
    for suffix in _MSBUILD_PROJECT_SUFFIXES:
        for project_file in sorted(path.glob(f"*{suffix}")):
            if project_file.is_file():
                logger.info("Detected %s", project_file)
                all_deps.extend(_read_with(
                    "msbuild_project", f"*{suffix}", scan_msbuild_project, project_file,
                ))

    # FPGA IP cores: a Vivado handoff (.hwh) already lists every core of a
    # block design — per-IP .xci files are only consulted when no handoff
    # exists, otherwise every core would be counted twice. Libero/Quartus
    # TCL files are an independent toolchain and always scanned.
    if fpga_recursive:
        hwh_files, xci_files, tcl_files, cxf_files = _find_fpga_files(path)
    else:
        hwh_files = sorted(path.glob("*.hwh"))
        xci_files = sorted(path.glob("*.xci"))
        tcl_files = sorted(path.glob("*.tcl"))
        cxf_files = sorted(path.glob("*.cxf"))
    for hwh_file in hwh_files:
        logger.info("Detected %s", hwh_file)
        all_deps.extend(_read_with("vivado_hwh", "*.hwh", scan_vivado_hwh, hwh_file))
    if not hwh_files:
        for xci_file in xci_files:
            logger.info("Detected %s", xci_file)
            all_deps.extend(_read_with("vivado_xci", "*.xci", scan_vivado_xci, xci_file))
    for tcl_file in tcl_files:
        all_deps.extend(_read_with("fpga_tcl", "*.tcl", scan_fpga_tcl, tcl_file))
    for cxf_file in cxf_files:
        all_deps.extend(_read_with("libero_cxf", "*.cxf", scan_libero_cxf, cxf_file))

    # Post-build enrichment: generated component data (.cxf) carries the
    # resolved version — it supersedes script-derived entries whose version
    # is unpinned (Libero '*' wildcard).
    versioned_fpga = {
        f"{(d.supplier or '').lower()}:{d.name.lower()}"
        for d in all_deps if d.ecosystem == "fpga-ip" and d.version
    }
    if versioned_fpga:
        all_deps = [
            d for d in all_deps
            if not (
                d.ecosystem == "fpga-ip" and not d.version
                and f"{(d.supplier or '').lower()}:{d.name.lower()}" in versioned_fpga
            )
        ]

    # Manual deps (jochwacht-deps.yaml) are authoritative — when a manual entry
    # exists for a component, drop auto-detected entries with the same name so
    # the richer metadata (supplier, license, purl) is kept.
    manual_names: set[str] = {
        dep.name for dep in all_deps if dep.ecosystem == "manual"
    }
    if manual_names:
        filtered: list[Dependency] = []
        for dep in all_deps:
            if dep.ecosystem != "manual" and dep.name in manual_names:
                logger.debug(
                    "Suppressing auto-detected %s (%s v%s) — manual entry exists",
                    dep.name, dep.ecosystem, dep.version,
                )
                continue
            filtered.append(dep)
        all_deps = filtered

    # Deduplicate by (name, version, ecosystem)
    seen: set[tuple[str, str, str]] = set()
    unique: list[Dependency] = []
    for dep in all_deps:
        key = (dep.name, dep.version, dep.ecosystem)
        if key not in seen:
            seen.add(key)
            unique.append(dep)

    logger.info("Total: %d unique dependencies in %s", len(unique), path)
    return unique


#: Directories never scanned for dependencies — build outputs and vendored
#: trees produce duplicate/phantom components (hidden dirs are skipped too).
DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset({
    "node_modules", "__pycache__", "build", "cmake-build",
    "target", "vendor", "dist", "venv",
})

#: Project-local ignore file — one glob pattern per line, ``#`` comments.
#: Patterns match directory names and paths relative to the scan root
#: (e.g. ``staging``, ``firmware/generated``, ``*.bak``).
IGNORE_FILENAME = file_names.IGNORE


def load_ignore_patterns(root: Path) -> list[str]:
    """Read ``.jochwachtignore`` at *root* (empty list when absent).

    Falls back to the pre-rename ``.jochwachtignore``; the new spelling wins
    when both exist. Reading only the new name would quietly stop honouring
    an exclusion file the customer already has — the scan would get larger
    and nothing would say why.
    """
    ignore_file = file_names.find(root, IGNORE_FILENAME)
    if ignore_file is None:
        return []
    try:
        lines = ignore_file.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Cannot read %s: %s", ignore_file, exc)
        return []
    patterns = [
        stripped.rstrip("/")
        for line in lines
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]
    if patterns:
        logger.info("Loaded %d ignore patterns from %s", len(patterns), ignore_file)
    return patterns


def _is_ignored(rel_path: str, name: str, patterns: list[str]) -> bool:
    """Match a directory (name or root-relative path) against ignore globs."""
    import fnmatch

    return any(
        fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel_path, pat)
        for pat in patterns
    )


def prefer_locked(deps: list[Dependency]) -> list[Dependency]:
    """Drop manifest-constraint entries shadowed by a resolved version.

    A pyproject ``pillow>=10.0`` next to a lockfile ``pillow 12.3.0`` must
    not become a second, phantom component with false-positive CVEs — the
    resolved version is the deployed truth, the constraint is only a floor.
    Manifest entries without any resolved counterpart are kept (a
    manifest-only project still gets its best-effort versions).
    """
    resolved_names = {
        dep.name.lower().replace("_", "-")
        for dep in deps
        if dep.source_kind != "manifest"
    }
    kept: list[Dependency] = []
    dropped = 0
    for dep in deps:
        if (
            dep.source_kind == "manifest"
            and dep.name.lower().replace("_", "-") in resolved_names
        ):
            dropped += 1
            continue
        kept.append(dep)
    if dropped:
        logger.info(
            "Dropped %d manifest-constraint entr%s shadowed by resolved versions",
            dropped, "y" if dropped == 1 else "ies",
        )
    return kept


#: Directory names whose contents are test/example material — the
#: components inside are real and stay listed, but scope "excluded"
#: keeps them out of the traffic light (order collector-
#: mehrfachversionen Befund 10; libwebsockets added test-apps/,
#: minimal-examples*/ and contrib/ — Befund 46).
_TEST_SCOPE_DIRS = frozenset({
    "tests", "test", "test-apps", "examples", "example",
    "minimal-examples", "fixtures", "samples", "benchmarks", "docs",
    "contrib",
})


def is_test_material_part(part: str) -> bool:
    """True when a path segment marks test/example/contrib material (Befund 46).

    Matches the exact names plus the common families — ``test-*`` (test-apps,
    test-server) and anything with ``example`` in it (minimal-examples-lowlevel).
    Such components are real and stay listed, but never gate the verdict and
    never cost the customer a review question.
    """
    p = part.lower()
    return p in _TEST_SCOPE_DIRS or p.startswith("test-") or "example" in p


def scan_directory_recursive(
    path: Path, *, max_depth: int = 5, cmake_extra_cache: Path | None = None,
    target_envs: list[TargetEnv] | None = None,
) -> list[Dependency]:
    """Recursively scan a directory tree for dependency files.

    Walks all subdirectories up to *max_depth* and calls :func:`scan_directory`
    for each.  Results are deduplicated by ``(name, version, ecosystem)``;
    manifest-constraint versions shadowed by a resolved version of the same
    package are dropped (:func:`prefer_locked`). Build-output directories
    (:data:`DEFAULT_EXCLUDE_DIRS`), hidden directories, and everything
    matched by a ``.jochwachtignore`` at *path* are skipped.

    This is used by the analyzer flow (``jochwacht init --scan``) to find
    lockfiles in mono-repos and nested sub-projects.

    Args:
        path: Root directory to scan.
        max_depth: Maximum directory depth to recurse into.

    Returns:
        Combined, deduplicated list of all discovered dependencies.
    """
    all_deps: list[Dependency] = []
    seen_dirs: set[Path] = set()
    ignore_patterns = load_ignore_patterns(path)
    # One CMake context for the whole tree: option() defaults live in the root
    # CMakeLists.txt, a find_package deep in src/; a configured build's
    # CMakeCache.txt (in build/, _build/, …) is the source of truth (Befund 41).
    cmake_ctx = build_cmake_context(path, extra_cache=cmake_extra_cache)

    def _walk(current: Path, depth: int) -> None:
        resolved = current.resolve()
        if resolved in seen_dirs:
            return
        seen_dirs.add(resolved)

        # A directory holding CMakeCache.txt is a build tree — its generated
        # CMakeLists/.cmake would inject phantom find_package hits. Its cache
        # is already folded into cmake_ctx; do not scan or descend into it.
        if (current / "CMakeCache.txt").is_file() and current != path:
            return

        # Scan this directory (FPGA sweep off — this walk visits every dir)
        found = scan_directory(
            current, fpga_recursive=False, cmake_ctx=cmake_ctx,
            target_envs=target_envs,
        )
        # Test/example material travels, but marked: scope "excluded"
        # keeps it out of the traffic light while hiding nothing
        # (order collector-mehrfachversionen Befund 10, way (b) — a
        # vulnerable flask 0.12.2 from tests/fixtures/ must never gate
        # the product verdict, and must never be silently dropped
        # either). Declarations keep their author's word untouched.
        try:
            rel_parts = current.relative_to(path).parts
        except ValueError:
            rel_parts = ()
        if any(is_test_material_part(part) for part in rel_parts):
            for dep in found:
                if not dep.scope and not dep.declared:
                    dep.scope = "excluded"
        all_deps.extend(found)

        if depth >= max_depth:
            return

        # Recurse into subdirectories
        try:
            entries = sorted(current.iterdir())
        except OSError:
            return
        for entry in entries:
            if not entry.is_dir():
                continue
            # Skip hidden dirs, build-output dirs, VCS dirs, and ignores
            name = entry.name
            if name.startswith(".") or name in DEFAULT_EXCLUDE_DIRS:
                continue
            try:
                rel = entry.relative_to(path).as_posix()
            except ValueError:
                rel = name
            if _is_ignored(rel, name, ignore_patterns):
                logger.info("Skipping %s (.jochwachtignore)", rel)
                continue
            _walk(entry, depth + 1)

    _walk(path, 0)

    # Manifest floors lose against resolved versions across the whole tree,
    # then deduplicate across all directories.
    all_deps = prefer_locked(all_deps)
    seen: set[tuple[str, str, str]] = set()
    unique: list[Dependency] = []
    for dep in all_deps:
        # NuGet ids are case-insensitive: Newtonsoft.Json and newtonsoft.json
        # from two project files are ONE component.
        name_key = dep.name.lower() if dep.ecosystem == "nuget" else dep.name
        key = (name_key, dep.version, dep.ecosystem)
        if key not in seen:
            seen.add(key)
            unique.append(dep)

    # Every component carries a scope (Befund 81, nachgezogen aus der Suite).
    # Until now only test material was stamped ("excluded") and everything
    # else stayed empty — so in the payload, and therefore in the CUSTOMER'S
    # report, "part of the product" and "never judged" looked identical. The
    # report could not separate product from test material, which is exactly
    # the distinction the free check is supposed to deliver.
    #
    # "required" is the CONSERVATIVE default, not a measurement: a component
    # found in the build tree and not recognised as test material is treated
    # as part of the product — the claim the report already makes about it.
    for dep in unique:
        if not dep.scope:
            dep.scope = "required"

    logger.info(
        "Recursive scan: %d unique dependencies in %s (depth=%d)",
        len(unique), path, max_depth,
    )
    return unique
