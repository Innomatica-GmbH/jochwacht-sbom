"""Dependency collection for the CRA Readiness Check.

Combines the two deterministic detection paths that already power jochwacht:

1. :func:`jochwacht.sbom.scanner.scan_directory_recursive` — lockfiles and
   manifests (16 formats, high confidence).
2. :func:`jochwacht.analyzer.pipeline.run_pipeline` — build-file analysis via
   the multi-tier pipeline, restricted to the deterministic tiers (2 = struct-
   ured parsers, 4 = regex; tier 1 CLI tools optional via ``with_tools``).

No LLM, no tree-sitter, no external tools by default — the collector must run
anywhere, instantly, with zero setup.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from jochwacht_sbom import filenames as file_names
from jochwacht_sbom.analyzer.normalize import normalize_dep_name
from jochwacht_sbom.analyzer.pipeline import run_pipeline
from jochwacht_sbom.analyzer.scanner import _apply_cmake_conditions, collect_build_files
from jochwacht_sbom.core.exceptions import CheckCollectionError
from jochwacht_sbom.diagnosis import record_failure
from jochwacht_sbom.payload import CheckComponent, CheckStats
from jochwacht_sbom.sbom.classify import (
    _C_KEYWORDS,
    _looks_like_library,
    clean_dependency,
    is_invalid_name,
    strip_control_chars,
)
from jochwacht_sbom.sbom.scanner import is_test_material_part, scan_directory_recursive

if TYPE_CHECKING:  # pragma: no cover - typing only
    from jochwacht_sbom.sbom.markers import TargetEnv

#: Deterministic pipeline tiers that need no tooling on the host.
_DEFAULT_TIERS = frozenset({2, 4})
#: Tier 1 adds native CLI tools (cargo, go, npm, …) when present on the host.
_TOOL_TIER = 1

#: Confidence assigned to lockfile-derived components (structured parse).
_LOCKFILE_CONFIDENCE = 0.95
#: Confidence for manifest-constraint floors (">=" — version unconfirmed).
_MANIFEST_CONFIDENCE = 0.7
_LOCKFILE_TIER = 2

#: Build-script name-token ecosystems — the only place the skip list
#: may drop a name (npm/pypi homonyms like bcrypt/threads/numpy are
#: real packages).
_NAME_ONLY_ECOSYSTEMS = frozenset({
    "cmake", "meson", "make", "autotools", "configure", "generic",
})


def _project_name(path: Path) -> str:
    """Project identity for the self-reference filter (Befund 75): the name in
    jochwacht.yaml (or the older jochwacht.yaml) if the tree carries one, else
    the directory name — the same precedence the suite uses, so both tools
    agree on what "self" is."""
    cfg = file_names.find(path, file_names.CONFIG)
    if cfg is not None:
        try:
            import yaml
            data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
            name = (data.get("project") or {}).get("name")
            if isinstance(name, str) and name.strip():
                return name.strip()
        except (OSError, ValueError, yaml.YAMLError):
            pass
    return path.resolve().name


def _is_parser_noise(name: str, version: str, ecosystem: str) -> bool:
    """DB-free parser-noise check (Befund 13, collector flavour).

    The collector has no knowledge DB — the SERVER does the authoritative
    suspect classification. So the collector only drops what is noise
    *regardless* of a DB: a C keyword (``int``), an empty name, or a single
    character (``n`` harvested from ``-ln``). An ambiguous capitalized word
    (``OpenSSL``, ``Packet``) is kept and sent — dropping it here would lose a
    real library, because unlike the suite there is no DB to vouch for it.
    """
    if version and version != "*":
        return False  # a resolved version is trust
    if ecosystem not in _NAME_ONLY_ECOSYSTEMS:
        return False
    clean = strip_control_chars(name)
    if not clean:
        return True
    if clean.lower() in _C_KEYWORDS:
        return True
    if _looks_like_library(clean):
        return False
    return len(clean) <= 1


def _identity(name: str) -> str:
    """Identity of a component for de-duplication: its OWN name, folded to
    lower case — never the fuzzy matching form.

    ``normalize_dep_name`` exists to MATCH names across spellings (a CMake
    ``GStreamer_video`` against a pkg-config ``gstreamer``), and it strips
    component suffixes like ``_core``, ``_client``, ``_base``. Used as a
    de-duplication key it silently merges packages that are not the same
    package: measured 15.09.2026 over six real trees, 9 components vanished
    from the bill without a trace — ``serde_core`` behind ``serde``,
    ``playwright-core`` behind ``playwright``, ``@sentry/node-core`` behind
    ``@sentry/node``, ``@docusaurus/utils-common`` behind
    ``@docusaurus/utils``. Each has its own version and its own CVE history.
    """
    return name.strip().lower()


def collect_components(
    path: Path,
    *,
    with_tools: bool = False,
    max_depth: int = 5,
    include_declared_metadata: bool = True,
    target_envs: list[TargetEnv] | None = None,
) -> tuple[list[CheckComponent], CheckStats]:
    """Collect deduplicated dependency metadata from a project directory.

    Args:
        path: Project root to scan.
        with_tools: Also run tier 1 (native CLI tools) of the pipeline.
        max_depth: Maximum directory depth for both detection paths.

    Returns:
        Tuple of (components sorted by insertion source, scan statistics).

    Raises:
        CheckCollectionError: If ``path`` is not a readable directory.
    """
    if not path.is_dir():
        msg = f"Not a directory: {path}"
        raise CheckCollectionError(msg)

    # Path 1: lockfiles / manifests — these win on conflict (they carry
    # pinned versions), so they are inserted first. Manifest-constraint
    # floors already lost against resolved versions inside
    # scan_directory_recursive (prefer_locked); the survivors are labelled
    # honestly — a ">=" floor is not a lockfile fact.
    from jochwacht_sbom.sbom.skiplist import is_skipped

    # Identity of a component is (name, version, ecosystem) — never the
    # name alone: npm regularly nests two versions of one package, and
    # the older nested one is often the vulnerable one (order
    # collector-mehrfachversionen).
    # The project's own name (its directory) is not a third-party component;
    # neither is an unexpanded CMake variable (Befund 47).
    # Self-reference identity from the same source as the suite (Befund 75):
    # the project name in jochwacht.yaml when present, else the directory name.
    # (The suite filters self-refs by its --project/config name; a measurement
    # in a differently-named copy dir must not diverge.)
    proj = normalize_dep_name(_project_name(path))

    # One CMake context for both paths (Befund 75): tool + program-module
    # classification must match scan_cmake / the suite reconciler exactly.
    from jochwacht_sbom.sbom.classify import is_build_tool
    from jochwacht_sbom.sbom.cmake_conditions import build_cmake_context

    cmake_ctx = build_cmake_context(path)

    def _is_tooling(name: str) -> bool:
        return is_build_tool(name) or name in cmake_ctx.program_modules

    def _not_component(name: str) -> bool:
        return is_invalid_name(name) or (
            bool(proj) and normalize_dep_name(name) == proj
        )

    merged: dict[tuple[str, str], CheckComponent] = {}
    # Conditional ALTERNATIVES travel MARKED, not dropped (Befund 44): the
    # report can then say "your project can be built with OpenSSL or LibreSSL
    # — configure once". They are never counted as components, never gating.
    conditional_comps: list[CheckComponent] = []
    conditional_seen: set[str] = set()

    def _add_conditional(name: str, version: str, ecosystem: str,
                         condition: str, tier: int) -> None:
        ckey = normalize_dep_name(name)
        if ckey in conditional_seen:
            return
        conditional_seen.add(ckey)
        conditional_comps.append(CheckComponent(
            name=name, version=version, ecosystem=ecosystem,
            source_type="conditional", tier=tier, confidence=0.0,
            # CycloneDX "optional" heisst genau das: kann im Produkt sein,
            # muss aber nicht (Befund 81 Nachtrag). Der leere Scope war die
            # Form der SUITE, wo der Kunde die Frage im Assistenten
            # beantwortet — im Gratis-Check gibt es diesen Dialog nicht, also
            # muss das Werkzeug selbst etwas Ehrliches sagen. "required" waere
            # eine Behauptung ohne Beleg, "excluded" ebenso.
            condition=condition, scope="optional",
        ))

    go_versions_unresolved = False
    for dep in scan_directory_recursive(
        path, max_depth=max_depth, target_envs=target_envs,
    ):
        # Control-char hygiene FIRST (Befund 15 — a scanner once read colored
        # tool output), so the dedup key and the uploaded payload are clean.
        clean_dependency(dep)
        # Go went to go.sum (all versions) instead of the linked set — carry
        # the note into the payload so the server records it (CRA).
        if getattr(dep, "versions_unresolved", False):
            go_versions_unresolved = True
        if not dep.declared and _not_component(dep.name):
            continue  # ${ARGN} or the project depending on itself (Befund 47)
        # A find_package behind an off-by-default option is an ALTERNATIVE —
        # it travels marked with its guard, never as a present component.
        if dep.condition:
            _add_conditional(dep.name, dep.version, dep.ecosystem,
                             dep.condition, _LOCKFILE_TIER)
            continue
        key = (_identity(dep.name), dep.version)
        if key in merged:
            continue
        # A tool / program-only Find module the scanner already marked
        # excluded (Git, OpenSSLbins) is LISTED as excluded — exactly like
        # the suite — never dropped by the skip list, so both tools show the
        # customer the same excluded set (Befund 75 issue 4).
        if not dep.declared and dep.scope == "excluded" and _is_tooling(dep.name):
            merged[key] = CheckComponent(
                name=dep.name,
                version=dep.version,
                ecosystem=dep.ecosystem,
                source_type=dep.source_kind or "build-file",
                tier=_LOCKFILE_TIER,
                confidence=_MANIFEST_CONFIDENCE,
                scope="excluded",
                # Two different reasons reach scope="excluded" now, and a
                # name can carry both: `cmake==3.27 ; sys_platform ==
                # "win32"` is a build-tool name AND marker-excluded.
                # Dropping the reason here made the run print "test/example
                # directories or dev tooling" for it — the exact false
                # statement cli.py refuses to make, and the suite kept the
                # reason, so the two halves disagreed (found in review).
                scope_reason=dep.scope_reason,
                markers=dep.markers,
                marker_note=dep.marker_note,
            )
            continue
        # Curated skip list (build tools, system libs) applies only to
        # name tokens from build scripts — a resolved lockfile entry is
        # a real package regardless of its name (npm bcrypt/threads/util
        # are homonyms, not tooling); declarations are never skipped.
        if (
            not dep.declared
            and dep.ecosystem in _NAME_ONLY_ECOSYSTEMS
            and is_skipped(dep.name)
        ):
            continue
        # Parser noise the collector can judge without a DB — int/char/n
        # (Befund 13); ambiguous names go to the server, which has the DB.
        if not dep.declared and _is_parser_noise(dep.name, dep.version, dep.ecosystem):
            continue
        # Entries from jochwacht-deps.yaml are the customer's own SBOM
        # declaration: they keep the metadata written there (opt-out via
        # include_declared_metadata) and are labelled "declared" so the
        # server can tell declaration from discovery apart.
        if dep.declared:
            merged[key] = CheckComponent(
                name=dep.name,
                version=dep.version,
                ecosystem=dep.ecosystem,
                source_type="declared",
                tier=_LOCKFILE_TIER,
                confidence=1.0,
                supplier=(dep.supplier or "") if include_declared_metadata else "",
                license=(dep.license or "") if include_declared_metadata else "",
                purl=(dep.purl or "") if include_declared_metadata else "",
                cpe=(dep.cpe or "") if include_declared_metadata else "",
                scope=dep.scope,
                scope_reason=dep.scope_reason,
                markers=dep.markers,
                marker_note=dep.marker_note,
            )
            continue
        is_floor = dep.source_kind == "manifest"
        merged[key] = CheckComponent(
            name=dep.name,
            version=dep.version,
            ecosystem=dep.ecosystem,
            source_type="manifest" if is_floor else "lockfile",
            tier=_LOCKFILE_TIER,
            confidence=_MANIFEST_CONFIDENCE if is_floor else _LOCKFILE_CONFIDENCE,
            scope=dep.scope,
                scope_reason=dep.scope_reason,
                markers=dep.markers,
                marker_note=dep.marker_note,
        )

    # Path 2: build-file pipeline (deterministic tiers only).
    tiers = set(_DEFAULT_TIERS | {_TOOL_TIER}) if with_tools else set(_DEFAULT_TIERS)
    build_files = collect_build_files(path, max_depth=max_depth)
    pipeline_deps, _artifacts, _internal = run_pipeline(
        path, build_files, enabled_tiers=tiers
    )
    # Reconcile CMake find_package hits with the branch/option/cache truth
    # (Befund 38/41): drop names the configured build did not take, mark an
    # off-by-default alternative's guard into context. run_pipeline does not
    # do this itself, so the collector must (the suite does it in
    # analyze_with_pipeline).
    pipeline_deps = _apply_cmake_conditions(pipeline_deps, path)
    # Cross-path match stays fuzzy (a build file writes
    # `GStreamer_video` for what the lockfile calls `gstreamer`);
    # only the identity key above is exact.
    seen_names = {normalize_dep_name(name) for name, _version in merged}
    for pdep in pipeline_deps:
        pdep.name = strip_control_chars(pdep.name)
        if _not_component(pdep.name):
            continue  # ${ARGN} or self-dependency (Befund 47)
        if normalize_dep_name(pdep.name) in seen_names:
            continue
        # Already carried as a conditional alternative (path 1 scan_cmake):
        # the pipeline finding the same name again must not add a second,
        # bare component (Befund 78 — the duplicate the suite never emits).
        if normalize_dep_name(pdep.name) in conditional_seen:
            continue
        if pdep.ecosystem in _NAME_ONLY_ECOSYSTEMS and is_skipped(pdep.name):
            continue
        if _is_parser_noise(pdep.name, pdep.version, pdep.ecosystem):
            continue
        key = (_identity(pdep.name), pdep.version)
        if key in merged:
            continue
        src_parts = Path(pdep.source_file).parts if pdep.source_file else ()
        # A ≤2-char token from test material is a stripped linker flag
        # (`-lev`→ev, `-luv`→uv), not a component — the suite drops these
        # (Befund 75 parity); keeping them only cluttered the excluded list.
        if (
            not pdep.version
            and len(strip_control_chars(pdep.name)) <= 2
            and any(is_test_material_part(part) for part in src_parts)
        ):
            continue
        # Scope mirrors the suite reconciler + scan_cmake exactly (Befund 75):
        # excluded ⟺ test/example/contrib material, a known build tool, or a
        # project Find module that only locates a PROGRAM (Git, OpenSSLbins).
        # A pipeline `context` (an option guard the no-cache build can't
        # decide) is informational — it does NOT make the dep a conditional
        # the way a configured scan_cmake `.condition` does; the suite lists
        # exactly these as open build_file_only entries (scope ""), so the
        # collector must too (mbedtls/wolfssl/opus were wrongly excluded).
        is_excluded = any(is_test_material_part(part) for part in src_parts) or (
            pdep.ecosystem in _NAME_ONLY_ECOSYSTEMS and _is_tooling(pdep.name)
        )
        merged[key] = CheckComponent(
            name=pdep.name,
            version=pdep.version,
            ecosystem=pdep.ecosystem,
            source_type=pdep.detection_method or "build-file",
            tier=pdep.tier,
            confidence=pdep.confidence,
            # Kein leerer Scope mehr (Befund 81 Nachtrag): an libwebsockets
            # gemessen blieben so 15 von 30 Komponenten ungestempelt, und der
            # Bericht konnte Produkt und Testmaterial nicht trennen — genau
            # die Aussage, für die der Gratis-Check da ist. "optional" ist
            # hier die belegbare: aus einer Baudatei gelesen, ohne
            # aufgeloesten Bau ist nicht entscheidbar, ob sie mitgeht.
            scope="excluded" if is_excluded else "optional",
        )

    # Path 3: Yocto/Buildroot BUILD OUTPUT — what is actually in the
    # customer's image (run the check in the build directory).
    from jochwacht_sbom.sbom.buildoutput import scan_build_output

    try:
        build_output_deps, build_output_sources = scan_build_output(
            path, max_depth=max_depth,
        )
    except Exception as exc:  # noqa: BLE001 — a reader defect, recorded, not fatal
        record_failure("build_output", "deploy/images/*.manifest | legal-info/manifest.csv", exc)
        build_output_deps, build_output_sources = [], []
    for dep in build_output_deps:
        clean_dependency(dep)  # control-char hygiene (Befund 15)
        # Resolved, installed packages — the skip list never applies.
        key = (_identity(dep.name), dep.version)
        if key in merged:
            continue
        merged[key] = CheckComponent(
            name=dep.name,
            version=dep.version,
            ecosystem=dep.ecosystem,
            source_type="build-output",
            tier=_LOCKFILE_TIER,
            confidence=_LOCKFILE_CONFIDENCE,
        )

    # Real components first, then the marked alternatives (Befund 44). The
    # component COUNT and the ecosystem list cover only real components; the
    # conditional ones are surfaced through stats.conditional.
    real = list(merged.values())
    components = real + conditional_comps
    ecosystems = sorted({c.ecosystem for c in real if c.ecosystem})

    # Inc-2 twin (Reihe 19): resolve system-library VERSIONS from the
    # machine the customer runs on (pkg-config, sysroot-aware). Under the
    # data-minimisation promise only the VERSION travels for discovered
    # components — supplier/license stay reserved for declarations; the
    # server enriches from its own knowledge base.
    from jochwacht_sbom.sbom.scanner import Dependency as _Dep
    from jochwacht_sbom.sbom.sysresolve import resolve_system_libraries

    _to_resolve: list[_Dep] = []
    _by_key: dict[tuple[str, str], CheckComponent] = {}
    for comp in real:
        if comp.ecosystem in ("cmake", "make", "meson", "autotools",
                              "configure", "generic") and not comp.version:
            d = _Dep(name=comp.name, version="", ecosystem=comp.ecosystem)
            _to_resolve.append(d)
            _by_key[(comp.name, comp.ecosystem)] = comp
    if _to_resolve:
        resolve_system_libraries(_to_resolve)
        for d in _to_resolve:
            if d.version:
                _by_key[(d.name, d.ecosystem)].version = d.version

    # Lifecycle mirrors the suite (Befund 52): a configured build (cache) or
    # resolved output (lockfile / build output) is "build" provenance; only
    # declarations is "design"; nothing found stays "".
    from jochwacht_sbom.sbom.cmake_conditions import build_cmake_context

    has_cache = build_cmake_context(path).has_cache
    resolved = any(
        c.source_type in ("lockfile", "build-output", "declared") for c in real
    )
    if has_cache or resolved:
        lifecycle = "build"
    elif real or conditional_comps:
        lifecycle = "design"
    else:
        lifecycle = ""

    stats = CheckStats(
        build_files_scanned=len(build_files),
        ecosystems=ecosystems,
        build_output_sources=build_output_sources,
        conditional=len(conditional_comps),
        lifecycle=lifecycle,
        go_versions_unresolved=go_versions_unresolved,
    )
    return components, stats
