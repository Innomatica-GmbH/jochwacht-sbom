"""Merge engine — deduplicates scanner results across tiers.

Lower tier number = higher confidence.  When the same dependency is found
by multiple scanners, the result from the lowest tier wins.

Tier 5 (external tools like syft/trivy) undergoes additional filtering:
- File paths and CI artifacts are removed (not real dependencies)
- Only deps NOT already found by Tier 1-4 are kept (gap-filling mode)
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from jochwacht_sbom.analyzer.normalize import LINK_NAME_PACKAGES, normalize_dep_name

if TYPE_CHECKING:
    from jochwacht_sbom.analyzer.models import (
        BuildFileArtifact,
        BuildFileDependency,
        BuildFileInternalDep,
    )
    from jochwacht_sbom.analyzer.pipeline.base import ScanResult

# Tier 5 noise patterns — deps matching these are filtered out
_TIER5_NOISE = re.compile(
    r"^(?:"
    r"actions/"              # GitHub Actions (actions/checkout, etc.)
    r"|github/"              # GitHub internal
    r"|google/"              # Google OSS-Fuzz actions
    r"|\.github/"            # .github/ workflow files
    r"|/repos/"              # Absolute repo paths
    r"|.*\.(?:yml|yaml|json|txt|toml|lock|gemspec|jar|war|properties|kts|gradle|xml)$"  # Config
    r")",
    re.IGNORECASE,
)


def _is_tier5_noise(name: str) -> bool:
    """Check if a Tier 5 dep name is noise (file paths, CI artifacts)."""
    return bool(_TIER5_NOISE.match(name))


#: Build-script name-token ecosystems — the only place the skip list
#: may drop a dependency (see check/collector.py for the measurement).
_NAME_ONLY_ECOSYSTEMS = frozenset({
    "cmake", "meson", "make", "autotools", "configure", "generic",
})


def _skip_checker() -> Callable[[str], bool] | None:
    """The curated skip list, if the knowledge DB is importable.

    The list (build tools, system libs — 950 curated names like
    ``threads``, ``git``, ``appleframeworks``) was enforced only by
    tier 4; tier 2's structured parsers emitted the same pseudo-deps
    unfiltered into every report (measured: 60+ of the 212 missing
    occurrences in embedded-coverage run #3 were skip-listed names).
    Enforcing it here, in the merge, covers every tier once.
    """
    try:
        from jochwacht_sbom.sbom.knowledge_db import is_skipped
    except ImportError:  # pragma: no cover - sbom extra not installed
        return None
    return is_skipped


def _name_preference(name: str) -> tuple[int, int, str, str]:
    """Between different names of one library, the one that leads to its key
    in the knowledge base (measured with the signed knowledge base:
    libnl-3.0 has a CPE, nl-3 none): lib<key> first (libwebsockets,
    libevent), then the key itself (openssl, glib, zlib), then a lib name
    (libnl-3.0 before nl-3), then the shortest, then the spelling."""
    key = normalize_dep_name(name)
    low = name.lower()
    order = 0 if low == f"lib{key}" else 1 if low == key else 2 if low.startswith("lib") else 3
    return (order, len(name), low, name)


# A major version in the name: SDL2, Qt5, Qt5Core, python3 (appended) or
# usb-1.0, libusb-0.1, gtk+-3.0, glib-2.0 (the pkg-config API suffix).
_DASH_MAJOR = re.compile(r"-(\d+)(?:\.\d+)*\Z")
_APPENDED_MAJOR = re.compile(r"\A[A-Za-z+]+?(\d+)(?=[A-Z_]|\Z)")


def _major(name: str) -> tuple[int | None, bool]:
    """(major, appended): the major version a name carries, and whether it
    is appended to the name itself (SDL2) rather than a pkg-config suffix."""
    m = _DASH_MAJOR.search(name)
    if m:
        return int(m.group(1)), False
    m = _APPENDED_MAJOR.match(name)
    if m:
        return int(m.group(1)), True
    return None, False


def _same_library(a: str, b: str) -> bool:
    """Two names of one normalized key name one library unless they carry
    different major versions (SDL and SDL2, Qt5 and Qt6,
    libusb-0.1 and usb-1.0 are different libraries). A name without a major
    joins a pkg-config suffix (glib, glib-2.0), never an appended major
    (SDL is SDL 1, not SDL2)."""
    (ma, appended_a), (mb, appended_b) = _major(a), _major(b)
    if ma is not None and mb is not None:
        return ma == mb
    if ma is None and mb is None:
        return True
    return not (appended_a or appended_b)


def _rank(tier: int, dep: BuildFileDependency) -> tuple[int, tuple[int, int, str, str]]:
    """Which occurrence of a name represents it — lower wins.

    Lowest tier first, then _name_preference. Before, the first won, and the
    order changed with the hash seed.
    """
    return (tier, _name_preference(dep.name))


def merge_results(
    results: list[ScanResult],
) -> tuple[list[BuildFileDependency], list[BuildFileArtifact], list[BuildFileInternalDep]]:
    """Merge scan results from multiple tiers.

    Deduplicates dependencies by normalized name.  The entry from the
    lowest tier (highest confidence) wins.  Version and source_file
    are taken from the winning entry.

    Tier 5 dependencies are filtered: file paths and CI artifacts are
    removed, and only deps not already found by Tier 1-4 are kept.

    Artifacts and internal deps are deduplicated by path/project name.

    Returns:
        Merged (dependencies, artifacts, internal_deps).
    """
    # --- Dependencies: deduplicate by normalized name, lowest tier wins ---
    is_skipped = _skip_checker()

    # First pass: collect Tier 1-4 deps
    groups: dict[str, list[list[tuple[int, BuildFileDependency]]]] = {}

    for result in results:
        if result.tier >= 5:
            continue  # handle Tier 5 in second pass
        for dep in result.dependencies:
            if (
                is_skipped is not None
                and getattr(dep, "ecosystem", "") in _NAME_ONLY_ECOSYSTEMS
                and is_skipped(dep.name)
            ):
                continue
            key = normalize_dep_name(dep.name)
            libraries = groups.setdefault(key, [])
            for library in libraries:
                if all(_same_library(dep.name, other.name) for _, other in library):
                    library.append((result.tier, dep))
                    break
            else:
                libraries.append([(result.tier, dep)])

    dep_best: dict[tuple[str, int], tuple[int, BuildFileDependency]] = {}
    for key, libraries in groups.items():
        for index, library in enumerate(libraries):
            tier, best = min(library, key=lambda entry: _rank(*entry))
            canonical = LINK_NAME_PACKAGES.get(best.name.lower())
            if canonical:
                # -lssl/-lcrypto: the package, the name that has the key
                best = best.model_copy(update={"name": canonical})
            dep_best[(key, index)] = (tier, best)

    # Second pass: Tier 5 — only keep non-noise deps not already found
    for result in results:
        if result.tier < 5:
            continue
        for dep in result.dependencies:
            if _is_tier5_noise(dep.name):
                continue
            if (
                is_skipped is not None
                and getattr(dep, "ecosystem", "") in _NAME_ONLY_ECOSYSTEMS
                and is_skipped(dep.name)
            ):
                continue
            key = normalize_dep_name(dep.name)
            if key not in groups:
                groups[key] = []
                dep_best[(key, 0)] = (result.tier, dep)

    merged_deps = [dep for _, dep in sorted(dep_best.values(), key=lambda x: x[1].name.lower())]

    # --- Artifacts: deduplicate by path ---
    seen_paths: set[str] = set()
    merged_artifacts: list[BuildFileArtifact] = []
    for result in sorted(results, key=lambda r: r.tier):
        for art in result.artifacts:
            if art.path not in seen_paths:
                seen_paths.add(art.path)
                merged_artifacts.append(art)

    # --- Internal deps: deduplicate by project name ---
    seen_projects: set[str] = set()
    merged_internal: list[BuildFileInternalDep] = []
    for result in sorted(results, key=lambda r: r.tier):
        for idep in result.internal_deps:
            key = idep.project.lower()
            if key not in seen_projects:
                seen_projects.add(key)
                merged_internal.append(idep)

    return merged_deps, merged_artifacts, merged_internal
