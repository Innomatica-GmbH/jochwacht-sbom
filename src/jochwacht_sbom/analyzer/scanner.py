"""Build file scanner — collects and analyzes build files with an inference backend.

Supports CMake, Make, Meson, Conan, Cargo, Gradle, Go, Python, npm, Maven,
and Autotools build files.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from jochwacht_sbom.core.log import get_logger

if TYPE_CHECKING:
    from jochwacht_sbom.analyzer.engine import InferenceBackend
    from jochwacht_sbom.analyzer.models import (
        BuildFileArtifact,
        BuildFileDependency,
        BuildFileInternalDep,
    )

logger = get_logger(__name__)


# File patterns to search for, mapped to their build-system type
BUILD_FILE_PATTERNS: list[tuple[str, str]] = [
    # C/C++ build systems
    ("CMakeLists.txt", "cmake"),
    ("**/CMakeLists.txt", "cmake"),
    ("**/*.cmake", "cmake"),
    ("Makefile", "make"),
    ("**/Makefile", "make"),
    ("*.mk", "make"),
    # automake input: fw_LDADD = -lz (measured 12.11.2026: never read)
    ("Makefile.am", "make"),
    ("**/Makefile.am", "make"),
    ("meson.build", "meson"),
    ("**/meson.build", "meson"),
    ("conanfile.py", "conan"),
    ("conanfile.txt", "conan"),
    ("configure.ac", "autotools"),
    ("configure.in", "autotools"),
    ("configure", "configure"),
    ("auto/lib/*/conf", "configure"),
    # Rust
    ("Cargo.toml", "cargo"),
    ("**/Cargo.toml", "cargo"),
    # Java
    ("build.gradle", "gradle"),
    ("**/build.gradle", "gradle"),
    ("build.gradle.kts", "gradle"),
    ("**/build.gradle.kts", "gradle"),
    ("**/dependencies.gradle", "gradle"),
    ("gradle/libs.versions.toml", "gradle"),
    ("**/libs.versions.toml", "gradle"),
    ("pom.xml", "maven"),
    ("**/pom.xml", "maven"),
    # Go
    ("go.mod", "go"),
    # Python
    ("pyproject.toml", "python"),
    ("setup.py", "python"),
    ("setup.cfg", "python"),
    ("requirements.txt", "python"),
    ("**/requirements.txt", "python"),
    ("**/requirements/*.txt", "python"),
    # Node.js
    ("package.json", "npm"),
    ("**/package.json", "npm"),
]


def collect_build_files(
    path: Path,
    max_depth: int = 5,
) -> list[tuple[Path, str]]:
    """Collect build files from a project directory.

    Args:
        path: Root directory to scan.
        max_depth: Maximum directory depth to search.

    Returns:
        List of (file_path, file_type) tuples.
    """
    from jochwacht_sbom.core.file_limit import note_skipped, too_large
    from jochwacht_sbom.sbom.scanner import (
        DEFAULT_EXCLUDE_DIRS,
        _is_ignored,
        load_ignore_patterns,
    )

    found: list[tuple[Path, str]] = []
    seen_paths: set[Path] = set()
    ignore_patterns = load_ignore_patterns(path)

    import re as _re

    # A directory holding CMakeCache.txt is a CONFIGURED BUILD TREE: its
    # CMakeLists/*.cmake are generated (CMakeFiles/, cmake_install.cmake, …)
    # and would inject dozens of phantom find_package hits. The
    # cache itself is read separately as the source of truth; the tree is not
    # a dependency source. Skip everything beneath such a directory.
    build_trees = {
        cache.parent.resolve()
        for cache in path.glob("**/CMakeCache.txt")
        if cache.is_file()
    }

    def _in_build_tree(p: Path) -> bool:
        rp = p.resolve()
        return any(bt == rp or bt in rp.parents for bt in build_trees)

    tree_root = path.resolve()
    for pattern, file_type in BUILD_FILE_PATTERNS:
        for match in path.glob(pattern):
            if not match.is_file():
                continue
            # Not a file that is a link out of the scanned tree, nor one
            # reached through a linked directory outside it.
            try:
                if not match.resolve().is_relative_to(tree_root):
                    continue
            except OSError:
                continue

            if build_trees and _in_build_tree(match):
                continue

            # The one size limit: no tier ever sees a file
            # over it — tier2_structured read seven 65 MiB manifests whole
            # and took five components from them. Named, never silent.
            if too_large(match):
                note_skipped(match)         # named once, counted by the collector
                continue

            # A Find<Name>.cmake module SEARCHES for a dependency — it is
            # tooling, not a declaration (Befund 38, same class as Befund 34:
            # libtls harvested from cmake/modules/FindLibreSSL.cmake). Never
            # a dependency source.
            if file_type == "cmake" and _re.fullmatch(r"Find.+\.cmake", match.name):
                continue

            # Check depth
            try:
                relative = match.relative_to(path)
            except ValueError:
                continue
            if len(relative.parts) > max_depth:
                continue

            # Skip build outputs (dist/staging copies of the source tree
            # produce duplicate conflicts), hidden dirs, and ignores.
            parent_parts = relative.parts[:-1]
            if any(
                part.startswith(".") or part in DEFAULT_EXCLUDE_DIRS
                for part in parent_parts
            ):
                continue
            if ignore_patterns and any(
                _is_ignored(
                    "/".join(parent_parts[: i + 1]), parent_parts[i], ignore_patterns,
                )
                for i in range(len(parent_parts))
            ):
                logger.info("Skipping %s (.jochwachtignore)", relative)
                continue

            resolved = match.resolve()
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)

            # Bare 'configure' must be a shell script (not a binary)
            if match.name == "configure" and file_type == "configure":
                try:
                    first_line = match.read_text(encoding="utf-8", errors="ignore")[:100]
                    if not first_line.startswith("#!"):
                        continue
                except OSError:
                    continue

            found.append((match, file_type))
            logger.info("Found build file: %s (%s)", match, file_type)

    logger.info("Collected %d build files from %s", len(found), path)
    return found


def analyze_build_files(
    files: list[tuple[Path, str]],
    backend: InferenceBackend,
) -> tuple[
    list[BuildFileDependency],
    list[BuildFileArtifact],
    list[BuildFileInternalDep],
]:
    """Analyze build files using an inference backend.

    Args:
        files: List of (file_path, file_type) tuples from collect_build_files.
        backend: Inference backend to use for analysis.

    Returns:
        Tuple of (dependencies, artifacts, internal_deps) aggregated from all files.
    """
    all_deps: list[BuildFileDependency] = []
    all_artifacts: list[BuildFileArtifact] = []
    all_internal: list[BuildFileInternalDep] = []

    total = len(files)
    for i, (file_path, file_type) in enumerate(files, 1):
        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to read %s: %s", file_path, exc)
            continue

        logger.info("Analyzing [%d/%d] %s (%s)", i, total, file_path, file_type)
        result = backend.analyze(content, file_type)

        # Set source_file on all results
        for dep in result.dependencies:
            if not dep.source_file:
                dep.source_file = str(file_path)
            all_deps.append(dep)

        for artifact in result.artifacts:
            if not artifact.source_file:
                artifact.source_file = str(file_path)
            all_artifacts.append(artifact)

        for internal_dep in result.internal_deps:
            if not internal_dep.source_file:
                internal_dep.source_file = str(file_path)
            all_internal.append(internal_dep)

    logger.info(
        "Analysis complete: %d deps, %d artifacts, %d internal deps",
        len(all_deps), len(all_artifacts), len(all_internal),
    )
    return all_deps, all_artifacts, all_internal


def analyze_with_pipeline(
    project_path: Path,
    build_files: list[tuple[Path, str]],
    *,
    backend: InferenceBackend | None = None,
    enabled_tiers: set[int] | None = None,
    timeout_per_tool: float = 30.0,
    cmake_extra_cache: Path | None = None,
) -> tuple[list[BuildFileDependency], list[BuildFileArtifact], list[BuildFileInternalDep]]:
    """Analyze build files using the multi-tier scanner pipeline.

    Runs all enabled tiers and merges results.  If no pipeline tiers produce
    results, falls back to the given backend (if provided).

    Args:
        project_path: Root directory of the project.
        build_files: List of (file_path, file_type) from collect_build_files.
        backend: Optional inference backend for LLM fallback.
        enabled_tiers: Which tiers to run (default: all).
        timeout_per_tool: Timeout in seconds for CLI tools.

    Returns:
        Tuple of (dependencies, artifacts, internal_deps).
    """
    from jochwacht_sbom.analyzer.pipeline import run_pipeline

    deps, artifacts, internal = run_pipeline(
        project_path,
        build_files,
        enabled_tiers=enabled_tiers,
        timeout_per_tool=timeout_per_tool,
    )

    deps = _apply_cmake_conditions(
        deps, project_path, extra_cache=cmake_extra_cache,
    )

    logger.info(
        "Pipeline complete: %d deps, %d artifacts, %d internal deps",
        len(deps), len(artifacts), len(internal),
    )
    return deps, artifacts, internal


def _apply_cmake_conditions(
    deps: list[BuildFileDependency], project_path: Path,
    *, extra_cache: Path | None = None,
) -> list[BuildFileDependency]:
    """Reconcile pipeline CMake deps with the branch/option/cache truth.

    Every tier (regex, tree-sitter, …) harvests ``find_package`` names flat.
    A call on a branch the configured build did not take (``CMakeCache.txt``
    decides ``PAHO_WITH_SSL=ON`` → no LibreSSL) must not survive here just
    because a parser saw the source line (Befund 38/41). Names the cache
    marks ``absent`` are dropped; an ``conditional`` alternative carries its
    guard into ``context``. Done once, centrally, for all tiers.
    """
    from jochwacht_sbom.sbom.cmake_conditions import build_cmake_context, find_dependencies

    if not any(d.ecosystem == "cmake" for d in deps):
        return deps

    ctx = build_cmake_context(project_path, extra_cache=extra_cache)
    states: dict[tuple[str, str], tuple[str, str]] = {}
    for source in {d.source_file for d in deps if d.ecosystem == "cmake" and d.source_file}:
        try:
            content = Path(source).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # ALL dep-producing commands (find_library, pkg_check, …), not just
        # find_package — an option-guarded find_library is an alternative too.
        # A file under add_subdirectory(mbedtls) inherits its if(LWS_WITH_MBEDTLS)
        # guard, so its find_library calls resolve to absent when the cache is off.
        inherited = ctx.inherited_atoms(str(Path(source).parent.resolve()))
        for hit in find_dependencies(content, ctx, inherited=inherited):
            states[(source, hit.name)] = (hit.state, hit.condition)

    kept: list[BuildFileDependency] = []
    for dep in deps:
        if dep.ecosystem == "cmake":
            state = states.get((dep.source_file, dep.name))
            if state is not None:
                if state[0] == "absent":
                    continue  # the configured build did not take this branch
                if state[0] == "conditional" and not dep.context:
                    dep.context = state[1]
        kept.append(dep)
    return kept
