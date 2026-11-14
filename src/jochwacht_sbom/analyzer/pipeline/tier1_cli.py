"""Tier 1 — Native CLI tool scanners.

Invokes native build-system tools (cargo, go, meson, npm, mvn, cmake, conan)
via subprocess and parses their structured output. Tier 1, confidence 0.95.

Each scanner checks tool availability via shutil.which() before attempting.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from jochwacht_sbom.analyzer.models import BuildFileDependency
from jochwacht_sbom.analyzer.pipeline.base import ScanResult
from jochwacht_sbom.core.log import get_logger

logger = get_logger(__name__)

_TIER = 1
_CONFIDENCE = 0.95
_TIMEOUT = 30


def _run_cmd(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: float = _TIMEOUT,
) -> subprocess.CompletedProcess[str] | None:
    """Run a command, returning None on failure."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None


# ---------------------------------------------------------------------------
# cargo metadata
# ---------------------------------------------------------------------------

class CargoMetadataScanner:
    """Parse output of ``cargo metadata --format-version=1 --no-deps``."""

    tier = _TIER
    name = "cargo-metadata"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        if file_type == "_project":
            return (project_path / "Cargo.toml").exists() and shutil.which("cargo") is not None
        return False

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        result = _run_cmd(
            ["cargo", "metadata", "--format-version=1", "--no-deps"],
            cwd=project_path,
        )
        if result is None or result.returncode != 0:
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return ScanResult(tier=self.tier, scanner_name=self.name)

        deps: list[BuildFileDependency] = []
        seen: set[str] = set()

        for package in data.get("packages", []):
            for dep in package.get("dependencies", []):
                name = dep.get("name", "")
                if not name or name in seen:
                    continue
                # Skip path dependencies — these are workspace-internal crates,
                # not external dependencies. In cargo metadata output, path deps
                # have a non-null "path" field (absolute filesystem path).
                if dep.get("path") is not None:
                    continue
                seen.add(name)
                req = dep.get("req", "")
                deps.append(BuildFileDependency(
                    name=name,
                    version=req,
                    ecosystem="cargo",
                    source_file="Cargo.toml",
                    confidence=_CONFIDENCE,
                    tier=self.tier,
                    detection_method="cargo-metadata",
                ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


# ---------------------------------------------------------------------------
# go list
# ---------------------------------------------------------------------------

class GoListScanner:
    """Parse output of ``go list -m -json all``."""

    tier = _TIER
    name = "go-list"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        if file_type == "_project":
            return (project_path / "go.mod").exists() and shutil.which("go") is not None
        return False

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        result = _run_cmd(["go", "list", "-m", "-json", "all"], cwd=project_path)
        if result is None or result.returncode != 0:
            return ScanResult(tier=self.tier, scanner_name=self.name)

        deps: list[BuildFileDependency] = []
        # Output is NDJSON (concatenated JSON objects)
        decoder = json.JSONDecoder()
        text = result.stdout.strip()
        pos = 0
        first = True
        while pos < len(text):
            try:
                obj, end = decoder.raw_decode(text, pos)
            except json.JSONDecodeError:
                break
            pos = end
            # Skip whitespace
            while pos < len(text) and text[pos] in " \t\n\r":
                pos += 1

            # Skip the main module itself (first entry)
            if first:
                first = False
                continue

            path = obj.get("Path", "")
            version = obj.get("Version", "")
            if path:
                deps.append(BuildFileDependency(
                    name=path,
                    version=version,
                    ecosystem="go",
                    source_file="go.mod",
                    confidence=_CONFIDENCE,
                    tier=self.tier,
                    detection_method="go-list",
                ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


# ---------------------------------------------------------------------------
# meson introspect
# ---------------------------------------------------------------------------

class MesonIntrospectScanner:
    """Parse output of ``meson introspect --scan-dependencies``."""

    tier = _TIER
    name = "meson-introspect"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        if file_type == "_project":
            return (project_path / "meson.build").exists() and shutil.which("meson") is not None
        return False

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        result = _run_cmd(
            ["meson", "introspect", "--scan-dependencies", str(project_path / "meson.build")],
            cwd=project_path,
        )
        if result is None or result.returncode != 0:
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return ScanResult(tier=self.tier, scanner_name=self.name)

        deps: list[BuildFileDependency] = []
        for entry in data if isinstance(data, list) else []:
            raw_name = entry.get("name", "")
            version = entry.get("version", [])
            ver_str = version[0] if isinstance(version, list) and version else ""
            # Some projects pass space-separated pkg-config names in one dep
            names = raw_name.split() if " " in raw_name else [raw_name]
            for name in names:
                if name:
                    deps.append(BuildFileDependency(
                        name=name,
                        version=str(ver_str),
                        ecosystem="meson",
                        source_file="meson.build",
                        confidence=_CONFIDENCE,
                        tier=self.tier,
                        detection_method="meson-introspect",
                    ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


# ---------------------------------------------------------------------------
# npm ls
# ---------------------------------------------------------------------------

class NpmLsScanner:
    """Parse output of ``npm ls --json --all --package-lock-only``."""

    tier = _TIER
    name = "npm-ls"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        if file_type == "_project":
            return (
                (project_path / "package.json").exists()
                and (project_path / "package-lock.json").exists()
                and shutil.which("npm") is not None
            )
        return False

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        result = _run_cmd(
            ["npm", "ls", "--json", "--all", "--package-lock-only"],
            cwd=project_path,
        )
        if result is None:
            return ScanResult(tier=self.tier, scanner_name=self.name)

        # npm ls may return non-zero but still produce valid JSON
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return ScanResult(tier=self.tier, scanner_name=self.name)

        deps: list[BuildFileDependency] = []
        seen: set[str] = set()
        self._extract_deps(data.get("dependencies", {}), deps, seen, file_path)

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)

    def _extract_deps(
        self,
        dep_tree: dict[str, object],
        deps: list[BuildFileDependency],
        seen: set[str],
        file_path: Path,
    ) -> None:
        """Recursively extract deps from npm ls tree (only top-level)."""
        for name, info in dep_tree.items():
            if name in seen:
                continue
            seen.add(name)
            version = ""
            if isinstance(info, dict):
                version = str(info.get("version", ""))
            deps.append(BuildFileDependency(
                name=name,
                version=version,
                ecosystem="npm",
                source_file="package.json",
                confidence=_CONFIDENCE,
                tier=self.tier,
                detection_method="npm-ls",
            ))


# ---------------------------------------------------------------------------
# mvn dependency:tree
# ---------------------------------------------------------------------------

class MvnDepTreeScanner:
    """Parse output of ``mvn dependency:tree -DoutputType=text``."""

    tier = _TIER
    name = "mvn-dependency-tree"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        if file_type == "_project":
            return (project_path / "pom.xml").exists() and shutil.which("mvn") is not None
        return False

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        result = _run_cmd(
            [
                "mvn", "dependency:tree",
                f"-DoutputFile={tmp_path}",
                "-DoutputType=text",
                "-q",
            ],
            cwd=project_path,
            timeout=60,
        )
        if result is None or result.returncode != 0:
            tmp_path.unlink(missing_ok=True)
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            content = tmp_path.read_text(encoding="utf-8")
        except OSError:
            return ScanResult(tier=self.tier, scanner_name=self.name)
        finally:
            tmp_path.unlink(missing_ok=True)

        deps: list[BuildFileDependency] = []
        seen: set[str] = set()
        for line in content.splitlines():
            # Format: [indent]groupId:artifactId:type:version[:classifier]:scope
            stripped = line.strip().lstrip("+-|\\ ")
            parts = stripped.split(":")
            if len(parts) >= 4:
                group_id = parts[0]
                artifact_id = parts[1]
                version = parts[3]
                name = f"{group_id}:{artifact_id}"
                if name not in seen:
                    seen.add(name)
                    deps.append(BuildFileDependency(
                        name=name,
                        version=version,
                        ecosystem="maven",
                        source_file="pom.xml",
                        confidence=_CONFIDENCE,
                        tier=self.tier,
                        detection_method="mvn-dependency-tree",
                    ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


# ---------------------------------------------------------------------------
# cmake --trace
# ---------------------------------------------------------------------------

class CmakeTraceScanner:
    """Parse cmake trace output to find find_package calls."""

    tier = _TIER
    name = "cmake-trace"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        if file_type == "_project":
            return (
                (project_path / "CMakeLists.txt").exists()
                and shutil.which("cmake") is not None
            )
        return False

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        # A fresh temporary build folder outside the scanned folder: in it, a
        # link ``_jochwacht_cmake_trace`` made cmake write its cache and
        # makefiles elsewhere (sicherheit-2, S3). cmake takes the source path.
        build_dir = Path(tempfile.mkdtemp(prefix="jochwacht-cmake-trace-"))

        result = _run_cmd(
            [
                "cmake",
                "--trace-format=json-v1",
                "--trace-expand",
                f"--trace-redirect={tmp_path}",
                str(project_path),
            ],
            cwd=build_dir,
            timeout=60,
        )

        # Clean up build dir
        import shutil as _shutil
        _shutil.rmtree(build_dir, ignore_errors=True)

        if result is None:
            tmp_path.unlink(missing_ok=True)
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            content = tmp_path.read_text(encoding="utf-8")
        except OSError:
            return ScanResult(tier=self.tier, scanner_name=self.name)
        finally:
            tmp_path.unlink(missing_ok=True)

        deps: list[BuildFileDependency] = []
        seen: set[str] = set()

        for line in content.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            cmd = entry.get("cmd", "").lower()
            args = entry.get("args", [])
            source = entry.get("file", "CMakeLists.txt")

            if cmd in ("find_package", "find_host_package") and args:
                name = args[0]
                # cmake trace may merge args with semicolons ("Git;QUIET")
                if ";" in name:
                    name = name.split(";")[0]
                # Skip CMake utility modules
                fp_skip = {
                    "PkgConfig", "Threads", "Git", "Perl", "Python3",
                    "PythonInterp", "PythonLibs",
                    "CTest", "CPack", "FetchContent", "ExternalProject",
                    "GNUInstallDirs", "GenerateExportHeader",
                    "CMakePackageConfigHelpers",
                }
                if name in fp_skip:
                    # Map known modules to canonical dep names
                    module_map = {"Threads": "pthread", "Python3": "Python",
                                  "PythonInterp": "Python", "PythonLibs": "Python"}
                    mapped = module_map.get(name)
                    if mapped and mapped not in seen:
                        seen.add(mapped)
                        deps.append(BuildFileDependency(
                            name=mapped,
                            ecosystem="cmake",
                            source_file=source,
                            confidence=_CONFIDENCE,
                            tier=self.tier,
                            detection_method="cmake-trace",
                        ))
                    continue
                if name not in seen:
                    seen.add(name)
                    deps.append(BuildFileDependency(
                        name=name,
                        ecosystem="cmake",
                        source_file=source,
                        confidence=_CONFIDENCE,
                        tier=self.tier,
                        detection_method="cmake-trace",
                    ))

            elif cmd in ("pkg_check_modules", "pkg_search_module") and len(args) >= 2:
                # args[0]=prefix, rest=flags+package names
                pkg_flags = {
                    "REQUIRED", "QUIET", "IMPORTED_TARGET",
                    "NO_CMAKE_PATH", "NO_CMAKE_ENVIRONMENT_PATH",
                }
                for arg in args[1:]:
                    if arg.upper() in pkg_flags:
                        continue
                    # CMake may pass semicolon-separated lists (e.g.
                    # "libavcodec;libavformat;libavutil;libswscale")
                    sub_args = arg.split(";") if ";" in arg else [arg]
                    for sub in sub_args:
                        # Strip version constraints (e.g. "glib-2.0>=2.50")
                        pkg = re.split(r"[><=]", sub)[0].strip()
                        if pkg and pkg not in seen:
                            seen.add(pkg)
                            deps.append(BuildFileDependency(
                                name=pkg,
                                ecosystem="cmake",
                                source_file=source,
                                confidence=_CONFIDENCE,
                                tier=self.tier,
                                detection_method="cmake-trace-pkg-check",
                            ))

            elif cmd == "find_library" and len(args) >= 2:
                # args[0]=result variable, then NAMES/name
                # Handle: find_library(VAR NAMES foo bar) or find_library(VAR foo)
                lib_skip = {"NAMES", "NAME", "PATHS", "PATH_SUFFIXES", "HINTS",
                            "DOC", "NO_DEFAULT_PATH", "REQUIRED", "QUIET",
                            "NO_CMAKE_PATH", "NO_CMAKE_ENVIRONMENT_PATH",
                            "NO_SYSTEM_ENVIRONMENT_PATH", "NO_CMAKE_SYSTEM_PATH",
                            "NO_CMAKE_FIND_ROOT_PATH", "NAMES_PER_DIR",
                            "ENV", "IMPORTED_TARGET", "CONFIG", "MODULE"}
                names_mode = False
                for arg in args[1:]:
                    upper = arg.upper()
                    if upper == "NAMES" or upper == "NAME":
                        names_mode = True
                        continue
                    if upper in lib_skip or upper.startswith("CMAKE_"):
                        names_mode = False
                        continue
                    if arg.startswith("/") or arg.startswith("$"):
                        # Path value, skip
                        continue
                    # Skip args with semicolons (cmake list expansions)
                    if ";" in arg:
                        continue
                    # Skip doc strings and descriptions (contain spaces/parens)
                    if " " in arg or "(" in arg:
                        continue
                    # Skip registry paths (Windows)
                    if arg.startswith("[HKEY"):
                        continue
                    if arg and arg not in seen:
                        seen.add(arg)
                        deps.append(BuildFileDependency(
                            name=arg,
                            ecosystem="cmake",
                            source_file=source,
                            confidence=_CONFIDENCE,
                            tier=self.tier,
                            detection_method="cmake-trace-find-library",
                        ))
                    if not names_mode:
                        break  # Only first name unless NAMES keyword

            elif cmd == "check_library_exists" and args:
                # check_library_exists(library function header result_var)
                lib_name = args[0]
                if lib_name and lib_name not in seen:
                    seen.add(lib_name)
                    deps.append(BuildFileDependency(
                        name=lib_name,
                        ecosystem="cmake",
                        source_file=source,
                        confidence=_CONFIDENCE,
                        tier=self.tier,
                        detection_method="cmake-trace-check-lib",
                    ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


# ---------------------------------------------------------------------------
# conan graph info
# ---------------------------------------------------------------------------

class ConanGraphScanner:
    """Parse output of ``conan graph info . --format=json``."""

    tier = _TIER
    name = "conan-graph"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        if file_type == "_project":
            return (
                (
                    (project_path / "conanfile.txt").exists()
                    or (project_path / "conanfile.py").exists()
                )
                and shutil.which("conan") is not None
            )
        return False

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        result = _run_cmd(
            ["conan", "graph", "info", ".", "--format=json"],
            cwd=project_path,
        )
        if result is None or result.returncode != 0:
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return ScanResult(tier=self.tier, scanner_name=self.name)

        deps: list[BuildFileDependency] = []
        seen: set[str] = set()

        nodes = data.get("graph", {}).get("nodes", {})
        for _id, node in nodes.items():
            ref = node.get("ref", "")
            if not ref or "#" not in ref:
                # Skip root node or invalid refs
                name = node.get("name", "")
                version = node.get("version", "")
            else:
                # ref format: "name/version#revision"
                name_ver = ref.split("#")[0]
                parts = name_ver.split("/", 1)
                name = parts[0]
                version = parts[1] if len(parts) > 1 else ""

            if name and name not in seen:
                seen.add(name)
                deps.append(BuildFileDependency(
                    name=name,
                    version=version,
                    ecosystem="conan",
                    source_file="conanfile.txt",
                    confidence=_CONFIDENCE,
                    tier=self.tier,
                    detection_method="conan-graph",
                ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


# ---------------------------------------------------------------------------
# gradle dependencies
# ---------------------------------------------------------------------------

class GradleDepScanner:
    """Parse output of ``gradle dependencies`` (prefers gradlew wrapper)."""

    tier = _TIER
    name = "gradle-dependencies"

    # Configurations to try in order (first success wins)
    _CONFIGURATIONS = [
        "runtimeClasspath",
        "compileClasspath",
        "default",
    ]

    def _find_gradle(self, project_path: Path) -> str | None:
        """Find gradle executable — prefer project's gradlew wrapper."""
        # The wrapper only as a regular, executable file of the project: never
        # through a link and never made executable by us (chmod follows a
        # link; sicherheit-2, S3).
        wrapper = project_path / "gradlew"
        if (wrapper.is_file() and not wrapper.is_symlink()
                and os.access(wrapper, os.X_OK)):
            return str(wrapper)
        if shutil.which("gradle") is not None:
            return "gradle"
        return None

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        if file_type == "_project":
            return (
                (
                    (project_path / "build.gradle").exists()
                    or (project_path / "build.gradle.kts").exists()
                )
                and self._find_gradle(project_path) is not None
            )
        return False

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        gradle_cmd = self._find_gradle(project_path)
        if gradle_cmd is None:
            return ScanResult(tier=self.tier, scanner_name=self.name)

        # Try each configuration until one produces deps
        for config in self._CONFIGURATIONS:
            result = _run_cmd(
                [
                    gradle_cmd, "dependencies",
                    "--configuration", config,
                    "-q", "--console=plain",
                ],
                cwd=project_path,
                timeout=120,
            )
            if result is not None and result.returncode == 0:
                deps = self._parse_tree(result.stdout, project_path)
                if deps:
                    return ScanResult(
                        tier=self.tier, scanner_name=self.name, dependencies=deps,
                    )

        # Last resort: run without --configuration (all configs)
        result = _run_cmd(
            [gradle_cmd, "dependencies", "-q", "--console=plain"],
            cwd=project_path,
            timeout=120,
        )
        if result is not None and result.returncode == 0:
            deps = self._parse_tree(result.stdout, project_path)
            if deps:
                return ScanResult(
                    tier=self.tier, scanner_name=self.name, dependencies=deps,
                )

        return ScanResult(tier=self.tier, scanner_name=self.name)

    def _parse_tree(
        self, stdout: str, project_path: Path,
    ) -> list[BuildFileDependency]:
        """Parse gradle dependency tree output."""
        deps: list[BuildFileDependency] = []
        seen: set[str] = set()

        for line in stdout.splitlines():
            # Format: +--- group:artifact:version or \--- group:artifact:version
            stripped = line.strip().lstrip("+-|\\ ")
            if not stripped or stripped.startswith("("):
                continue
            # Skip constraint/project lines
            if stripped.startswith("project "):
                continue
            parts = stripped.split(":")
            if len(parts) >= 3:
                group_id = parts[0]
                artifact_id = parts[1]
                # Version may have annotations like " -> 1.2.3" or " (*)"
                version_part = parts[2].split()
                version = version_part[0] if version_part else ""
                # Handle " -> actual_version" (conflict resolution)
                if "->" in parts[2]:
                    arrow_idx = version_part.index("->") if "->" in version_part else -1
                    if arrow_idx >= 0 and arrow_idx + 1 < len(version_part):
                        version = version_part[arrow_idx + 1]
                name = f"{group_id}:{artifact_id}"
                if name not in seen:
                    seen.add(name)
                    source = "build.gradle.kts" if (
                        project_path / "build.gradle.kts"
                    ).exists() else "build.gradle"
                    deps.append(BuildFileDependency(
                        name=name,
                        version=version,
                        ecosystem="gradle",
                        source_file=source,
                        confidence=_CONFIDENCE,
                        tier=self.tier,
                        detection_method="gradle-dependencies",
                    ))

        return deps


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_scanners() -> list[
    CargoMetadataScanner
    | GoListScanner
    | MesonIntrospectScanner
    | NpmLsScanner
    | MvnDepTreeScanner
    | CmakeTraceScanner
    | ConanGraphScanner
    | GradleDepScanner
]:
    """Return all Tier 1 CLI scanner instances."""
    return [
        CargoMetadataScanner(),
        GoListScanner(),
        MesonIntrospectScanner(),
        NpmLsScanner(),
        MvnDepTreeScanner(),
        CmakeTraceScanner(),
        ConanGraphScanner(),
        GradleDepScanner(),
    ]
