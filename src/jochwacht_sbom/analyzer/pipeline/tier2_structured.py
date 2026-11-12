"""Tier 2 — Structured file parsers using Python stdlib.

Uses tomllib, json, and xml.etree to parse build files with proper
structure awareness (no regex). Tier 2, confidence 0.90.
"""

from __future__ import annotations

import json
import tomllib
from typing import TYPE_CHECKING

from jochwacht_sbom.analyzer.models import BuildFileDependency
from jochwacht_sbom.analyzer.pipeline.base import ScanResult
from jochwacht_sbom.core import xmlsafe
from jochwacht_sbom.core.log import get_logger

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger(__name__)

_TIER = 2
_CONFIDENCE = 0.90


# ---------------------------------------------------------------------------
# Cargo.toml (Rust)
# ---------------------------------------------------------------------------

def _is_local_crate(spec: dict[str, object], manifest: Path, dep_name: str) -> bool:
    """True when a ``path = "..."`` dependency points at a crate INSIDE the
    customer's own tree (a workspace member).

    A multi-crate repository writes ``grep = { version = "0.4.1", path =
    "crates/grep" }``: the version is what gets published to crates.io, the
    path is what this build actually uses. Measured on ripgrep (15.09.2026),
    the free check listed globset, ignore and grep-matcher — the project's
    OWN crates — as third-party components of the customer's product.
    Only a ``path`` resolving to a Cargo.toml that declares the SAME package
    name counts; anything unresolvable is left alone rather than guessed.
    """
    raw = spec.get("path")
    if not isinstance(raw, str) or not raw:
        return False
    try:
        target = (manifest.parent / raw / "Cargo.toml").resolve()
        data = tomllib.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    package = data.get("package")
    if not isinstance(package, dict):
        return False
    name = package.get("name")
    return isinstance(name, str) and name.strip().lower() == dep_name.strip().lower()


class CargoTomlParser:
    """Parse Cargo.toml using tomllib — handles inline tables, workspace, etc."""

    tier = _TIER
    name = "structured-cargo-toml"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        return file_type == "cargo"

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        try:
            data = tomllib.loads(file_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return ScanResult(tier=self.tier, scanner_name=self.name)

        deps: list[BuildFileDependency] = []
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            dep_table = data.get(section, {})
            if not isinstance(dep_table, dict):
                continue
            for name, spec in dep_table.items():
                version = ""
                if isinstance(spec, str):
                    version = spec
                elif isinstance(spec, dict):
                    # Skip workspace-inherited deps: { workspace = true }
                    if spec.get("workspace"):
                        continue
                    # Skip path-only deps (no version, no git) — workspace-internal crates
                    has_path = "path" in spec
                    has_version = "version" in spec
                    has_git = "git" in spec
                    if has_path and not has_version and not has_git:
                        continue
                    # …and a `version` + `path` pair naming a crate of the same
                    # name in this tree is a workspace member too: the version
                    # is for publishing, the path is what actually builds.
                    if has_path and _is_local_crate(spec, file_path, str(name)):
                        continue
                    version = spec.get("version", "")
                # Use the canonical crate name if renamed via `package = "real-name"`
                canonical_name = str(spec.get("package", name)) if isinstance(spec, dict) else name
                deps.append(BuildFileDependency(
                    name=canonical_name,
                    version=str(version),
                    ecosystem="cargo",
                    source_file=str(file_path),
                    confidence=_CONFIDENCE,
                    tier=self.tier,
                    detection_method="tomllib-cargo",
                ))

        # Also check [target.'cfg(...)'.dependencies]
        target = data.get("target", {})
        if isinstance(target, dict):
            for _cfg, cfg_data in target.items():
                if not isinstance(cfg_data, dict):
                    continue
                for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                    dep_table = cfg_data.get(section, {})
                    if not isinstance(dep_table, dict):
                        continue
                    for name, spec in dep_table.items():
                        version = ""
                        if isinstance(spec, str):
                            version = spec
                        elif isinstance(spec, dict):
                            # Skip workspace-inherited deps: { workspace = true }
                            if spec.get("workspace"):
                                continue
                            # Skip path-only deps (no version, no git) — workspace-internal crates
                            has_path = "path" in spec
                            has_version = "version" in spec
                            has_git = "git" in spec
                            if has_path and not has_version and not has_git:
                                continue
                            # …and a `version` + `path` pair naming a crate of the same
                            # name in this tree is a workspace member too: the version
                            # is for publishing, the path is what actually builds.
                            if has_path and _is_local_crate(spec, file_path, str(name)):
                                continue
                            version = spec.get("version", "")
                        canonical_name = (
                            str(spec.get("package", name)) if isinstance(spec, dict) else name
                        )
                        deps.append(BuildFileDependency(
                            name=canonical_name,
                            version=str(version),
                            ecosystem="cargo",
                            source_file=str(file_path),
                            confidence=_CONFIDENCE,
                            tier=self.tier,
                            detection_method="tomllib-cargo",
                        ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


# ---------------------------------------------------------------------------
# pyproject.toml (Python — PEP 621 + Poetry)
# ---------------------------------------------------------------------------

class PyprojectTomlParser:
    """Parse pyproject.toml for PEP 621 and Poetry dependencies."""

    tier = _TIER
    name = "structured-pyproject"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        return file_type == "python"

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        if file_path.name != "pyproject.toml":
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            data = tomllib.loads(file_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return ScanResult(tier=self.tier, scanner_name=self.name)

        deps: list[BuildFileDependency] = []

        # PEP 621: [project.dependencies]
        for req_str in data.get("project", {}).get("dependencies", []):
            name = _extract_pep508_name(req_str)
            if name:
                deps.append(BuildFileDependency(
                    name=name,
                    ecosystem="pypi",
                    source_file=str(file_path),
                    confidence=_CONFIDENCE,
                    tier=self.tier,
                    detection_method="tomllib-pyproject",
                ))

        # PEP 621: [project.optional-dependencies]
        for _group, group_deps in data.get("project", {}).get("optional-dependencies", {}).items():
            if not isinstance(group_deps, list):
                continue
            for req_str in group_deps:
                name = _extract_pep508_name(req_str)
                if name:
                    deps.append(BuildFileDependency(
                        name=name,
                        ecosystem="pypi",
                        source_file=str(file_path),
                        confidence=_CONFIDENCE,
                        tier=self.tier,
                        detection_method="tomllib-pyproject",
                    ))

        # PEP 735: [dependency-groups]
        for _group, group_deps in data.get("dependency-groups", {}).items():
            if not isinstance(group_deps, list):
                continue
            for entry in group_deps:
                if isinstance(entry, str):
                    name = _extract_pep508_name(entry)
                    if name:
                        deps.append(BuildFileDependency(
                            name=name,
                            ecosystem="pypi",
                            source_file=str(file_path),
                            confidence=_CONFIDENCE,
                            tier=self.tier,
                            detection_method="tomllib-pyproject",
                        ))

        # Poetry: [tool.poetry.dependencies]
        poetry = data.get("tool", {}).get("poetry", {})
        for section in ("dependencies", "dev-dependencies"):
            poetry_deps = poetry.get(section, {})
            if not isinstance(poetry_deps, dict):
                continue
            for name, _spec in poetry_deps.items():
                if name == "python":
                    continue
                deps.append(BuildFileDependency(
                    name=name,
                    ecosystem="pypi",
                    source_file=str(file_path),
                    confidence=_CONFIDENCE,
                    tier=self.tier,
                    detection_method="tomllib-pyproject",
                ))

        # Poetry group deps: [tool.poetry.group.*.dependencies]
        for _group, group_data in poetry.get("group", {}).items():
            if not isinstance(group_data, dict):
                continue
            group_deps = group_data.get("dependencies", {})
            if not isinstance(group_deps, dict):
                continue
            for name in group_deps:
                if name == "python":
                    continue
                deps.append(BuildFileDependency(
                    name=name,
                    ecosystem="pypi",
                    source_file=str(file_path),
                    confidence=_CONFIDENCE,
                    tier=self.tier,
                    detection_method="tomllib-pyproject",
                ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


def _extract_pep508_name(req_str: str) -> str:
    """Extract the package name from a PEP 508 requirement string."""
    # Strip extras, version specifiers, markers
    # e.g. "requests[security]>=2.0; python_version>='3'" → "requests"
    import re
    m = re.match(r"^([A-Za-z0-9][-A-Za-z0-9_.]*)", req_str.strip())
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# libs.versions.toml (Gradle Version Catalog)
# ---------------------------------------------------------------------------

class GradleCatalogParser:
    """Parse Gradle version catalogs (libs.versions.toml)."""

    tier = _TIER
    name = "structured-gradle-catalog"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        return file_type == "gradle"

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        if file_path.name not in ("libs.versions.toml", "gradle.versions.toml"):
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            data = tomllib.loads(file_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return ScanResult(tier=self.tier, scanner_name=self.name)

        deps: list[BuildFileDependency] = []
        versions = data.get("versions", {})
        libraries = data.get("libraries", {})

        for _alias, lib in libraries.items():
            if not isinstance(lib, dict):
                continue
            module = lib.get("module", "")
            group = lib.get("group", "")
            artifact_name = lib.get("name", "")

            if module:
                name = module
            elif group and artifact_name:
                name = f"{group}:{artifact_name}"
            else:
                continue

            # Resolve version
            version = ""
            ver_spec = lib.get("version", "")
            if isinstance(ver_spec, str):
                version = ver_spec
            elif isinstance(ver_spec, dict):
                ref = ver_spec.get("ref", "")
                if ref and ref in versions:
                    version = str(versions[ref])

            deps.append(BuildFileDependency(
                name=name,
                version=version,
                ecosystem="maven",
                source_file=str(file_path),
                confidence=_CONFIDENCE,
                tier=self.tier,
                detection_method="tomllib-gradle-catalog",
            ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


# ---------------------------------------------------------------------------
# package.json (npm/Node.js)
# ---------------------------------------------------------------------------

#: A dependency range that is not a range but a pointer into the customer's
#: OWN tree. Measured on streamlit and vue-core (16.09.2026): seven resp.
#: eleven of the project's own packages were listed as third-party
#: components, with `workspace:^` standing where a version belongs.
#: `file:` is deliberately NOT in this list — it points at a local path,
#: and that path can just as well be a vendored THIRD-PARTY archive
#: (`file:./vendor/foo-1.2.3.tgz`), which is exactly the kind of component
#: that must not vanish. It is decided separately, by looking.
_OWN_TREE_PROTOCOLS = ("workspace:", "link:", "portal:")


def _is_own_tree(spec: str, manifest: Path) -> bool:
    """True when *spec* points into the customer's own tree, not at a package.

    ``file:`` is the ambiguous one: ``file:../shared-lib`` is a sibling
    package in the same repository, ``file:./vendor/foo-1.2.3.tgz`` is a
    third-party library vendored into the tree — a real component of the
    product. A directory is the own tree; an archive, or anything that
    cannot be resolved, stays in the bill (the cautious direction).
    """
    text = spec.strip()
    if text.startswith(_OWN_TREE_PROTOCOLS):
        return True
    if not text.startswith("file:"):
        return False
    target = text[len("file:"):].strip()
    if not target:
        return False
    try:
        return (manifest.parent / target).resolve().is_dir()
    except OSError:
        return False


class PackageJsonParser:
    """Parse package.json using json module."""

    tier = _TIER
    name = "structured-package-json"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        return file_type == "npm"

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        if file_path.name != "package.json":
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return ScanResult(tier=self.tier, scanner_name=self.name)
        if not isinstance(data, dict):
            # Measured on grpc (16.09.2026): examples/node/package.json holds
            # a STRING. json.loads succeeds and data.get then raised
            # AttributeError.
            logger.warning(
                "Failed to parse %s: top level is %s, not an object",
                file_path, type(data).__name__,
            )
            return ScanResult(tier=self.tier, scanner_name=self.name)

        deps: list[BuildFileDependency] = []
        own_tree = 0
        dep_sections = (
            "dependencies", "devDependencies", "peerDependencies", "optionalDependencies",
        )
        for section in dep_sections:
            section_deps = data.get(section, {})
            if not isinstance(section_deps, dict):
                continue
            for name, version in section_deps.items():
                # The customer's own tree is not a third-party component.
                if isinstance(version, str) and _is_own_tree(version, file_path):
                    own_tree += 1
                    continue
                deps.append(BuildFileDependency(
                    name=name,
                    version=str(version) if isinstance(version, str) else "",
                    ecosystem="npm",
                    source_file=str(file_path),
                    # Section = provenance: devDependencies never ship —
                    # the accept path maps this to scope "excluded".
                    context=section,
                    confidence=_CONFIDENCE,
                    tier=self.tier,
                    detection_method="json-package",
                ))

        if own_tree:
            # Countable: a filter whose effect cannot be seen is where the
            # next rebuild quietly drops a little more.
            logger.info(
                "%s: %d Eintraege zeigen in den eigenen Baum "
                "(workspace/link/portal/file-Verzeichnis) — keine Komponenten",
                file_path, own_tree,
            )

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


# ---------------------------------------------------------------------------
# pom.xml (Maven)
# ---------------------------------------------------------------------------

class PomXmlParser:
    """Parse pom.xml using ElementTree with property resolution."""

    tier = _TIER
    name = "structured-pom-xml"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        return file_type == "maven"

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        if file_path.name != "pom.xml":
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            tree = xmlsafe.parse(file_path)   # no DOCTYPE, no entities
        except Exception:  # noqa: BLE001
            return ScanResult(tier=self.tier, scanner_name=self.name)

        root = tree.getroot()
        # Handle Maven namespace
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        # Collect properties for ${...} resolution
        props: dict[str, str] = {}
        props_el = root.find(f"{ns}properties")
        if props_el is not None:
            for prop in props_el:
                tag = prop.tag.replace(ns, "")
                if prop.text:
                    props[tag] = prop.text.strip()

        # Also add project.version / project.groupId
        version_el = root.find(f"{ns}version")
        if version_el is not None and version_el.text:
            props["project.version"] = version_el.text.strip()
        group_el = root.find(f"{ns}groupId")
        if group_el is not None and group_el.text:
            props["project.groupId"] = group_el.text.strip()

        deps: list[BuildFileDependency] = []

        # Find all <dependency> elements
        for dep_el in root.iter(f"{ns}dependency"):
            gid_el = dep_el.find(f"{ns}groupId")
            aid_el = dep_el.find(f"{ns}artifactId")
            ver_el = dep_el.find(f"{ns}version")

            if aid_el is None or not aid_el.text:
                continue

            raw_gid = gid_el.text.strip() if gid_el is not None and gid_el.text else ""
            group_id = _resolve_props(raw_gid, props)
            artifact_id = aid_el.text.strip()
            raw_ver = ver_el.text.strip() if ver_el is not None and ver_el.text else ""
            version = _resolve_props(raw_ver, props)

            name = f"{group_id}:{artifact_id}" if group_id else artifact_id
            deps.append(BuildFileDependency(
                name=name,
                version=version,
                ecosystem="maven",
                source_file=str(file_path),
                confidence=_CONFIDENCE,
                tier=self.tier,
                detection_method="xml-pom",
            ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


def _resolve_props(text: str, props: dict[str, str]) -> str:
    """Resolve Maven ${property} references."""
    import re
    def replacer(m: re.Match[str]) -> str:
        key = m.group(1)
        return props.get(key, m.group(0))
    return re.sub(r"\$\{([^}]+)\}", replacer, text)


# ---------------------------------------------------------------------------
# go.mod (Go modules)
# ---------------------------------------------------------------------------

class GoModParser:
    """Parse go.mod using line-by-line structured parsing."""

    tier = _TIER
    name = "structured-gomod"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        return file_type == "go"

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        if file_path.name != "go.mod":
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:  # noqa: BLE001
            return ScanResult(tier=self.tier, scanner_name=self.name)

        deps: list[BuildFileDependency] = []
        in_require = False

        for line in content.splitlines():
            stripped = line.strip()

            if stripped.startswith("require ("):
                in_require = True
                continue
            if stripped == ")" and in_require:
                in_require = False
                continue

            # Single-line require
            if stripped.startswith("require ") and "(" not in stripped:
                parts = stripped[len("require "):].strip().split()
                if len(parts) >= 2:
                    deps.append(BuildFileDependency(
                        name=parts[0],
                        version=parts[1],
                        ecosystem="go",
                        source_file=str(file_path),
                        confidence=_CONFIDENCE,
                        tier=self.tier,
                        detection_method="structured-gomod",
                    ))
                continue

            # Inside require block
            if in_require and stripped and not stripped.startswith("//"):
                parts = stripped.split()
                if len(parts) >= 2 and not parts[0].startswith("//"):
                    deps.append(BuildFileDependency(
                        name=parts[0],
                        version=parts[1],
                        ecosystem="go",
                        source_file=str(file_path),
                        confidence=_CONFIDENCE,
                        tier=self.tier,
                        detection_method="structured-gomod",
                    ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


# ---------------------------------------------------------------------------
# conanfile.txt
# ---------------------------------------------------------------------------

class ConanfileTextParser:
    """Parse conanfile.txt [requires] section."""

    tier = _TIER
    name = "structured-conanfile-txt"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        return file_type == "conan"

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        if file_path.name != "conanfile.txt":
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:  # noqa: BLE001
            return ScanResult(tier=self.tier, scanner_name=self.name)

        deps: list[BuildFileDependency] = []
        in_requires = False

        for line in content.splitlines():
            stripped = line.strip()
            if stripped.lower() in ("[requires]", "[tool_requires]"):
                in_requires = True
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                in_requires = False
                continue
            if in_requires and stripped and not stripped.startswith("#"):
                # Format: name/version or name/version@user/channel
                parts = stripped.split("/", 1)
                name = parts[0]
                version = ""
                if len(parts) > 1:
                    version = parts[1].split("@")[0]
                deps.append(BuildFileDependency(
                    name=name,
                    version=version,
                    ecosystem="conan",
                    source_file=str(file_path),
                    confidence=_CONFIDENCE,
                    tier=self.tier,
                    detection_method="structured-conanfile",
                ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


# ---------------------------------------------------------------------------
# meson.build (structured line parsing for dependency() calls)
# ---------------------------------------------------------------------------

class MesonBuildParser:
    """Parse meson.build dependency() calls using structured parsing."""

    tier = _TIER
    name = "structured-meson"

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        return file_type == "meson"

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        if file_path.name != "meson.build":
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:  # noqa: BLE001
            return ScanResult(tier=self.tier, scanner_name=self.name)

        import re
        deps: list[BuildFileDependency] = []

        # Match dependency('name') and dependency('name', version: '...')
        for m in re.finditer(r"dependency\(\s*'([^']+)'", content):
            name = m.group(1)
            # Try to extract version from the same call
            version = ""
            rest = content[m.end():m.end() + 200]
            ver_m = re.search(r"version\s*:\s*'([^']*)'", rest)
            if ver_m and ")" not in rest[:ver_m.start()]:
                version = ver_m.group(1)
            deps.append(BuildFileDependency(
                name=name,
                version=version,
                ecosystem="meson",
                source_file=str(file_path),
                confidence=_CONFIDENCE,
                tier=self.tier,
                detection_method="structured-meson",
            ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


# ---------------------------------------------------------------------------
# build.gradle / build.gradle.kts (Gradle dependency declarations)
# ---------------------------------------------------------------------------

class GradleBuildFileParser:
    """Parse build.gradle(.kts) for dependency declarations.

    Fallback for when gradlew/gradle CLI (Tier 1) is unavailable or fails
    (e.g. Android projects without SDK, missing wrapper, timeout).

    Extracts group:artifact from implementation/api/compileOnly/etc. declarations.
    """

    tier = _TIER
    name = "structured-gradle-build"

    # Gradle dependency configurations to capture
    _CONFIGURATIONS = {
        "implementation", "api", "compileOnly", "runtimeOnly",
        "testImplementation", "testCompileOnly", "testRuntimeOnly",
        "annotationProcessor", "kapt", "ksp",
        "compile", "runtime", "provided",  # legacy configurations
    }

    def can_handle(self, file_type: str, project_path: Path) -> bool:
        return file_type == "gradle"

    def scan(self, file_type: str, file_path: Path, project_path: Path) -> ScanResult:
        if file_path.name not in ("build.gradle", "build.gradle.kts", "dependencies.gradle"):
            return ScanResult(tier=self.tier, scanner_name=self.name)

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:  # noqa: BLE001
            return ScanResult(tier=self.tier, scanner_name=self.name)

        import re
        deps: list[BuildFileDependency] = []
        seen: set[str] = set()

        # Build regex for all configurations
        configs = "|".join(self._CONFIGURATIONS)

        # Pattern 1: Groovy string — implementation 'group:artifact:version'
        # Pattern 2: Groovy GString — implementation "group:artifact:version"
        # Pattern 3: Kotlin DSL — implementation("group:artifact:version")
        pattern = re.compile(
            rf"(?:{configs})"
            r"""\s*[\(]?\s*['"]"""
            r"([a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+)"  # group:artifact
            r"(?::([a-zA-Z0-9._+-]*))?"  # optional :version
            r"""['"]""",
        )

        for m in pattern.finditer(content):
            coord = m.group(1)  # group:artifact
            version = m.group(2) or ""
            if coord not in seen:
                seen.add(coord)
                deps.append(BuildFileDependency(
                    name=coord,
                    version=version,
                    ecosystem="maven",
                    source_file=str(file_path),
                    confidence=_CONFIDENCE,
                    tier=self.tier,
                    detection_method="structured-gradle-build",
                ))

        # Pattern 4: Map notation — implementation group: 'g', name: 'a', version: 'v'
        map_pattern = re.compile(
            rf"(?:{configs})"
            r"""\s+group\s*:\s*['"]([^'"]+)['"]"""
            r"""\s*,\s*name\s*:\s*['"]([^'"]+)['"]"""
            r"""(?:\s*,\s*version\s*:\s*['"]([^'"]+)['"])?""",
        )

        for m in map_pattern.finditer(content):
            group = m.group(1)
            artifact = m.group(2)
            version = m.group(3) or ""
            coord = f"{group}:{artifact}"
            if coord not in seen:
                seen.add(coord)
                deps.append(BuildFileDependency(
                    name=coord,
                    version=version,
                    ecosystem="maven",
                    source_file=str(file_path),
                    confidence=_CONFIDENCE,
                    tier=self.tier,
                    detection_method="structured-gradle-build",
                ))

        return ScanResult(tier=self.tier, scanner_name=self.name, dependencies=deps)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_scanners() -> list[
    CargoTomlParser
    | PyprojectTomlParser
    | GradleCatalogParser
    | GradleBuildFileParser
    | PackageJsonParser
    | PomXmlParser
    | GoModParser
    | ConanfileTextParser
    | MesonBuildParser
]:
    """Return all Tier 2 structured parser instances."""
    return [
        CargoTomlParser(),
        PyprojectTomlParser(),
        GradleCatalogParser(),
        GradleBuildFileParser(),
        PackageJsonParser(),
        PomXmlParser(),
        GoModParser(),
        ConanfileTextParser(),
        MesonBuildParser(),
    ]
