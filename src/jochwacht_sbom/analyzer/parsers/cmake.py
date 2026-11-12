"""Deterministic CMake build-file parser.

Extracts dependency names from CMakeLists.txt and *.cmake files by matching:
- find_package / find_host_package(Name ...)
- include(FindXXX) — CMake module inclusion for dependency search
- FetchContent_Declare(name ...)
- pkg_check_modules / pkg_search_module / ocv_check_modules(VAR name ...)
- set(XXX_PKG_CONFIG_SPEC name) — SDL-style variable-based pkg-config
- find_library(VAR NAMES name ...)
- find_path(VAR NAMES header ...) — header search for libraries
- check_library_exists(lib ...)
- ExternalProject_Add(name ...)
"""

from __future__ import annotations

import re

from jochwacht_sbom.analyzer.parsers.short_libs import short_library
from jochwacht_sbom.analyzer.parsers.system_libs import is_system_library

# --- Regex patterns -----------------------------------------------------------

# find_package(OpenSSL REQUIRED) / find_host_package(CUDA ...) → "OpenSSL" / "CUDA"
_FIND_PACKAGE = re.compile(
    r"find_(?:host_)?package\s*\(\s*(\w+)",
    re.IGNORECASE,
)

# FetchContent_Declare(json GIT_REPOSITORY ...) → "json"
_FETCH_CONTENT = re.compile(
    r"FetchContent_Declare\s*\(\s*(\w+)",
    re.IGNORECASE,
)

# pkg_check_modules(DLT REQUIRED 'automotive-dlt >= 2.11')
# pkg_check_modules(DLT automotive-dlt>=2.11)
# pkg_check_modules(DLT REQUIRED IMPORTED_TARGET automotive-dlt)
# Also: pkg_search_module, ocv_check_modules (OpenCV wrapper)
_PKG_CHECK_MODULES = re.compile(
    r"(?:pkg_(?:check_modules|search_module)|ocv_check_modules)\s*\("
    r"\s*\w+"  # variable name
    r"(?:\s+(?:REQUIRED|QUIET|IMPORTED_TARGET|NO_CMAKE_PATH|NO_CMAKE_ENVIRONMENT_PATH))*"  # flags
    r"\s+['\"]?([a-zA-Z0-9_][a-zA-Z0-9_.+-]*)",  # package name
    re.IGNORECASE,
)

# SDL pattern: set(PipeWire_PKG_CONFIG_SPEC libpipewire-0.3>=0.3.44)
# Also: set(PKG_CONFIG_LIBDRM_SPEC libdrm) — alternate SDL naming convention
# Captures the pkg-config package name from variable-based pkg_check_modules
_SET_PKG_CONFIG_SPEC = re.compile(
    r"set\s*\(\s*(?:\w+_PKG_CONFIG_SPEC|PKG_CONFIG_\w+_SPEC)\s+"
    r"['\"]?([a-zA-Z][a-zA-Z0-9_.+-]*)",
    re.IGNORECASE,
)

# find_library(MICROHTTPD_LIBRARY NAMES microhttpd)
# find_library(MICROHTTPD_LIBRARY microhttpd)
# find_library(VIVANTE_LIBRARY REQUIRED NAMES VIVANTE vivante) — flags before NAMES
_FIND_LIBRARY = re.compile(
    r"find_library\s*\(\s*\w+"  # variable
    r"(?:\s+(?:REQUIRED|QUIET))*"  # optional flags before NAMES
    r"\s+(?:NAMES?\s+)?(\w+)",  # library name
    re.IGNORECASE,
)

# check_library_exists(rt clock_gettime "" HAVE_RT)
_CHECK_LIBRARY = re.compile(
    r"check_library_exists\s*\(\s*(\w+)",
    re.IGNORECASE,
)

# ExternalProject_Add(name ...) → "name"
_EXTERNAL_PROJECT = re.compile(
    r"ExternalProject_Add\s*\(\s*(\w+)",
    re.IGNORECASE,
)

# include(FindJPEG) / include(FindZLIB) — CMake Find-module inclusion
# Captures the library name from "FindXXX" (strips "Find" prefix)
_INCLUDE_FIND = re.compile(
    r"include\s*\(\s*Find(\w+)\s*\)",
    re.IGNORECASE,
)

# include(cmake/cares.cmake) / include(cmake/opentelemetry-cpp.cmake)
# grpc-style: dependency helper modules in cmake/ subdirectory
# Captures the filename stem (without .cmake extension)
_INCLUDE_CMAKE_SUBDIR = re.compile(
    r"include\s*\(\s*cmake/([a-zA-Z][a-zA-Z0-9_+-]*?)\.cmake\s*\)",
    re.IGNORECASE,
)

# find_path(VA_INCLUDE_DIR NAMES va/va.h ...) / find_path(VA_INCLUDE_DIR va/va.h ...)
# Extracts library hint from header path (e.g. va/va.h → va)
_FIND_PATH = re.compile(
    r"find_path\s*\(\s*\w+"  # variable
    r"\s+(?:NAMES?\s+)?([a-zA-Z0-9_]+)/",  # header directory prefix
    re.IGNORECASE,
)

# target_link_libraries(target ... -lfoo -lbar)
_TLL_BLOCK = re.compile(
    r"target_link_libraries\s*\(([^)]+)\)",
    re.IGNORECASE,
)
_DASH_L_FLAG = re.compile(r"-l(\w[\w.+-]*)")  # stdc++ is one name

# --- CMake module → library name mapping --------------------------------------

_CMAKE_MODULE_MAP: dict[str, str] = {
    "Threads": "pthread",
}

# CMake built-in / meta-modules that are not real dependencies
_SKIP_MODULES: set[str] = {
    "PkgConfig",
    "CMakeDependentOption",
    "CheckIncludeFile",
    "CheckIncludeFiles",
    "CheckFunctionExists",
    "CheckLibraryExists",
    "CheckSymbolExists",
    "CheckTypeSize",
    "CheckCSourceCompiles",
    "CheckCXXSourceCompiles",
    "CheckCCompilerFlag",
    "CheckCXXCompilerFlag",
    "CheckStructHasMember",
    "CheckPrototypeDefinition",
    "CheckIPOSupported",
    "CMakePackageConfigHelpers",
    "CMakePushCheckState",
    "CTest",
    "CPack",
    "FetchContent",
    "ExternalProject",
    "GNUInstallDirs",
    "GenerateExportHeader",
    "InstallRequiredSystemLibraries",
    "WriteBasicConfigVersionFile",
    "FeatureSummary",
    "ProcessorCount",
    "FindPackageHandleStandardArgs",
    "FindPackageMessage",
    "TestBigEndian",
    # include(FindXXX) utility modules (not real deps)
    "PackageHandleStandardArgs",
    "PackageMessage",
}

# include(cmake/xxx.cmake) stems that are NOT real dependencies
# (build infrastructure, options, compiler settings, etc.)
_SKIP_CMAKE_INCLUDES: set[str] = {
    "import",  # cmake/Import.cmake: a helper that imports
    "options", "config", "settings", "compiler", "flags", "toolchain",
    "install", "pkg-config", "version", "download", "build",
    "common", "utils", "helpers", "macros", "functions",
}

# Common find_package / find_library flags that should never be treated as deps
_CMAKE_FLAGS: set[str] = {
    "REQUIRED", "QUIET", "IMPORTED_TARGET", "CONFIG", "MODULE",
    "NO_MODULE", "NO_POLICY_SCOPE", "COMPONENTS", "OPTIONAL_COMPONENTS",
    "NAMES", "HINTS", "PATHS", "PATH_SUFFIXES", "DOC", "NO_DEFAULT_PATH",
    "NO_CMAKE_PATH", "NO_CMAKE_ENVIRONMENT_PATH", "NO_SYSTEM_ENVIRONMENT_PATH",
    "NO_CMAKE_SYSTEM_PATH", "NO_CMAKE_PACKAGE_REGISTRY",
    "NAMES_PER_DIR", "NO_CMAKE_FIND_ROOT_PATH",
}


def _strip_comments(content: str) -> str:
    """Remove single-line CMake comments."""
    return re.sub(r"#[^\n]*", "", content)


def parse(content: str) -> list[str]:
    """Extract dependency names from CMakeLists.txt content."""
    content = _strip_comments(content)
    deps: set[str] = set()

    # find_package
    for m in _FIND_PACKAGE.finditer(content):
        name = m.group(1)
        if name in _SKIP_MODULES:
            continue
        deps.add(_CMAKE_MODULE_MAP.get(name, name))

    # FetchContent_Declare
    for m in _FETCH_CONTENT.finditer(content):
        deps.add(m.group(1))

    # pkg_check_modules / pkg_search_module / ocv_check_modules
    for m in _PKG_CHECK_MODULES.finditer(content):
        deps.add(m.group(1))

    # set(XXX_PKG_CONFIG_SPEC name) — SDL-style variable-based pkg-config
    for m in _SET_PKG_CONFIG_SPEC.finditer(content):
        deps.add(m.group(1))

    # include(FindXXX) — CMake module-based dependency search
    for m in _INCLUDE_FIND.finditer(content):
        name = m.group(1)
        if name in _SKIP_MODULES:
            continue
        deps.add(_CMAKE_MODULE_MAP.get(name, name))

    # include(cmake/xxx.cmake) — grpc-style dependency helper modules
    for m in _INCLUDE_CMAKE_SUBDIR.finditer(content):
        name = m.group(1)
        if name.lower() in _SKIP_CMAKE_INCLUDES:
            continue
        # An "…_import" helper IMPORTS a dependency, it is not one itself
        # (cmake/pico_sdk_import.cmake became the component
        # "pico_sdk_import" — the real dep, pico_sdk, is found inside it).
        if name.lower().endswith(("_import", "-import")):
            continue
        deps.add(name)

    # find_path — header search (extracts directory prefix as library name)
    for m in _FIND_PATH.finditer(content):
        name = m.group(1)
        # Skip generic paths and cmake flags
        if name.lower() in ("include", "src", "lib", "usr", "opt", "sys"):
            continue
        if name.upper() in _CMAKE_FLAGS:
            continue
        deps.add(name)

    # find_library
    for m in _FIND_LIBRARY.finditer(content):
        name = m.group(1)
        if name.upper() in _CMAKE_FLAGS:
            continue
        deps.add(name)

    # check_library_exists
    for m in _CHECK_LIBRARY.finditer(content):
        deps.add(m.group(1))

    # ExternalProject_Add
    for m in _EXTERNAL_PROJECT.finditer(content):
        deps.add(m.group(1))

    # target_link_libraries -l flags
    for m in _TLL_BLOCK.finditer(content):
        block = m.group(1)
        for flag in _DASH_L_FLAG.finditer(block):
            name = short_library(flag.group(1)) or flag.group(1)
            # the C library and compiler runtime are no component
            if len(name) > 2 and not is_system_library(name):
                deps.add(name)

    return sorted(deps)


# ---------------------------------------------------------------------------
# FetchContent_Declare with version (GIT_TAG or the archive in URL)
# ---------------------------------------------------------------------------

_FETCH_START = re.compile(r"\bFetchContent_Declare\s*\(", re.IGNORECASE)
_ARCHIVE_EXT = re.compile(r"\.(tar\.gz|tar\.xz|tar\.bz2|tar\.zst|tgz|txz|tbz2|zip|tar)\Z",
                          re.IGNORECASE)
#: The version at the end of an archive name: "v1.7.17", "zlib-1.3.1",
#: "libfoo_2.0.5", "y-3.1" — the separator or a "v" before it, nothing after.
_ARCHIVE_VERSION = re.compile(
    r"(?:^|[-_v])v?([0-9]+(?:\.[0-9]+)+(?:[-+.]?(?:rc|alpha|beta|pre|post|p)\.?[0-9]+)?)\Z",
    re.IGNORECASE,
)


class FetchDeclaration:
    """One ``FetchContent_Declare``: name, version (or ""), and what stood
    instead of a version (``branch:<name>`` for a GIT_TAG that is a branch)."""

    __slots__ = ("declared_range", "name", "version")

    def __init__(self, name: str, version: str = "", declared_range: str = "") -> None:
        self.name = name
        self.version = version
        self.declared_range = declared_range

    def __repr__(self) -> str:
        return f"FetchDeclaration({self.name!r}, {self.version!r}, {self.declared_range!r})"


#: Longest argument list of one declaration we read; a longer one (or one
#: without its ")") ends the reading (an open declaration
#: made every later one read to the end of the file, quadratic).
_MAX_BLOCK = 16 * 1024


def _block(content: str, start: int) -> str | None:
    """The arguments from *start* (after "(") to the matching ")", or None
    when there is no ")" within _MAX_BLOCK characters."""
    depth, i, quoted = 1, start, False
    end_at = min(len(content), start + _MAX_BLOCK)
    while i < end_at:
        ch = content[i]
        if ch == '"' and content[i - 1] != "\\":
            quoted = not quoted
        elif not quoted and ch == "(":
            depth += 1
        elif not quoted and ch == ")":
            depth -= 1
            if depth == 0:
                return content[start:i]
        i += 1
    return None


def _version_from_url(url: str) -> str:
    last = url.split("?", 1)[0].split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    stem = _ARCHIVE_EXT.sub("", last)
    m = _ARCHIVE_VERSION.search(stem)
    return m.group(1) if m else ""


def fetch_content_declarations(content: str) -> list[FetchDeclaration]:
    """Every ``FetchContent_Declare(name …)`` in *content*, each read only
    up to its own closing parenthesis. The version is the ``GIT_TAG`` when
    it pins (a tag or commit), else the version in the ``URL`` archive name;
    a branch in ``GIT_TAG`` gives no version and ``branch:<name>``. An
    unexpanded ``${…}`` is no version."""
    from jochwacht_sbom.core.revisions import is_pinned_revision
    from jochwacht_sbom.sbom.project_identity import cmake_code

    # Comments go first: a commented-out declaration is no component.
    content = cmake_code(content, keep_strings=True)
    out: list[FetchDeclaration] = []
    for m in _FETCH_START.finditer(content):
        block = _block(content, m.end())
        if block is None:
            # An open declaration: nothing after it is reliable. Named, never
            # silent.
            head = content[m.end():m.end() + 60].split()
            from jochwacht_sbom.core.log import get_logger

            get_logger(__name__).warning(
                "FetchContent_Declare(%s …) has no closing parenthesis within %d "
                "characters; the declarations after it are not read",
                head[0] if head else "?", _MAX_BLOCK)
            break
        args = [a.strip('"') for a in block.split()]
        if not args or not re.fullmatch(r"[A-Za-z0-9_.+-]+", args[0]):
            continue
        name = args[0]
        opts: dict[str, str] = {}
        for key, value in zip(args[1:], args[2:], strict=False):
            if key.upper() in ("GIT_TAG", "URL") and key.upper() not in opts:
                opts[key.upper()] = value
        tag = opts.get("GIT_TAG", "")
        version, declared = "", ""
        if tag and "${" not in tag:
            if is_pinned_revision(tag):
                version = tag
            else:
                declared = f"branch:{tag}"
        if not version and not declared and "URL" in opts and "${" not in opts["URL"]:
            version = _version_from_url(opts["URL"])
        out.append(FetchDeclaration(name, version, declared))
    return out



# ---------------------------------------------------------------------------
# Libraries named by their bare name in target_link_libraries/link_libraries
# ---------------------------------------------------------------------------
# Measured 12.11.2026: only -l in
# target_link_libraries was read; "target_link_libraries(fw z pq curl)",
# link_libraries and ${LIBS} from set()/list(APPEND) gave nothing.

# add_library/add_executable and wrappers such as qt_add_executable,
# pico_add_library: the first argument is one of the project's own targets
_TARGET_DEF = re.compile(r"\b\w*add_(?:library|executable)\s*\(\s*([^\s)]+)", re.IGNORECASE)
_PROJECT = re.compile(r"\bproject\s*\(\s*([A-Za-z0-9_.+-]+)", re.IGNORECASE)
_LINK_CALL = re.compile(r"\b(target_link_libraries|link_libraries)\s*\(([^)]*)\)", re.IGNORECASE)
_SET_CALL = re.compile(r"\bset\s*\(\s*(\w+)([^)]*)\)", re.IGNORECASE)
_LIST_APPEND = re.compile(r"\blist\s*\(\s*APPEND\s+(\w+)([^)]*)\)", re.IGNORECASE)
_ARG = re.compile(r'"[^"]*"|[^\s"]+')
_VAR_ONLY = re.compile(r"\$\{(\w+)\}")
_LINK_KEYWORDS = frozenset({
    "PRIVATE", "PUBLIC", "INTERFACE", "LINK_PRIVATE", "LINK_PUBLIC",
    "LINK_INTERFACE_LIBRARIES", "general", "optimized",
})
_LIBRARY_FILE = re.compile(
    r".*\.(?:a|la|lib|dll|dylib|framework|so(?:\.[0-9.]+)?)\Z", re.IGNORECASE)
_LINK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]*\Z")
_FUNCTION_EDGE = re.compile(r"\b(function|macro|endfunction|endmacro)\s*\(", re.IGNORECASE)
_SET_FIRST = re.compile(r"\bset\s*\(\s*(\w+)\s+([^)]*)\)", re.IGNORECASE)
_VAR_REF = re.compile(r"\$\{(\w+)\}")
_TARGET_CALL = re.compile(r"\b(\w+)\s*\(([^()]*)\)", re.IGNORECASE)
_INCLUDE_ANY = re.compile(r"\binclude\s*\(\s*([^\s)]+)", re.IGNORECASE)
_TARGET_COMMAND = re.compile(r"\w*add_(?:library|executable)", re.IGNORECASE)
_SDK_EVIDENCE = {
    "pico": re.compile(r"\bpico_sdk_init\s*\(|pico_sdk_import", re.IGNORECASE),
    # find_package(Zephyr) in an application; zephyr_library() and the like
    # in a Zephyr module (civetweb)
    "zephyr": re.compile(
        r"\bfind_package\s*\(\s*Zephyr\b|\bzephyr_(?:library\w*|interface_library_named)\s*\(",
        re.IGNORECASE),
}
#: Target prefixes of an SDK: skipped only when the project uses the SDK
#: otherwise they pass on like any name.
_SDK_PREFIXES = {
    "pico": re.compile(r"(?:pico|hardware|boot|tinyusb|cmsis)_", re.IGNORECASE),
    "zephyr": re.compile(r"zephyr_", re.IGNORECASE),
}
#: A variant a project gives a library target: cut, the base name passes on
#: (libzstd_static is zstd, zlibstatic is zlib, uv_a is uv).
_VARIANT_SUFFIX = re.compile(
    r"(?:[_-](?:static|shared|objects|obj|interface|a)|(?<=[a-z])static)\Z", re.IGNORECASE)

#: Ceilings of the resolution. Measured 12.11.2026 on 50
#: projects with the scope of a variable (its folder and the parents): one
#: add_library/add_executable produced at most 3 names (FreeRDP
#: ${MODULE_NAME}); the variables with many values are source lists
#: (libuv uv_test_sources 193, nghttp2 APIDOCS 149) that never name a
#: target. No project reached a ceiling; the slowest took 0.23 s (FreeRDP).
#: Above the ceiling the variable or the call yields no own target: a
#: component too many, never one lost, and the run never hangs. Every such
#: case is counted (CMakeProject.capped, logged as cmake_resolution_capped).
MAX_VALUES_PER_VARIABLE = 64
MAX_NAMES_PER_CALL = 256
_MAX_LEVELS = 3


def _args(text: str) -> list[str]:
    return [a[1:-1] if a.startswith('"') else a for a in _ARG.findall(text)]


def _folder(rel: str) -> str:
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


def _ancestors(folder: str) -> list[str]:
    """The folder itself and every parent up to the root, nearest first."""
    out = [folder]
    while folder:
        folder = _folder(folder)
        out.append(folder)
    return out


class CMakeProject:
    """The CMake files of a project, read once: its own targets, the SDKs it
    uses, the variables each folder sees, and how often a ceiling was hit."""

    def __init__(self) -> None:
        self.targets: frozenset[str] = frozenset()
        self.sdks: frozenset[str] = frozenset()
        self.capped = 0
        # folder → variable → values set in that folder's files (one level)
        self._values: dict[str, dict[str, list[str]]] = {}
        # folder → project() name set in that folder
        self._projects: dict[str, str] = {}

    @classmethod
    def from_files(cls, files: dict[str, str]) -> CMakeProject:
        """*files*: path relative to the project root → content."""
        project = cls()
        texts = {rel.replace("\\", "/"): _strip_comments(text) for rel, text in files.items()}
        for rel, text in sorted(texts.items()):
            folder = _folder(rel)
            values = project._values.setdefault(folder, {})
            for m in _SET_FIRST.finditer(text):
                for item in _args(m.group(2)):
                    if item in ("CACHE", "PARENT_SCOPE"):
                        break
                    values.setdefault(m.group(1), []).append(item)
            for m in _LIST_APPEND.finditer(text):
                for item in _args(m.group(2)):
                    values.setdefault(m.group(1), []).append(item)
            name = _PROJECT.search(text)
            if name and folder not in project._projects:
                project._projects[folder] = name.group(1)
        project.sdks = frozenset(
            sdk for sdk, evidence in _SDK_EVIDENCE.items()
            if any(evidence.search(t) for t in texts.values()))
        wrappers = project._wrappers(texts)
        project.targets = project._own_targets(texts, wrappers)
        return project

    # -- variables, scoped ------------------------------------------------------

    def _visible(self, folder: str) -> dict[str, list[str]]:
        """Values a file in *folder* sees: its folder and the parents."""
        seen: dict[str, list[str]] = {}
        for f in reversed(_ancestors(folder)):
            for var, vals in self._values.get(f, {}).items():
                seen.setdefault(var, []).extend(vals)
        return seen

    def inherited(self, rel: str) -> dict[str, list[str]]:
        """Values of set()/list(APPEND) a file sees from its parent folders
        (for ${VAR} in target_link_libraries; the file's own come on top)."""
        folder = _folder(rel.replace("\\", "/"))
        seen: dict[str, list[str]] = {}
        for f in reversed(_ancestors(folder)):
            for var, vals in self._values.get(f, {}).items():
                seen.setdefault(var, []).extend(vals)
        return {v: vals for v, vals in seen.items() if len(set(vals)) <= MAX_VALUES_PER_VARIABLE}

    def _project_name(self, folder: str) -> str:
        for f in _ancestors(folder):
            if f in self._projects:
                return self._projects[f]
        return ""

    def _expand(self, name: str, variables: dict[str, list[str]]) -> set[str] | None:
        """Every name *name* can take; None at a ceiling (counted)."""
        results = {name}
        for _ in range(_MAX_LEVELS):
            if not any("${" in r for r in results):
                break
            nxt: set[str] = set()
            for r in results:
                m = _VAR_REF.search(r)
                if not m:
                    nxt.add(r)
                    continue
                values = set(variables.get(m.group(1), ()))
                if len(values) > MAX_VALUES_PER_VARIABLE:
                    self.capped += 1
                    return None
                for value in values:
                    nxt.add(r[:m.start()] + value + r[m.end():])
                    if len(nxt) > MAX_NAMES_PER_CALL:
                        self.capped += 1
                        return None
            results = nxt
        return {r for r in results if "$" not in r}

    # -- targets ----------------------------------------------------------------

    @staticmethod
    def _wrappers(texts: dict[str, str]) -> dict[str, bool]:
        """Functions and macros that pass their first parameter to
        add_library/add_executable, directly, through a local set(x
        ${param}) (FreeRDP AddTargetWithResourceFile) or through another
        such function (mosquitto add_mosquitto_plugin): name → True when
        that target is own, False when it is IMPORTED (an import helper).
        One pass over the function/endfunction marks, linear also without
        an end; the chain of wrappers is followed until nothing changes."""
        bodies: list[tuple[str, set[str], str]] = []
        for text in texts.values():
            edges = list(_FUNCTION_EDGE.finditer(text))
            for i, edge in enumerate(edges):
                if edge.group(1).lower() not in ("function", "macro"):
                    continue
                end = edges[i + 1].start() if i + 1 < len(edges) else len(text)
                close = text.find(")", edge.end(), end)
                params = _args(text[edge.end():close if close != -1 else end])
                if not params:
                    continue
                body = text[close + 1 if close != -1 else end:end]
                refs = {"${ARGV0}"} | ({f"${{{params[1]}}}"} if len(params) > 1 else set())
                for m in _SET_FIRST.finditer(body):
                    if _args(m.group(2))[:1] and _args(m.group(2))[0] in refs:
                        refs.add(f"${{{m.group(1)}}}")
                bodies.append((params[0].lower(), refs, body))
        found: dict[str, bool] = {}
        # callee → the wrappers that pass their target name on to it
        waiting: dict[str, list[str]] = {}
        for name, refs, body in bodies:
            for m in _TARGET_CALL.finditer(body):
                args = _args(m.group(2))
                if not args or args[0] not in refs:
                    continue
                command = m.group(1).lower()
                if _TARGET_COMMAND.fullmatch(command):
                    found.setdefault(name, "IMPORTED" not in args)
                else:
                    waiting.setdefault(command, []).append(name)
        todo = list(found)
        while todo:  # each wrapper is settled once: linear in the calls
            callee = todo.pop()
            for caller in waiting.pop(callee, ()):
                if caller not in found:
                    found[caller] = found[callee]
                    todo.append(caller)
        return found

    @staticmethod
    def _includers(texts: dict[str, str]) -> dict[str, set[str]]:
        """included file → the folders of the files that include() it: an
        included file runs in the scope of its includer (micropython
        py/mkrules.cmake with MICROPY_TARGET of the port)."""
        by_name: dict[str, list[str]] = {}
        for rel in texts:
            by_name.setdefault(rel.rsplit("/", 1)[-1].lower(), []).append(rel)
        out: dict[str, set[str]] = {}
        for rel, text in texts.items():
            folder = _folder(rel)
            for m in _INCLUDE_ANY.finditer(text):
                arg = _VAR_REF.sub("", m.group(1).strip('"')).lstrip("/")
                if not arg.endswith(".cmake"):
                    arg += ".cmake"
                parts: list[str] = [p for p in folder.split("/") if p]
                for piece in arg.split("/"):
                    if piece == "..":
                        if parts:
                            parts.pop()
                    elif piece not in ("", "."):
                        parts.append(piece)
                target = "/".join(parts)
                if target not in texts:
                    candidates = by_name.get(arg.rsplit("/", 1)[-1].lower(), [])
                    target = candidates[0] if len(candidates) == 1 else ""
                if target:
                    out.setdefault(target, set()).add(folder)
        return out

    def _own_targets(self, texts: dict[str, str], wrappers: dict[str, bool]) -> frozenset[str]:
        own: set[str] = set()
        aliases: list[tuple[set[str], set[str]]] = []
        includers = self._includers(texts)
        for rel, text in sorted(texts.items()):
            folder = _folder(rel)
            scopes = [folder, *sorted(includers.get(rel, ()))]
            variables: dict[str, list[str]] = {}
            for scope in scopes:
                for var, vals in self._visible(scope).items():
                    variables.setdefault(var, []).extend(vals)
            variables["PROJECT_NAME"] = sorted(
                {self._project_name(f) for f in scopes} - {""})
            for m in _TARGET_CALL.finditer(text):
                command = m.group(1).lower()
                is_def = _TARGET_COMMAND.fullmatch(command) is not None
                if not is_def and command not in wrappers:
                    continue
                args = _args(m.group(2))
                if not args:
                    continue
                names = self._expand(args[0], variables)
                if not names:
                    continue
                if is_def and "IMPORTED" in args:
                    continue  # a dependency
                if not is_def and not wrappers[command]:
                    continue  # an import helper
                if is_def and len(args) >= 3 and args[1] == "ALIAS":
                    aliases.append((names, self._expand(args[2], variables) or set()))
                    continue
                own |= names
        for names, of in aliases:
            if of and of <= own:
                own |= names
        return frozenset(own)


def project_targets(contents: list[str]) -> frozenset[str]:
    """The own targets of files that all lie in the project root."""
    return CMakeProject.from_files(
        {f"f{i}.cmake": c for i, c in enumerate(contents)}).targets


def defined_targets(content: str) -> set[str]:
    """The targets one CMake file defines (see :class:`CMakeProject`)."""
    return set(project_targets([content]))


def _variables(content: str) -> dict[str, list[str]]:
    """set()/list(APPEND) values of this file, one level: a value that is
    itself a variable stays unresolved."""
    values: dict[str, list[str]] = {}
    for pattern in (_SET_CALL, _LIST_APPEND):
        for m in pattern.finditer(content):
            items = []
            for arg in _args(m.group(2)):
                if arg in ("CACHE", "PARENT_SCOPE"):
                    break
                if "${" not in arg:
                    items.append(arg)
            values.setdefault(m.group(1), []).extend(items)
    return values


def _skip_sdk(name: str, sdks: frozenset[str]) -> bool:
    return any(_SDK_PREFIXES[sdk].match(name) for sdk in sdks)


def link_names(
    content: str,
    own_targets: frozenset[str] | set[str] = frozenset(),
    *,
    inherited: dict[str, list[str]] | None = None,
    sdks: frozenset[str] = frozenset(),
) -> list[str]:
    """Libraries a CMake file links by name: bare names, -l flags and
    ${VAR} set in the same file or a parent folder (*inherited*), in
    target_link_libraries (after the target) and link_libraries. Never the
    project's own targets, an imported target (Name::Name, read through
    find_package), a path or library file, a generator expression, a flag,
    a debug-only variant, a system library or a name under three
    characters outside short_libs. A variant suffix (_static) is cut and
    the base name judged; an SDK target only when the project uses the SDK."""
    content = _strip_comments(content)
    variables = dict(inherited or {})
    for var, vals in _variables(content).items():
        variables.setdefault(var, []).extend(vals)
    deps: set[str] = set()
    for m in _LINK_CALL.finditer(content):
        args = _args(m.group(2))
        if m.group(1).lower() == "target_link_libraries":
            args = args[1:]
        expanded: list[str] = []
        for arg in args:
            ref = _VAR_ONLY.fullmatch(arg)
            values = variables.get(ref.group(1)) if ref else None
            if ref and values is not None and len(set(values)) <= MAX_VALUES_PER_VARIABLE:
                expanded.extend(v for v in values if "${" not in v)
            else:
                expanded.append(arg)
        skip_next = False
        for arg in expanded:
            if skip_next:
                skip_next = False
                continue
            if arg in ("debug", "-framework"):
                skip_next = True
                continue
            if (arg in _LINK_KEYWORDS or "$" in arg or "::" in arg or "/" in arg
                    or "\\" in arg or _LIBRARY_FILE.match(arg)):
                continue
            if arg.startswith("-"):
                if not arg.startswith("-l"):
                    continue
                arg = arg[2:]
            if arg in own_targets or not _LINK_NAME.match(arg) or _skip_sdk(arg, sdks):
                continue
            base = _VARIANT_SUFFIX.sub("", arg)
            if base != arg and (not base or base in own_targets):
                continue
            name = short_library(base) or base
            if len(name) > 2 and not is_system_library(name) and not is_system_library(
                    name.lower()):
                deps.add(name)
    return sorted(deps)
