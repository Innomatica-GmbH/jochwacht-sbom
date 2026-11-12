"""Branch-, option- and cache-aware CMake ``find_package`` analysis.

A ``find_package()`` is not automatically a component of the product. In a
C/C++ project with selectable backends the call sits inside an ``if`` branch
guarded by an ``option()``::

    option(PAHO_WITH_SSL      "..." FALSE)
    option(PAHO_WITH_LIBRESSL "..." FALSE)
    ...
    if(PAHO_WITH_SSL OR PAHO_WITH_LIBRESSL)
      if(PAHO_WITH_LIBRESSL)
        find_package(LibreSSL REQUIRED)   # only with -DPAHO_WITH_LIBRESSL=ON
      else()
        find_package(OpenSSL REQUIRED)    # only with -DPAHO_WITH_SSL=ON
      endif()
    endif()

The two are **alternatives** — no build contains both — and with both options
FALSE the default build contains *neither*. A flat regex over the file reports
both as present; that invents content.

This module reads the whole project (options live in the ROOT ``CMakeLists.txt``,
the ``find_package`` in ``src/CMakeLists.txt``) plus a ``CMakeCache.txt`` when
one exists, and classifies each ``find_package`` into three states:

- ``present``      — unconditional, or the guarding condition is true given the
  option defaults / cache. This is a real component (``confirmed``).
- ``conditional``  — behind an ``option()`` that is off by default and no cache
  decides it. An alternative, surfaced with its condition — never ``confirmed``.
- ``absent``       — a ``CMakeCache.txt`` decides the build and this branch is
  not taken. Dropped, not guessed.

Nothing is read from ``Find*.cmake`` module files — those *search* for a
dependency, they are not a declaration (same class as Befund 34).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from jochwacht_sbom.core.file_limit import MAX_BUILD_FILE, note_skipped, too_large
from jochwacht_sbom.core.log import get_logger

logger = get_logger(__name__)

# --- CMake truthiness ---------------------------------------------------------

#: Constants CMake treats as false in an ``if()`` (case-insensitive), plus the
#: empty string and the ``*-NOTFOUND`` suffix handled separately.
_FALSE_CONSTANTS: frozenset[str] = frozenset({
    "off", "no", "false", "n", "ignore", "notfound", "0", "",
})
#: Constants CMake treats as true.
_TRUE_CONSTANTS: frozenset[str] = frozenset({
    "on", "yes", "true", "y", "1",
})

#: ``if()`` operators this evaluator does not model — their presence makes the
#: whole expression undecidable (returns ``None``), never a false verdict.
_UNSUPPORTED_OPS: frozenset[str] = frozenset({
    "strequal", "equal", "less", "greater", "less_equal", "greater_equal",
    "version_less", "version_greater", "version_equal",
    "version_less_equal", "version_greater_equal",
    "matches", "defined", "exists", "command", "policy", "in_list",
    "path_equal", "is_directory", "is_absolute", "is_symlink", "is_newer_than",
})


def _const_truthiness(token: str) -> bool | None:
    """Truthiness of a bare CMake constant, or ``None`` if it is not one."""
    low = token.lower()
    if low in _TRUE_CONSTANTS:
        return True
    if low in _FALSE_CONSTANTS:
        return False
    if low.endswith("-notfound"):
        return False
    # A non-zero number is true; zero is false.
    if re.fullmatch(r"-?\d+", token):
        return token not in ("0", "-0")
    return None


@dataclass
class CMakeContext:
    """Project-wide option defaults and (optional) cache values."""

    #: option name → resolved default truthiness (only clearly-boolean defaults).
    options: dict[str, bool] = field(default_factory=dict)
    #: CMakeCache.txt variable → raw value (decides the build when present).
    cache: dict[str, str] = field(default_factory=dict)
    #: True when at least one CMakeCache.txt was found — the build is decided.
    has_cache: bool = False
    #: Find modules in the project tree that only locate a PROGRAM
    #: (find_program, no find_library/find_path/pkg_check): their
    #: find_package() names are tooling, never product components
    #: (lws' FindOpenSSLbins.cmake finds the openssl BINARY).
    program_modules: set[str] = field(default_factory=set)
    #: resolved child dir → (resolved parent dir, guard atoms) — a subdirectory
    #: added under ``if(LWS_WITH_MBEDTLS) add_subdirectory(mbedtls)`` inherits
    #: that guard, and so does every find_library inside it.
    added_by: dict[str, tuple[str, list[tuple[bool, str]]]] = field(
        default_factory=dict,
    )

    def inherited_atoms(self, dir_str: str) -> list[_Atom]:
        """Guard atoms a directory inherits from the add_subdirectory chain."""
        atoms: list[_Atom] = []
        cur = dir_str
        seen: set[str] = set()
        while cur in self.added_by and cur not in seen:
            seen.add(cur)
            parent, tuples = self.added_by[cur]
            atoms = [_Atom(neg, expr) for neg, expr in tuples] + atoms
            cur = parent
        return atoms

    def known(self, name: str) -> bool:
        """Is *name* a variable this context can resolve (cache or option)?"""
        return name in self.cache or name in self.options

    def value(self, name: str) -> bool | None:
        """Truthiness of a variable: cache wins over option default; else None."""
        if name in self.cache:
            return _const_truthiness(self.cache[name])
        if name in self.options:
            return self.options[name]
        return None


@dataclass
class FindPackageHit:
    """One ``find_package`` occurrence with its resolved branch state."""

    name: str
    version: str
    state: str      # "present" | "conditional" | "absent"
    condition: str  # human-readable guard, "" when unconditional / present


#: A dotted version anywhere in a string (``3.0.13``, ``v1.2``, ``3.0.13()``).
_VERSION_IN = re.compile(r"v?(\d+(?:\.\d+)+[A-Za-z0-9.\-]*?)(?:\(|\s|$|\])")
#: A version embedded in a shared-object name (``libcrypto.so.3.0.2``).
_SO_VERSION = re.compile(r"\.so\.(\d+(?:\.\d+)*)")


def version_from_cache(name: str, ctx: CMakeContext) -> str:
    """Best resolved version for a configured ``find_package(NAME)`` package.

    The configured build already found the library; its version is a fact of
    the build machine recorded in the cache. Sources, in order of
    trust: an explicit ``<NAME>_VERSION`` variable, the pkg-config
    ``_<NAME>_VERSION``, CMake's own ``FIND_PACKAGE_MESSAGE_DETAILS_<Name>``
    record, and last the resolved library path (``libcrypto.so.3.0.2``).
    Empty when even the build does not know — an honest unknown, not a guess.
    """
    base = name.upper()
    for key in (f"{base}_VERSION", f"{base}_VERSION_STRING", f"_{base}_VERSION"):
        raw = ctx.cache.get(key, "").strip()
        if raw:
            m = _VERSION_IN.match(raw) or _VERSION_IN.search(raw)
            if m:
                return m.group(1)
    detail = ctx.cache.get(f"FIND_PACKAGE_MESSAGE_DETAILS_{name}", "")
    if detail:
        # Format: ``[lib][include][flags][v3.0.13()]`` — take the v-token.
        m = re.search(r"\[v?(\d+(?:\.\d+)+)", detail)
        if m:
            return m.group(1)
    # Resolved library FILEPATH → version in the .so name, if any.
    for key, val in ctx.cache.items():
        ku = key.upper()
        if ku.startswith(base) and ("LIBRARY" in ku or "LIBRARIES" in ku):
            m = _SO_VERSION.search(val)
            if m:
                return m.group(1)
    return ""


# --- Command tokenizer (balanced parentheses) ---------------------------------

_COMMAND = re.compile(
    r"\b(if|elseif|else|endif|find_package|find_host_package|find_library|"
    r"find_path|pkg_check_modules|pkg_search_module|ocv_check_modules|"
    r"check_library_exists|add_subdirectory)\s*\(",
    re.IGNORECASE,
)

#: Dep-producing commands (everything but the control-flow keywords).
_DEP_COMMANDS: frozenset[str] = frozenset({
    "find_package", "find_host_package", "find_library", "find_path",
    "pkg_check_modules", "pkg_search_module", "ocv_check_modules",
    "check_library_exists",
})


def _strip_comments(content: str) -> str:
    """Remove ``#`` line comments (bracket comments are rare — left intact)."""
    return re.sub(r"#[^\n]*", "", content)


def _extract_args(content: str, open_paren: int) -> tuple[str, int]:
    """Return (argument text, index past the matching ``)``)."""
    depth = 0
    i = open_paren
    n = len(content)
    while i < n:
        c = content[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return content[open_paren + 1:i], i + 1
        i += 1
    return content[open_paren + 1:], n


def _iter_commands(content: str) -> list[tuple[str, str]]:
    """Yield ``(command_lower, args_text)`` in source order."""
    out: list[tuple[str, str]] = []
    pos = 0
    for m in _COMMAND.finditer(content):
        if m.start() < pos:
            continue  # inside a previous command's arguments
        args, end = _extract_args(content, m.end() - 1)
        out.append((m.group(1).lower(), args))
        pos = end
    return out


# --- Boolean expression evaluator (three-valued / Kleene) ---------------------

_EXPR_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def _tokenize_expr(expr: str) -> list[str]:
    return _EXPR_TOKEN.findall(expr)


def _clean_var(token: str) -> str:
    """Strip a ``${...}`` wrapper and surrounding quotes from a variable token."""
    t = token.strip().strip('"')
    m = re.fullmatch(r"\$\{(.+)\}", t)
    return m.group(1) if m else t


class _UndecidableError(Exception):
    """Raised when an expression uses an operator we do not model."""


def _eval_tokens(tokens: list[str], ctx: CMakeContext) -> bool | None:
    """Kleene-evaluate a CMake boolean token list. ``None`` = undecidable."""
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def kleene_or(a: bool | None, b: bool | None) -> bool | None:
        if a is True or b is True:
            return True
        if a is False and b is False:
            return False
        return None

    def kleene_and(a: bool | None, b: bool | None) -> bool | None:
        if a is False or b is False:
            return False
        if a is True and b is True:
            return True
        return None

    def parse_or() -> bool | None:
        nonlocal pos
        val = parse_and()
        while (tok := peek()) is not None and tok.lower() == "or":
            pos += 1
            val = kleene_or(val, parse_and())
        return val

    def parse_and() -> bool | None:
        nonlocal pos
        val = parse_not()
        while (tok := peek()) is not None and tok.lower() == "and":
            pos += 1
            val = kleene_and(val, parse_not())
        return val

    def parse_not() -> bool | None:
        nonlocal pos
        tok = peek()
        if tok is not None and tok.lower() == "not":
            pos += 1
            inner = parse_not()
            return None if inner is None else (not inner)
        return parse_primary()

    def parse_primary() -> bool | None:
        nonlocal pos
        tok = peek()
        if tok is None:
            return None
        if tok == "(":
            pos += 1
            val = parse_or()
            if peek() == ")":
                pos += 1
            return val
        if tok == ")":
            return None
        if tok.lower() in _UNSUPPORTED_OPS:
            raise _UndecidableError
        pos += 1
        # A binary operator immediately after an operand → undecidable.
        nxt = peek()
        if nxt is not None and nxt.lower() in _UNSUPPORTED_OPS:
            raise _UndecidableError
        const = _const_truthiness(tok)
        if const is not None:
            return const
        return ctx.value(_clean_var(tok))

    try:
        return parse_or()
    except _UndecidableError:
        return None


@dataclass
class _Atom:
    """One guard term on a branch path: an expression, possibly negated."""

    negate: bool
    expr: str

    def evaluate(self, ctx: CMakeContext) -> bool | None:
        val = _eval_tokens(_tokenize_expr(self.expr), ctx)
        if val is None:
            return None
        return (not val) if self.negate else val

    def mentions_known(self, ctx: CMakeContext) -> bool:
        return any(
            ctx.known(_clean_var(t))
            for t in _tokenize_expr(self.expr)
            if t not in ("(", ")") and t.lower() not in ("and", "or", "not")
        )

    def render(self) -> str:
        expr = self.expr.strip()
        body = f"({expr})" if re.search(r"\s", expr) else expr
        return f"NOT {body}" if self.negate else body


@dataclass
class _Frame:
    """An open ``if``/``elseif``/``else`` block during the walk."""

    #: Expressions of the ``if`` + every ``elseif`` seen so far.
    seen: list[str]
    #: Atoms describing the branch currently in effect.
    current: list[_Atom]


def _branch_atoms(stack: list[_Frame]) -> list[_Atom]:
    atoms: list[_Atom] = []
    for frame in stack:
        atoms.extend(frame.current)
    return atoms


def _classify(atoms: list[_Atom], ctx: CMakeContext) -> tuple[str, str]:
    """Return (state, condition_text) for a find_package under *atoms*."""
    if not atoms:
        return "present", ""

    # Kleene conjunction over the branch path.
    taken: bool | None = True
    for atom in atoms:
        v = atom.evaluate(ctx)
        if v is False:
            taken = False
            break
        if v is None:
            taken = None

    condition = "nur bei: " + " und ".join(a.render() for a in atoms)

    if ctx.has_cache:
        # The build is decided by the cache.
        if taken is False:
            return "absent", condition
        # True or undecidable → keep (never drop what we cannot disprove).
        return "present", ""

    # No cache: an option toggle that is off by default is an alternative.
    involves_option = any(a.mentions_known(ctx) for a in atoms)
    if taken is False and involves_option:
        return "conditional", condition
    return "present", ""


# --- find_package name filtering ---------------------------------------------

#: CMake built-in modules never treated as product dependencies (mirrors the
#: skip list of the standalone scanner).
_SKIP_FIND: frozenset[str] = frozenset({
    "Threads", "PkgConfig", "Python", "Python2", "Python3",
    "GTest", "Doxygen",
})

_FIND_ARG_NAME = re.compile(r"^\s*(\w+)(?:\s+(\d[\w._-]*))?")
# The following mirror analyzer/parsers/cmake.py EXACTLY so the names line up
# with the pipeline's — _apply_cmake_conditions matches on (source_file, name).
_ARG_FIND_LIBRARY = re.compile(
    r"^\s*\w+(?:\s+(?:REQUIRED|QUIET))*\s+(?:NAMES?\s+)?(\w+)", re.IGNORECASE,
)
_ARG_FIND_PATH = re.compile(
    r"^\s*\w+\s+(?:NAMES?\s+)?([a-zA-Z0-9_]+)/", re.IGNORECASE,
)
_ARG_PKG = re.compile(
    r"^\s*\w+"
    r"(?:\s+(?:REQUIRED|QUIET|IMPORTED_TARGET|NO_CMAKE_PATH|"
    r"NO_CMAKE_ENVIRONMENT_PATH))*"
    r"\s+['\"]?([a-zA-Z0-9_][a-zA-Z0-9_.+-]*)",
    re.IGNORECASE,
)
_ARG_CHECK_LIB = re.compile(r"^\s*(\w+)", re.IGNORECASE)
#: Generic find_path header prefixes that are not library names.
_FIND_PATH_GENERIC: frozenset[str] = frozenset({
    "include", "src", "lib", "usr", "opt", "sys",
})
#: flag tokens that a find_library/find_path capture must not mistake for a name.
_CMAKE_FLAG_TOKENS: frozenset[str] = frozenset({
    "REQUIRED", "QUIET", "NAMES", "HINTS", "PATHS", "PATH_SUFFIXES", "DOC",
    "NO_DEFAULT_PATH", "NO_CMAKE_PATH",
})


def _name_from_command(cmd: str, args: str) -> tuple[str, str] | None:
    """Extract (name, version) for a dep command, or None. version is '' for
    everything but find_package. Mirrors analyzer/parsers/cmake.py."""
    if cmd in ("find_package", "find_host_package"):
        m = _FIND_ARG_NAME.match(args)
        if not m or m.group(1) in _SKIP_FIND:
            return None
        return m.group(1), (m.group(2) or "")
    if cmd == "find_library":
        m = _ARG_FIND_LIBRARY.match(args)
        if not m or m.group(1).upper() in _CMAKE_FLAG_TOKENS:
            return None
        return m.group(1), ""
    if cmd == "find_path":
        m = _ARG_FIND_PATH.match(args)
        if not m:
            return None
        name = m.group(1)
        if name.lower() in _FIND_PATH_GENERIC or name.upper() in _CMAKE_FLAG_TOKENS:
            return None
        return name, ""
    if cmd in ("pkg_check_modules", "pkg_search_module", "ocv_check_modules"):
        m = _ARG_PKG.match(args)
        return (m.group(1), "") if m else None
    if cmd == "check_library_exists":
        m = _ARG_CHECK_LIB.match(args)
        return (m.group(1), "") if m else None
    return None


def _iter_with_branches(
    content: str,
) -> Iterator[tuple[str, str, list[_Atom]]]:
    """Yield ``(command, args, branch_atoms)`` — every non-control command with
    the condition atoms in effect where it appears."""
    content = _strip_comments(content)
    stack: list[_Frame] = []
    for cmd, args in _iter_commands(content):
        if cmd == "if":
            expr = args.strip()
            stack.append(_Frame(seen=[expr], current=[_Atom(False, expr)]))
        elif cmd == "elseif":
            if stack:
                frame = stack[-1]
                expr = args.strip()
                frame.current = [_Atom(True, e) for e in frame.seen]
                frame.current.append(_Atom(False, expr))
                frame.seen.append(expr)
        elif cmd == "else":
            if stack:
                stack[-1].current = [_Atom(True, e) for e in stack[-1].seen]
        elif cmd == "endif":
            if stack:
                stack.pop()
        else:
            yield cmd, args, _branch_atoms(stack)


def _walk_dependencies(
    content: str, ctx: CMakeContext, *, find_package_only: bool,
    inherited: list[_Atom] | None = None,
) -> list[FindPackageHit]:
    """Classify dependency commands against their branch condition.

    ``find_package_only`` keeps :func:`find_packages` at its historical scope
    (``scan_cmake`` emits only those); the full set (find_library, find_path,
    pkg_check_modules, …) drives :func:`find_dependencies` for the pipeline
    filter, so an option-guarded find_library (mbedtls, alsa) is resolved the
    same way a find_package is. *inherited* prepends the guard a
    directory carries from the ``add_subdirectory`` chain.
    """
    base = list(inherited or [])
    hits: list[FindPackageHit] = []
    for cmd, args, atoms in _iter_with_branches(content):
        if cmd not in _DEP_COMMANDS:
            continue
        if find_package_only and cmd not in ("find_package", "find_host_package"):
            continue
        extracted = _name_from_command(cmd, args)
        if extracted is None:
            continue
        name, version = extracted
        state, condition = _classify(base + atoms, ctx)
        hits.append(FindPackageHit(
            name=name, version=version, state=state, condition=condition,
        ))
    return hits


_ADD_SUBDIR_ARG = re.compile(r"\s*([^\s)]+)")


def _collect_add_subdirs(
    content: str, file_dir: Path,
) -> list[tuple[str, list[tuple[bool, str]]]]:
    """Yield ``(resolved child dir, guard atoms)`` for each add_subdirectory."""
    out: list[tuple[str, list[tuple[bool, str]]]] = []
    for cmd, args, atoms in _iter_with_branches(content):
        if cmd != "add_subdirectory":
            continue
        m = _ADD_SUBDIR_ARG.match(args)
        if not m:
            continue
        raw = m.group(1).strip().strip('"')
        if not raw or "$" in raw or raw.startswith("/"):
            continue  # variable-driven or absolute — cannot resolve statically
        child = (file_dir / raw).resolve()
        out.append((str(child), [(a.negate, a.expr) for a in atoms]))
    return out


def find_packages(content: str, ctx: CMakeContext) -> list[FindPackageHit]:
    """Classify every ``find_package`` in *content* against *ctx*."""
    return _walk_dependencies(content, ctx, find_package_only=True)


def find_dependencies(
    content: str, ctx: CMakeContext, *, inherited: list[_Atom] | None = None,
) -> list[FindPackageHit]:
    """Classify every dependency-producing command (find_package, find_library,
    find_path, pkg_check_modules, …) against its branch condition, prepending
    the *inherited* add_subdirectory guard for the file's directory."""
    return _walk_dependencies(
        content, ctx, find_package_only=False, inherited=inherited,
    )


# --- Project-wide context building --------------------------------------------

_OPTION = re.compile(
    r"\b(?:option|cmake_dependent_option)\s*\(", re.IGNORECASE,
)
#: A CMakeCache.txt entry: ``NAME:TYPE=VALUE``.
_CACHE_LINE = re.compile(r"^\s*([A-Za-z_]\w*):[A-Za-z]+=(.*)$")


def _parse_options(content: str, into: dict[str, bool]) -> None:
    """Collect ``option(NAME "desc" DEFAULT)`` defaults from *content*."""
    content = _strip_comments(content)
    for m in _OPTION.finditer(content):
        args, _ = _extract_args(content, m.end() - 1)
        # Tokens: NAME "desc" [DEFAULT] (cmake_dependent_option adds more,
        # but its 3rd token is still the default).
        toks = re.findall(r'"[^"]*"|\S+', args)
        if not toks:
            continue
        name = toks[0].strip('"')
        if not re.fullmatch(r"\w+", name):
            continue
        default = False
        if len(toks) >= 3:  # noqa: PLR2004 — NAME, "desc", DEFAULT
            resolved = _const_truthiness(toks[2].strip('"'))
            default = bool(resolved)  # unknown/var default → treated as OFF
        into.setdefault(name, default)


def _load_cache(path: Path, into: dict[str, str]) -> None:
    if too_large(path):
        # a 65 MiB CMakeCache.txt was read whole
        note_skipped(path)
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for line in text.splitlines():
        m = _CACHE_LINE.match(line)
        if m:
            into[m.group(1)] = m.group(2).strip()


#: Directories not walked when collecting options (mirror the scanner).
_SKIP_DIRS: frozenset[str] = frozenset({
    "node_modules", "__pycache__", "target", "vendor", "dist", "venv",
})


def _is_find_module(path: Path) -> bool:
    """A ``Find<Name>.cmake`` file is a search module, not a declaration."""
    return bool(re.fullmatch(r"Find.+\.cmake", path.name))


#: Largest CMake file the context walk reads — the one limit
#: (core.file_limit; a 65 MiB CMakeLists.txt was skipped by the
#: walk and read whole here, 13.6 s and 167 MiB). A larger one gives no options.
MAX_CMAKE_FILE = MAX_BUILD_FILE


def build_cmake_context(
    root: Path, *, max_depth: int = 5, extra_cache: Path | None = None,
) -> CMakeContext:
    """Collect option defaults and cache values across the whole project.

    ``option()`` declarations live in the top-level ``CMakeLists.txt`` while a
    ``find_package`` lives deep in a sub-directory — a per-file parser never
    sees the toggle. Build outputs and vendored trees are skipped; ``CMakeCache.txt``
    (in the source tree or a nested build directory) is loaded when present.
    """
    ctx = CMakeContext()
    if not root.is_dir():
        return ctx

    def _walk(current: Path, depth: int) -> None:
        # A directory holding CMakeCache.txt IS a build tree: read the cache,
        # but never parse its generated CMakeLists/.cmake for options and do
        # not descend — those files would inject phantom find_package hits.
        cache_file = current / "CMakeCache.txt"
        if cache_file.is_file():
            _load_cache(cache_file, ctx.cache)
            ctx.has_cache = True
            return
        try:
            entries = sorted(current.iterdir())
        except OSError:
            return
        for entry in entries:
            name = entry.name
            if entry.is_dir():
                if depth >= max_depth or name.startswith(".") or name in _SKIP_DIRS:
                    continue
                _walk(entry, depth + 1)
            elif name == "CMakeLists.txt" or name.endswith(".cmake"):
                try:
                    if entry.stat().st_size > MAX_CMAKE_FILE or too_large(entry):
                        note_skipped(entry)
                        continue
                    text = entry.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _is_find_module(entry):
                    # Never harvested for options/deps — but a module that
                    # only runs find_program locates a TOOL: its
                    # find_package() name must never become a component
                    # question (Befund 57, FindOpenSSLbins.cmake).
                    low = text.lower()
                    if "find_program" in low and not any(
                        k in low for k in
                        ("find_library", "find_path", "pkg_check_modules",
                         "pkg_search_module")
                    ):
                        ctx.program_modules.add(entry.name[4:-6])  # Find<X>.cmake
                    continue
                _parse_options(text, ctx.options)
                # add_subdirectory(X) under a guard makes X (and its find_library
                # calls) inherit that guard.
                parent = str(entry.parent.resolve())
                for child, atom_tuples in _collect_add_subdirs(text, entry.parent):
                    if atom_tuples:  # only record guarded subdirectories
                        ctx.added_by[child] = (parent, atom_tuples)

    _walk(root, 0)
    if extra_cache is not None and extra_cache.is_file():
        # A configuration produced OUTSIDE the tree (init --scan --configure
        # writes into a temp dir, Increment 4) — the build is decided by it.
        _load_cache(extra_cache, ctx.cache)
        ctx.has_cache = True
    if ctx.options or ctx.cache:
        logger.info(
            "CMake context: %d option(s), %d cache value(s)%s",
            len(ctx.options), len(ctx.cache),
            " [build decided by cache]" if ctx.has_cache else "",
        )
    return ctx
