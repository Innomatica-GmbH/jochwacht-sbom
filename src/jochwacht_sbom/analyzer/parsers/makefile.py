"""Deterministic Makefile parser.

Extracts dependency names from Makefiles by matching:
- -l flags (only after whitespace — avoids false positives from --language etc.)
- pkg-config --libs calls
- $(shell pkg-config --cflags name)
"""

from __future__ import annotations

import re

from jochwacht_sbom.analyzer.parsers.short_libs import short_library
from jochwacht_sbom.analyzer.parsers.system_libs import is_system_library

# -lfoo ONLY when preceded by whitespace, '=' or start-of-line.
# This avoids matching --language → -language → "anguage",
# fsm-listen → -listen → "isten", etc.
# Min length 3: "-ln -s …" is make's ignore-errors prefix before the
# ln COMMAND, not a library — it produced a component literally named
# "n" in a customer-facing report. -lm/-lz/-lrt are glibc system libs the
# skip list drops anyway; a sub-3-char name is never worth the risk.
# A shorter name counts only when it is a real library of the fixed list
# (short_libs: -lz → zlib); "-ln" stays nothing.
_DASH_L = re.compile(
    r"(?:^|[\s=])-l([A-Za-z0-9][A-Za-z0-9_.+-]*)",
    re.MULTILINE,
)

# pkg-config --libs name or pkg-config --cflags name; at least one option:
# "pkg-config support" in an echo text is no package (htop Makefile.am,
# read since 12.11.2026)
_PKG_CONFIG = re.compile(
    r"pkg-config\s+(?:--[\w-]+\s+)+([a-zA-Z0-9_][a-zA-Z0-9_.+-]*)",
)

# $(shell pkg-config ...)
_SHELL_PKG_CONFIG = re.compile(
    r"\$\(shell\s+pkg-config\s+(?:--\w+\s+)*([a-zA-Z0-9_][a-zA-Z0-9_.+-]*)\)",
)

# A -l name counts only where the build links: in an
# assignment to a link variable or on a line that calls a compiler or linker.
# Before, a recipe line such as "ls -lts" or "grep -lz" gave tslib or zlib.
_ASSIGN = re.compile(
    r"^\s*(?:[^\s:=#]+\s*:\s+)?(?:(?:export|override)\s+)*"
    r"([A-Za-z0-9_.-]+)\s*(?::{1,3}|\+|\?|!)?=(.*)\Z",
    re.DOTALL,
)
# LIBS, LDLIBS, EXTLIBS, FW_LIBS; LDFLAGS, AM_LDFLAGS; fw_LDADD; libx_la_LIBADD
_LINK_SUFFIX = re.compile(r"(?:LIBS|LDFLAGS|LDADD|LIBADD)\Z")
# A name with LIB in it (mosquitto LIB_ARGON2, LIBMOSQ_COMMON, git
# LIB_4_CRYPTO), often defined in a config.mk and used by a link line in
# another file, links only when its value starts like a link list
# (CALIBRATE = grep -lz is no library). A search path
# (LD_LIBRARY_PATH, LIBRARY_PATH) never links.
_LIB_NAME = re.compile(r"LIB")
_PATH_NAME = re.compile(r"PATH|DIR")
_LINK_VALUE_START = re.compile(
    r"(?:-l|-L|-Wl,|\$[({]|\$[A-Za-z_]|\S*\.(?:a|la|so(?:\.[0-9.]+)?|dylib|lib)(?:\s|\Z))"
)
# $(CC) ${CXX} $(LD) $(CCLD) $(CXXLD) $(LINK) $(LINK.o) ...
_LINK_TOOL_VAR = re.compile(r"\$[({](?:CC|CXX|LD|CCLD|CXXLD|LINK(?:\.\w+)?)[)}]")
# gcc, g++, cc, c++, clang, clang++, ld; with a cross prefix, path or version
# (a dash counts only inside a word like arm-none-eabi-gcc)
_LINK_TOOL_WORD = re.compile(
    r"(?:.*/)?(?:[A-Za-z0-9_.]+-)*(?:gcc|g\+\+|cc|c\+\+|clang|clang\+\+|ld)(?:-[0-9.]+)?"
)
# A shell line is cut into its commands; a compiler counts only as a
# command, never as a word somewhere in the line.
# ("(" and "{" open a subshell or group, never the "$(" of a variable nor
# find's "{}" placeholder)
_SUB_COMMAND = re.compile(r";|&&|\|\||\||\s-exec\s|\$\(shell\s|`|(?<!\$)\(|(?<!\$)\{(?!\})")
_SHELL_KEYWORDS = frozenset({"do", "then", "else", "elif", "!"})
_WRAPPERS = frozenset({"ccache", "distcc", "env", "exec", "time", "nice", "xargs", "command"})
_ENV_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=\S*\Z")
_LIBTOOL = re.compile(r"(?:.*/)?libtool|\$[({]LIBTOOL[)}]")
_CONDITIONAL = re.compile(r"\s*(?:ifeq|ifneq|ifdef|ifndef|else|endif)\b")
_RULE = re.compile(r"[^\t#=:][^=]*?::?(?!=)")
_VAR_USE = re.compile(r"\$[({]([A-Za-z0-9_.-]+)[)}]")


def _strip_comments(content: str) -> str:
    """Remove Makefile comments."""
    return re.sub(r"#[^\n]*", "", content)


def _logical_lines(content: str) -> list[str]:
    """Join backslash continuations as make does."""
    return re.sub(r"\\\r?\n", " ", content).splitlines()


def is_link_assignment(name: str, value: str) -> bool:
    """True for an assignment a link step reads: LIBS, LDLIBS, fw_LDADD, …
    with a value that starts like a link list (a flag, a variable, a library
    file); a name with LIB in it only with -l, -L, -Wl, a variable or a file."""
    value = value.strip()
    if _PATH_NAME.search(name):
        return False
    if _LINK_SUFFIX.search(name):
        # SHOW_LIBS = ls -lts is a command, no link list;
        # a link variable's value starts with a flag, a variable or a file
        return value.startswith("-") or bool(_LINK_VALUE_START.match(value))
    return bool(_LIB_NAME.search(name)) and bool(_LINK_VALUE_START.match(value))


def _command_word(segment: str) -> tuple[str, str]:
    """The command of one shell command and the rest after it, past make's
    @-+ prefixes, $(Q), environment assignments and wrappers like ccache."""
    words = segment.split()
    while words:
        word = words[0].lstrip("@-+")
        # $(Q)$(CC) and $(CROSS_COMPILE)gcc: an empty-looking prefix variable
        prefix = re.match(r"\$[({][A-Za-z0-9_.]+[)}]", word)
        if prefix and len(word) > prefix.end() and not _LINK_TOOL_VAR.fullmatch(prefix.group(0)):
            word = word[prefix.end():]
        if not word or word in _SHELL_KEYWORDS or word in _WRAPPERS or _ENV_ASSIGN.match(word):
            words.pop(0)
            continue
        return word, " ".join(words[1:])
    return "", ""


def _link_commands(line: str) -> list[str]:
    """The commands of a shell line that call a compiler or linker."""
    found = []
    for segment in _SUB_COMMAND.split(line):
        word, rest = _command_word(segment)
        if not word:
            continue
        if _LIBTOOL.fullmatch(word):
            if "--mode=link" in rest:
                found.append(rest)
            continue
        if _LINK_TOOL_VAR.fullmatch(word) or _LINK_TOOL_WORD.fullmatch(word):
            found.append(rest)
    return found


def add_link_names(deps: set[str], text: str) -> None:
    """Add every -l name of a text that links: a real library of the short
    list under its component name, no system library, no name under three
    characters."""
    for m in _DASH_L.finditer(text):
        name = m.group(1).rstrip("-.")
        if short_library(name):
            deps.add(short_library(name))
        elif len(name) >= 3 and not is_system_library(name):
            deps.add(name)


def parse(content: str) -> list[str]:
    """Extract dependency names from Makefile content."""
    content = _strip_comments(content)
    deps: set[str] = set()

    lines = _logical_lines(content)
    assignments: dict[str, list[str]] = {}
    link_lines: list[str] = []
    in_recipe = False
    for line in lines:
        if not line.strip() or _CONDITIONAL.match(line):
            continue
        # A tab line after a rule is shell, never a make assignment
        # (LD_LIBRARY_PATH=. ls -lts); a tab-indented assignment inside
        # ifeq outside a rule is make's (mosquitto "\tLOCAL_LDADD+=-lssl").
        if line.startswith("\t") and in_recipe:
            link_lines.extend(_link_commands(line))
            continue
        in_recipe = False
        m = _ASSIGN.match(line)
        if m:
            name, value = m.group(1), m.group(2)
            assignments.setdefault(name, []).append(value)
            if is_link_assignment(name, value):
                link_lines.append(value)
            else:
                link_lines.extend(_link_commands(value))  # LINK_CMD = $(CC) …
            continue
        if _RULE.match(line):
            in_recipe = True
            # target: deps ; command
            if ";" in line:
                link_lines.extend(_link_commands(line.split(";", 1)[1]))
            continue
        link_lines.extend(_link_commands(line))

    # A variable a link line uses links too (git: EXTLIBS += $(LIB_4_CRYPTO)).
    seen: set[str] = set()
    todo = list(link_lines)
    while todo:
        text = todo.pop()
        for use in _VAR_USE.finditer(text):
            var = use.group(1)
            if var not in seen and var in assignments:
                seen.add(var)
                todo.extend(assignments[var])
                link_lines.extend(assignments[var])

    # -l flags (only when preceded by whitespace/= to avoid word fragments)
    for text in link_lines:
        add_link_names(deps, text)

    # pkg-config calls
    for pattern in (_PKG_CONFIG, _SHELL_PKG_CONFIG):
        for m in pattern.finditer(content):
            name = m.group(1)
            if name and not name.startswith("-"):
                deps.add(name)

    return sorted(deps)
