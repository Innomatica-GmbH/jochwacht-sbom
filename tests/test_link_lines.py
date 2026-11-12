"""-l names count only on lines that link; system libraries stay out on every path.

The make reader took -l<name> from every line, recipes
included. With the short-name table (short_libs) ``ls -lts`` became tslib,
``ls -lgd`` libgd, ``grep -lz``/``tar -lz`` zlib, ``du -lss`` libss and
``@echo linking with -lmd`` libmd. A -l name now counts only in an
assignment to a linking variable (LIBS, LDLIBS, LDFLAGS, *_LIBS, *_LDADD
and the like) or on a line that calls a compiler or linker.

F2: AC_SEARCH_LIBS and AC_CHECK_LIB returned c, m, rt, pthread and posix4
as components; the make path let anl and gcc_s through. One list of
system libraries (system_libs) holds on every path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from jochwacht_sbom.analyzer.parsers import autotools, cmake, configure, makefile
from jochwacht_sbom.analyzer.parsers.system_libs import SYSTEM_LIBRARIES

# Recipe lines: no line links anything.
RECIPES = [
    "ls -lts",
    "ls -lgd",
    "grep -lz pattern *.c",
    "tar -lz -cf out.tar src",
    "du -lss build",
    "@echo linking with -lmd",
    "ls -lart",
    "ls -lh",
    "ls -ld /opt/lib",
    "LS_COLORS=x ls -lts",
    "-ls -lcurl",
    "find . -name '*.o' | xargs ls -lssl",
]


@pytest.mark.parametrize("line", RECIPES)
def test_a_recipe_line_without_a_link_call_gives_nothing(line: str) -> None:
    assert makefile.parse(f"all:\n\t{line}\n") == []


@pytest.mark.parametrize("line", RECIPES)
def test_a_recipe_line_next_to_a_link_line_adds_nothing(line: str) -> None:
    content = f"fw: main.o\n\t$(CC) -o fw main.o -lcurl\n\t{line}\n"
    assert makefile.parse(content) == ["curl"]


@pytest.mark.parametrize(
    "line",
    [
        "LIBS = -lz",
        "LIBS += -lz",
        "LIBS := -lz",
        "LIBS ?= -lz",
        "LDLIBS = -lz",
        "LDFLAGS += -L/opt/lib -lz",
        "FW_LIBS = -lz",
        "fw_LDADD = -lz",
        "libfw_la_LIBADD = -lz",
        "EXTLIBS += -lz",
        "export LIBS = -lz",
        "override LDLIBS += -lz",
        "fw: LDLIBS += -lz",
    ],
)
def test_a_link_variable_assignment_counts(line: str) -> None:
    assert makefile.parse(f"{line}\n") == ["zlib"]


@pytest.mark.parametrize(
    "line",
    [
        "\t$(CC) -o fw main.o -lz",
        "\t$(CXX) -o fw main.o -lz",
        "\t$(LD) -o fw main.o -lz",
        "\t${CC} -o fw main.o -lz",
        "\t@$(CC) -o fw main.o -lz",
        "\t$(Q)$(CC) -o fw main.o -lz",
        "\tgcc -o fw main.o -lz",
        "\tg++ -o fw main.o -lz",
        "\tcc -o fw main.o -lz",
        "\tclang -o fw main.o -lz",
        "\tclang++ -o fw main.o -lz",
        "\tld -o fw main.o -lz",
        "\tarm-none-eabi-gcc -o fw main.o -lz",
        "\t$(CROSS_COMPILE)gcc -o fw main.o -lz",
        "\t/usr/bin/gcc-13 -o fw main.o -lz",
        "\tcd out && $(CC) -o fw main.o -lz",
        "\t$(LINK.o) $^ -o $@ -lz",
        "\t$(CCLD) -o fw main.o -lz",
        "\tCFLAGS=-O2 $(CC) -o fw main.o -lz",
    ],
)
def test_a_compiler_or_linker_line_counts(line: str) -> None:
    assert makefile.parse(f"fw: main.o\n{line}\n") == ["zlib"]


def test_an_indented_link_assignment_in_a_conditional_counts() -> None:
    """mosquitto: assignments inside ifeq are indented with a tab."""
    content = ("ifeq ($(WITH_TLS),yes)\n\tLOCAL_LDADD+=-lssl -lcrypto\n"
               "\tLOCAL_LIBADD+=-lcares\nendif\n")
    assert makefile.parse(content) == ["cares", "crypto", "ssl"]


def test_a_continued_link_line_counts_to_its_end() -> None:
    content = "fw: main.o\n\t$(CC) -o fw main.o \\\n\t\t-lcurl \\\n\t\t-lz\n"
    assert makefile.parse(content) == ["curl", "zlib"]


def test_a_continued_link_assignment_counts_to_its_end() -> None:
    assert makefile.parse("LIBS = -lcurl \\\n  -lz\n") == ["curl", "zlib"]


def test_a_continued_recipe_line_stays_nothing() -> None:
    assert makefile.parse("all:\n\tls -lts \\\n\t  -lgd\n") == []


def test_another_variable_counts_only_when_a_link_line_uses_it() -> None:
    """git style: LIB_4_CRYPTO = -lssl, then EXTLIBS += $(LIB_4_CRYPTO)."""
    used = "LIB_4_CRYPTO = -lssl -lcrypto\nEXTLIBS += $(LIB_4_CRYPTO)\n"
    assert makefile.parse(used) == ["crypto", "ssl"]
    via_cc = "CURL_LINK = -lcurl\nfw:\n\t$(CC) -o fw main.o $(CURL_LINK)\n"
    assert makefile.parse(via_cc) == ["curl"]
    unused = "LS_FLAGS = -lts\nall:\n\tls $(LS_FLAGS)\n"
    assert makefile.parse(unused) == []


def test_a_variable_named_lib_counts_in_its_own_file() -> None:
    """mosquitto config.mk: LIB_ARGON2=-largon2, used in client/Makefile."""
    assert makefile.parse("\tLIB_ARGON2=-largon2\n") == ["argon2"]
    assert makefile.parse("LIBMOSQ_COMMON:=-Wl,--whole-archive x.a -lcjson\n") == ["cjson"]


def test_a_variable_chain_counts() -> None:
    content = "A = -lz\nB = $(A) -lcurl\nLIBS = ${B}\n"
    assert makefile.parse(content) == ["curl", "zlib"]


def test_a_compiler_word_after_echo_is_no_link_call() -> None:
    """a compiler word counts only as the command."""
    assert makefile.parse("all:\n\t@echo gcc -lz\n") == []
    assert makefile.parse('all:\n\t@echo "gcc -lz"\n') == []


# --- hardening of the send and status path ---

@pytest.mark.parametrize(
    "content",
    [
        "CALIBRATE = grep -lz pattern\n",
        "CALIBRATE := ls -lts\n",
        "GLIBC_CHECK = du -lss .\n",
        "all:\n\tLD_LIBRARY_PATH=. ls -lts\n",
        "all:\n\tLIBRARY_PATH=/opt/lib grep -lz x *.c\n",
        "all:\n\tLD_LIBRARY_PATH=$(PWD)/lib ./run -lgd\n",
        "all:\n\tgrep -lz gcc *.c\n",
        "all:\n\tls -lts cc\n",
        "all:\n\tls -lts && echo gcc\n",
        "all:\n\tfind . -name '*.c' -exec ls -lts {} \\;\n",
        "all:\n\tls -lts | grep ld\n",
        "all:\n\tfor f in *.o; do ls -lts $$f; done\n",
    ],
)
def test_no_link_call_in_a_recipe_word(content: str) -> None:
    assert makefile.parse(content) == []


@pytest.mark.parametrize(
    "content",
    [
        "LIB_ARGON2 = -largon2\n",
        "LIBMOSQ = -L/opt/lib -lmosquitto\n",
        "LIBMOSQ = $(OTHER) -lmosquitto\n",
        "LIBMOSQ = ${OTHER} -lmosquitto\n",
        "LIBMOSQ = libcommon.a -lmosquitto\n",
        "LIBMOSQ = ../lib/libcommon.so -lmosquitto\n",
        "LIBMOSQ = -Wl,--whole-archive libc.a -Wl,--no-whole-archive -lmosquitto\n",
    ],
)
def test_a_lib_named_variable_counts_when_its_value_links(content: str) -> None:
    assert makefile.parse(content) == (["argon2"] if "argon2" in content else ["mosquitto"])


@pytest.mark.parametrize(
    "line",
    [
        "\tls -lts; $(CC) -o fw main.o -lz",
        "\tls -lts && gcc -o fw main.o -lz",
        "\ttrue || cc -o fw main.o -lz",
        "\tfind . -name main.o -exec gcc -o fw {} -lz \\;",
        "\tLD_LIBRARY_PATH=. $(CC) -o fw main.o -lz",
        "\tCFLAGS=-O2 LDFLAGS=-s gcc -o fw main.o -lz",
        "\t(cd out && $(CC) -o fw main.o -lz)",
        "\tccache gcc -o fw main.o -lz",
        "\t$(LIBTOOL) --mode=link $(CC) -o fw main.lo -lz",
    ],
)
def test_the_compiler_as_a_sub_command_counts(line: str) -> None:
    assert makefile.parse(f"fw: main.o\n{line}\n") == ["zlib"]


def test_only_the_link_part_of_a_line_counts() -> None:
    """ls -lts before && must not give tslib although gcc follows."""
    content = "fw: main.o\n\tls -lts && gcc -o fw main.o -lcurl\n"
    assert makefile.parse(content) == ["curl"]


# --- one list of system libraries on every path -----------------------------

SYSTEM = ["c", "m", "dl", "rt", "pthread", "posix4", "anl", "gcc", "gcc_s",
          "stdc++", "resolv", "util", "atomic"]


def test_the_list_holds_the_named_parts() -> None:
    assert set(SYSTEM) <= SYSTEM_LIBRARIES


@pytest.mark.parametrize("lib", SYSTEM)
def test_make_drops_system_libraries(lib: str) -> None:
    assert makefile.parse(f"fw:\n\t$(CC) -o fw main.o -l{lib}\n") == []
    assert makefile.parse(f"LIBS = -l{lib}\n") == []


@pytest.mark.parametrize("lib", SYSTEM)
def test_autotools_check_lib_drops_system_libraries(lib: str) -> None:
    assert autotools.parse(f"AC_CHECK_LIB([{lib}], [f])\n") == []


@pytest.mark.parametrize("lib", SYSTEM)
def test_autotools_search_libs_drops_system_libraries(lib: str) -> None:
    assert autotools.parse(f"AC_SEARCH_LIBS([f], [{lib}])\n") == []


def test_autotools_search_libs_keeps_the_real_library_beside() -> None:
    content = "AC_SEARCH_LIBS([clock_gettime], [rt posix4])\nAC_SEARCH_LIBS(dlopen, dl zrldsrl)\n"
    assert autotools.parse(content) == ["zrldsrl"]


@pytest.mark.parametrize("lib", SYSTEM)
def test_configure_drops_system_libraries(lib: str) -> None:
    assert configure.parse(f'ngx_feature_libs="-l{lib}"\n') == []


@pytest.mark.parametrize("lib", SYSTEM)
def test_cmake_drops_system_libraries(lib: str) -> None:
    assert cmake.parse(f"target_link_libraries(fw PRIVATE -l{lib})\n") == []


def test_recipe_lines_in_the_collector(tmp_path: Path) -> None:
    """The customer's path: a Makefile with a recipe of ls/grep/tar/du."""
    from jochwacht_sbom.collector import collect_components

    (tmp_path / "Makefile").write_text(
        "fw: main.o\n\t$(CC) -o fw main.o -lz -lcurl -lm -lgcc_s -lanl\n"
        "list:\n\tls -lts\n\tls -lgd\n\tgrep -lz x *.c\n\tdu -lss .\n"
        "\t@echo linking with -lmd\n",
        encoding="utf-8")
    names = {c.name for c in collect_components(tmp_path)[0]}
    assert names == {"zlib", "curl"}
