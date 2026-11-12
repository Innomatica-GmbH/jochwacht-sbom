"""configure.ac link assignments and Makefile.am are read (before the start).

Measured 12.11.2026 on d5c9f76: LIBS="$LIBS -luv", LIBS+=" -lx", X_LIBS="-lx"
with AC_SUBST in configure.ac and fw_LDADD = -lz in Makefile.am gave no
component on any path, the standalone collector included. Every autotools
project links this way, so much was lost silently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from jochwacht_sbom.analyzer.parsers import autotools, makefile

AC = "AC_INIT([fw], [1.0])\n{}\nAC_OUTPUT\n"


@pytest.mark.parametrize(
    "line",
    [
        'LIBS="$LIBS -lmosquitto"',
        'LIBS="-lmosquitto $LIBS"',
        "LIBS=\"${LIBS} -lmosquitto\"",
        "LIBS='-lmosquitto'",
        "LIBS=-lmosquitto",
        'LIBS+=" -lmosquitto"',
        'MOSQ_LIBS="-lmosquitto"\nAC_SUBST([MOSQ_LIBS])',
        "MOSQ_LIBS=-lmosquitto\nAC_SUBST(MOSQ_LIBS)",
        'AC_SUBST([MOSQ_LIBS], ["-lmosquitto"])',
        "AC_SUBST(MOSQ_LIBS, -lmosquitto)",
        'LDFLAGS="$LDFLAGS -L/opt/lib -lmosquitto"',
        '  if test "x$with_mosq" = xyes; then\n    LIBS="$LIBS -lmosquitto"\n  fi',
        'AS_IF([test x$a = xyes], [LIBS="$LIBS -lmosquitto"])',
    ],
)
def test_a_link_assignment_in_configure_ac_counts(line: str) -> None:
    assert autotools.parse(AC.format(line)) == ["mosquitto"]


def test_several_libraries_and_short_names() -> None:
    content = AC.format('LIBS="$LIBS -lz -lpq -lcurl"')
    assert autotools.parse(content) == ["curl", "libpq", "zlib"]


@pytest.mark.parametrize("lib", ["m", "dl", "rt", "pthread", "anl", "gcc_s", "stdc++"])
def test_system_libraries_stay_out(lib: str) -> None:
    assert autotools.parse(AC.format(f'LIBS="$LIBS -l{lib}"')) == []


@pytest.mark.parametrize(
    "line",
    [
        'CFLAGS="$CFLAGS -lfake"',          # no link variable
        'ac_cv_x="-lfake"',                 # cache variable
        'AC_MSG_CHECKING([for -lfake])',    # text
        'echo "-lfake"',
        'LIBS="$LIBS"',
        'LIBS="$LIBS $MOSQ_LIBS"',
    ],
)
def test_no_link_assignment_gives_nothing(line: str) -> None:
    assert autotools.parse(AC.format(line)) == []


def test_a_commented_assignment_gives_nothing() -> None:
    content = AC.format('dnl LIBS="$LIBS -lfake"\n# LIBS="$LIBS -lfake2"')
    assert autotools.parse(content) == []


def test_the_old_checks_still_count() -> None:
    content = AC.format("AC_CHECK_LIB([curl], [curl_global_init])\n"
                        'LIBS="$LIBS -lmosquitto"')
    assert autotools.parse(content) == ["curl", "mosquitto"]


# --- Makefile.am through the collector and the suite's analyzer --------------

def test_the_collector_reads_makefile_am(tmp_path: Path) -> None:
    from jochwacht_sbom.collector import collect_components

    (tmp_path / "configure.ac").write_text(AC.format(""), encoding="utf-8")
    (tmp_path / "Makefile.am").write_text(
        "bin_PROGRAMS = fw\nfw_SOURCES = main.c\nfw_LDADD = -lz -lmosquitto -lm\n",
        encoding="utf-8")
    names = {c.name for c in collect_components(tmp_path)[0]}
    assert names == {"zlib", "mosquitto"}


def test_the_collector_reads_a_nested_makefile_am(tmp_path: Path) -> None:
    from jochwacht_sbom.collector import collect_components

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Makefile.am").write_text(
        "lib_LTLIBRARIES = libfw.la\nlibfw_la_LIBADD = -lcurl\n", encoding="utf-8")
    names = {c.name for c in collect_components(tmp_path)[0]}
    assert names == {"curl"}


def test_the_collector_reads_configure_ac_libs(tmp_path: Path) -> None:
    from jochwacht_sbom.collector import collect_components

    (tmp_path / "configure.ac").write_text(
        AC.format('LIBS="$LIBS -luv -lmosquitto -lrt"'), encoding="utf-8")
    names = {c.name for c in collect_components(tmp_path)[0]}
    assert names == {"libuv", "mosquitto"}


def test_a_recipe_in_makefile_am_gives_nothing(tmp_path: Path) -> None:
    """The link-line rule holds for Makefile.am too."""
    from jochwacht_sbom.collector import collect_components

    (tmp_path / "Makefile.am").write_text(
        "check-local:\n\tls -lts\n\tgrep -lz x *.c\n", encoding="utf-8")
    assert collect_components(tmp_path)[0] == []


# --- one name per library, whatever the order (merge) ------------------------

@pytest.mark.parametrize(
    ("names", "winner"),
    [
        (["crypto", "openssl", "ssl"], "openssl"),
        (["ssl", "crypto", "openssl"], "openssl"),
        (["openssl", "crypto"], "openssl"),
        (["websockets", "libwebsockets"], "libwebsockets"),
        (["libwebsockets", "websockets"], "libwebsockets"),
        (["event", "libevent"], "libevent"),
        (["libevent_core", "event"], "event"),
        (["libswresample", "libavcodec"], "libavcodec"),
        (["glib-2.0", "glib"], "glib"),
        (["CURL", "libcurl", "curl"], "libcurl"),
    ],
)
def test_the_merge_picks_one_name_in_any_order(names: list[str], winner: str) -> None:
    """memcached: LIBS="-lssl -lcrypto" beside PKG_CHECK_MODULES(openssl) gave
    the component "crypto"; mosquitto showed libwebsockets or websockets by
    hash seed. One name wins, in every order."""
    from jochwacht_sbom.analyzer.models import BuildFileDependency
    from jochwacht_sbom.analyzer.pipeline.base import ScanResult
    from jochwacht_sbom.analyzer.pipeline.merge import merge_results

    one = ScanResult(tier=4, scanner_name="a",
                     dependencies=[BuildFileDependency(name=n) for n in names])
    assert [d.name for d in merge_results([one])[0]] == [winner]
    split = [ScanResult(tier=4, scanner_name=n, dependencies=[BuildFileDependency(name=n)])
             for n in names]
    assert [d.name for d in merge_results(split)[0]] == [winner]


def test_memcached_keeps_openssl(tmp_path: Path) -> None:
    from jochwacht_sbom.collector import collect_components

    (tmp_path / "configure.ac").write_text(AC.format(
        'PKG_CHECK_MODULES(OPENSSL, openssl, [LIBS="$LIBS $OPENSSL_LIBS"], [\n'
        '  LIBS="-lssl -lcrypto $saved_LIBS"])\nLIBS="-levent $LIBS"'), encoding="utf-8")
    names = {c.name for c in collect_components(tmp_path)[0]}
    assert names == {"openssl", "event"}


def test_pkg_config_in_an_echo_text_is_no_package() -> None:
    """htop Makefile.am: echo '... incomplete pkg-config support ...'."""
    content = ("dist-hook:\n\techo 'ERROR: The configure script has incomplete "
               "pkg-config support and regenerating it is advised.'\n")
    assert makefile.parse(content) == []
    assert makefile.parse("CFLAGS += $(shell pkg-config --cflags glib-2.0)\n") == ["glib-2.0"]
    assert makefile.parse("LIBS += `pkg-config --libs --static libcurl`\n") == ["libcurl"]
