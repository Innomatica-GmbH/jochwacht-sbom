"""One component per library, the name that leads to its key; no merge
across major versions; text in configure.ac and a *LIBS name with a
non-link value count nothing.

N1, measured 12.11.2026 with the signed knowledge base (sbom generate
--offline, sbom keys): libnl-3.0 leads to cpe libnl_project:libnl, nl-3 to
none; openssl to openssl:openssl, ssl and crypto to none. The merge chose
nl-3 for htop and ssl for unbound.
"""

from __future__ import annotations

import pytest

from jochwacht_sbom.analyzer.models import BuildFileDependency
from jochwacht_sbom.analyzer.parsers import autotools, makefile
from jochwacht_sbom.analyzer.pipeline.base import ScanResult
from jochwacht_sbom.analyzer.pipeline.merge import merge_results


def merged(names: list[str]) -> list[str]:
    together = merge_results([ScanResult(
        tier=4, scanner_name="a", dependencies=[BuildFileDependency(name=n) for n in names])])[0]
    apart = merge_results([ScanResult(tier=4, scanner_name=n,
                                      dependencies=[BuildFileDependency(name=n)])
                           for n in reversed(names)])[0]
    a, b = sorted(d.name for d in together), sorted(d.name for d in apart)
    assert a == b
    return a


@pytest.mark.parametrize(
    ("names", "result"),
    [
        (["nl-3", "libnl-3.0"], ["libnl-3.0"]),
        (["ssl", "crypto"], ["openssl"]),
        (["crypto"], ["openssl"]),
        (["ssl"], ["openssl"]),
        (["openssl", "ssl", "crypto"], ["openssl"]),
        (["libavutil", "avutil"], ["libavutil"]),
        (["websockets", "libwebsockets"], ["libwebsockets"]),
        (["glib", "glib-2.0"], ["glib"]),
    ],
)
def test_n1_the_name_that_leads_to_the_key(names: list[str], result: list[str]) -> None:
    assert merged(names) == result


@pytest.mark.parametrize(
    ("names", "result"),
    [
        (["SDL", "SDL2"], ["SDL", "SDL2"]),
        (["Qt5", "Qt6"], ["Qt5", "Qt6"]),
        (["Qt5", "Qt6", "Qt5Core"], ["Qt5", "Qt6"]),
        (["libusb-0.1", "usb-1.0"], ["libusb-0.1", "usb-1.0"]),
        (["gtk+-2.0", "gtk+-3.0"], ["gtk+-2.0", "gtk+-3.0"]),
        (["python2", "python3"], ["python2", "python3"]),
        (["libnl-3.0", "nl-3"], ["libnl-3.0"]),
        (["SDL2", "sdl2"], ["SDL2"]),
    ],
)
def test_n2_major_versions_stay_apart(names: list[str], result: list[str]) -> None:
    assert merged(names) == result


# --- N3: text is no assignment; a *LIBS value must look like a link list ---

AC = "AC_INIT([fw], [1.0])\n{}\nAC_OUTPUT\n"


@pytest.mark.parametrize(
    "line",
    [
        'AC_MSG_NOTICE([set LIBS=-lfake to link it])',
        'AC_MSG_RESULT([LIBS="$LIBS -lfake"])',
        'AC_MSG_WARN([use LIBS=-lfake])',
        'AC_ARG_WITH([x], AS_HELP_STRING([--with-x], [needs LIBS=-lfake]))',
        'AC_ARG_WITH([x], AC_HELP_STRING([--with-x], [needs LIBS=-lfake]))',
        'echo "LIBS=-lfake"',
        'echo LIBS=-lfake',
        "printf '%s\\n' \"LIBS=-lfake\"",
        'msg="then LIBS=-lfake"',
        "msg='set LIBS=-lfake'",
        'SHOW_LIBS="ls -lts"',
        "CHECK_LIBS=grep -lz",
    ],
)
def test_n3_configure_text_is_no_assignment(line: str) -> None:
    assert autotools.parse(AC.format(line)) == []


@pytest.mark.parametrize(
    "line",
    [
        'LIBS="$LIBS -lmosquitto"',
        'if test x = x; then LIBS="$LIBS -lmosquitto"; fi',
        'AS_IF([test x = x], [LIBS="$LIBS -lmosquitto"])',
        'test x = x && LIBS="$LIBS -lmosquitto"',
        'MOSQ_LIBS="-L/opt/lib -lmosquitto"',
        'MOSQ_LIBS="-Wl,-rpath,/opt -lmosquitto"',
    ],
)
def test_n3_real_assignments_still_count(line: str) -> None:
    assert autotools.parse(AC.format(line)) == ["mosquitto"]


@pytest.mark.parametrize(
    "content",
    [
        "SHOW_LIBS = ls -lts\n",
        "DUMP_LDFLAGS = grep -lz x\n",
        "TEST_LDADD = du -lss\n",
    ],
)
def test_n3_make_link_name_with_a_command_value_counts_nothing(content: str) -> None:
    assert makefile.parse(content) == []


@pytest.mark.parametrize(
    "content",
    [
        "LDFLAGS = -static -lz\n",
        "LIBS = $(EXTRA) -lz\n",
        "fw_LDADD = libfw.la -lz\n",
        "fw_LDADD = ../lib/libfw.a -lz\n",
        "LIBS = -lz\n",
    ],
)
def test_n3_make_link_values_still_count(content: str) -> None:
    assert makefile.parse(content) == ["zlib"]
