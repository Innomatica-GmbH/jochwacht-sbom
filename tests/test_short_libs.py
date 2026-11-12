"""Real libraries with a one- or two-character link name are kept
(measured 12.11.2026)."""

from __future__ import annotations

from pathlib import Path

import pytest

from jochwacht_sbom.analyzer.parsers import autotools, makefile
from jochwacht_sbom.analyzer.parsers.short_libs import SHORT_LIBRARIES
from jochwacht_sbom.collector import collect_components


@pytest.mark.parametrize(("link", "component"), sorted(SHORT_LIBRARIES.items()))
def test_make_and_autotools_keep_each_short_library(link: str, component: str) -> None:
    assert makefile.parse(f"all:\n\t$(CC) main.c -l{link}\n") == [component]
    assert autotools.parse(f"AC_CHECK_LIB([{link}], [f])\n") == [component]


def test_glibc_parts_and_ln_stay_out() -> None:
    assert makefile.parse("all:\n\t-ln -s a b\n\t$(CC) main.c -lm -lc -ldl -lrt -lpthread\n") == []


def test_the_customer_path_reports_zlib(tmp_path: Path) -> None:
    (tmp_path / "Makefile").write_text("all:\n\t$(CC) -o fw main.c -lz -lpq -lcurl\n",
                                       encoding="utf-8")
    assert {c.name for c in collect_components(tmp_path)[0]} == {"zlib", "libpq", "curl"}
