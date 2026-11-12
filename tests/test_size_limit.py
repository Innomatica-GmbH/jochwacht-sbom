"""One size limit for every reader."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import jochwacht_sbom.collector  # noqa: F401 — loaded before the limit is patched
import jochwacht_sbom.sbom.scanner  # noqa: F401
from jochwacht_sbom.core import file_limit

if TYPE_CHECKING:
    import pytest


def test_no_component_from_a_file_over_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from jochwacht_sbom.collector import collect_components

    for name, text in (("conanfile.txt", "[requires]\nzlib/1.2.13\n"),
                       ("go.mod", "module x\nrequire golang.org/x/net v0.1.0\n"),
                       ("Cargo.toml", '[dependencies]\nserde = "1.0"\n')):
        (tmp_path / name).write_text(text + "#" * 4096, encoding="utf-8")
    assert collect_components(tmp_path)[0]            # readable under the limit
    monkeypatch.setattr(file_limit, "MAX_BUILD_FILE", 1024)
    assert collect_components(tmp_path)[0] == []
