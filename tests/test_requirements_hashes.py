"""A pin with hashes keeps its version; skipped files are counted once."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import jochwacht_sbom.collector  # noqa: F401 — loaded before the limit is patched
import jochwacht_sbom.sbom.scanner  # noqa: F401
from jochwacht_sbom.collector import collect_components
from jochwacht_sbom.core import file_limit
from jochwacht_sbom.sbom.scanner import scan_directory

if TYPE_CHECKING:
    import pytest

PIP_COMPILE = """\
certifi==2026.10.23 \\
    --hash=sha256:a9895e6e2758b371e0545e321a3a8fd1fcfd9829ada8824a936dfb16aaaf36cd \\
    --hash=sha256:e9b54de76e530bb6cf0ccd036787103acb58fd42ba930ea8bf948ddbaa2f61d1
    # via requests
idna==3.6 --hash=sha256:c05567e9c24a6b9e5e9f2bc6cb9f6bbd6d1e4e9a0e0b7c6c0e9f0c7e3c3c3c3c
colorama==0.4.6 ; sys_platform == "win32" \\
    --hash=sha256:08695f5cb7ed6e0531a20572697297273c47b8cae5a63ffc6d6ed5c201be6e44
-e git+https://github.com/pallets/click.git@8.1.7#egg=click
-e ./local/mylib
--index-url https://pypi.org/simple
"""


def test_pins_with_hashes_keep_their_version(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(PIP_COMPILE, encoding="utf-8")
    deps = {d.name: d.version for d in scan_directory(tmp_path)}
    assert deps == {"certifi": "2026.10.23", "idna": "3.6", "colorama": "0.4.6", "click": ""}


def test_an_oversized_file_is_counted_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(file_limit, "MAX_BUILD_FILE", 64)
    (tmp_path / "jochwacht-deps.yaml").write_text(
        "dependencies:\n  - name: mylib\n    version: 1.2.3\n" + "#" * 200, encoding="utf-8")
    comps, stats = collect_components(tmp_path)
    assert comps == [] and stats.oversized_files == ["jochwacht-deps.yaml"]
    assert "oversized" not in stats.model_dump_json()


def test_a_comment_line_ends_a_continuation_as_pip_does() -> None:
    """(pip 25.0.1 measured): "#…" at a line's start ends it."""
    from jochwacht_sbom.sbom.scanner import requirement_lines

    assert requirement_lines("six==1.16.0 \\\n# note \\\nattrs==23.2.0\n") == [
        "six==1.16.0", "attrs==23.2.0"]
    assert requirement_lines("requests==2.31.0 # pinned \\\nurllib3==2.8.0\n") == [
        "requests==2.31.0"]
