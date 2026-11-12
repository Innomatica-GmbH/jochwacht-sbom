"""A floor or a range is no installed version."""

from __future__ import annotations

from pathlib import Path

import pytest

from jochwacht_sbom.collector import collect_components
from jochwacht_sbom.sbom.scanner import pep440_version_fields, scan_directory


@pytest.mark.parametrize(("spec", "fields"), [
    ("==2.31.0", ("2.31.0", "")), (">=3.1", ("", ">=3.1")), ("<2", ("", "<2")),
    ("!=3.0", ("", "!=3.0")), (">=8,<9", ("", ">=8,<9")), ("", ("", "")),
])
def test_pep440_fields(spec: str, fields: tuple[str, str]) -> None:
    assert pep440_version_fields(spec) == fields


def test_only_a_pin_is_a_version(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("jinja2>=3.1\nrequests==2.31.0\nurllib3<2\n",
                                               encoding="utf-8")
    deps = {d.name: (d.version, d.declared_range) for d in scan_directory(tmp_path)}
    assert deps == {"jinja2": ("", ">=3.1"), "requests": ("2.31.0", ""), "urllib3": ("", "<2")}


def test_the_payload_states_no_floor_as_a_version(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "app"\nversion = "1"\n'
        'dependencies = ["jinja2>=3.1", "idna==3.7", "app[x]"]\n', encoding="utf-8")
    comps = {c.name: c.version for c in collect_components(tmp_path)[0]}
    assert comps == {"jinja2": "", "idna": "3.7"}
