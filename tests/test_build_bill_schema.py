"""The local bill of a build directory is valid CycloneDX (0.20).

The writer nests file components, writes manufacturer, hashes and our
properties, and images as components of type file. The foreign library's
strict schema check reads both the local bill and the upload, for each
version the collector emits, on a Buildroot build and on suite-d's real
Yocto excerpt.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

pytest.importorskip("cyclonedx.validation.json",
                    reason="cyclonedx-python-lib is the foreign cross-check; install .[dev]")
pytest.importorskip("jsonschema", reason="cyclonedx-python-lib[validation]; install .[dev]")

from cyclonedx.schema import SchemaVersion  # noqa: E402
from cyclonedx.validation.json import JsonStrictValidator  # noqa: E402
from test_build_hebel import _tree  # noqa: E402

from jochwacht_sbom.collector import collect_components  # noqa: E402
from jochwacht_sbom.sbom_out import SPEC_VERSIONS, build_cyclonedx, slim_bytes  # noqa: E402

SCHEMA = {"1.6": SchemaVersion.V1_6, "1.7": SchemaVersion.V1_7}
EXCERPT = Path(__file__).parent / "fixtures" / "yocto_scarthgap4_excerpt"


def _buildroot(tmp_path: Path) -> Path:
    root = _tree(tmp_path / "br")
    images = root / "output" / "images"
    images.mkdir()
    (images / "rootfs.tar").write_bytes(b"ustar")
    return root


def _yocto(tmp_path: Path) -> Path:
    root = tmp_path / "yocto"
    shutil.copytree(EXCERPT, root / "build", symlinks=True)
    return root


@pytest.mark.parametrize("spec", SPEC_VERSIONS)
@pytest.mark.parametrize("make", [_buildroot, _yocto], ids=["buildroot", "yocto"])
def test_local_bill_and_upload_are_valid(tmp_path: Path, spec: str, make: object) -> None:
    root = make(tmp_path)  # type: ignore[operator]
    components, stats = collect_components(root)
    full = build_cyclonedx(components, stats, project_name="fw", spec_version=spec)
    assert any("components" in c for c in full["components"])  # nested files present
    err = JsonStrictValidator(SCHEMA[spec]).validate_str(json.dumps(full))
    assert err is None, f"local bill, CycloneDX {spec}: {err}"
    sent = slim_bytes(components, stats, project_name="fw", spec_version=spec).decode()
    err = JsonStrictValidator(SCHEMA[spec]).validate_str(sent)
    assert err is None, f"upload, CycloneDX {spec}: {err}"
