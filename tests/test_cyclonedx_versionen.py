"""Which CycloneDX version the collector writes — and whether it is valid.

The second half is the point: our own assertions can only repeat what we
already assumed. ``cyclonedx-python-lib`` is a foreign implementation that
ships the published schemas, so it judges the document the way a customer's
tooling would.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from jochwacht_sbom.cli import main
from jochwacht_sbom.core.exceptions import JochwachtError
from jochwacht_sbom.payload import CheckComponent, CheckStats
from jochwacht_sbom.sbom_out import SPEC_VERSION, SPEC_VERSIONS, build_cyclonedx

if TYPE_CHECKING:
    from pathlib import Path

pytest.importorskip(
    "cyclonedx.validation.json",
    reason="cyclonedx-python-lib is the foreign cross-check; install .[dev]",
)
# The validator itself is behind the library's "validation" extra: without
# jsonschema the import above still succeeds and the failure only surfaces
# at validate time, as a bare ModuleNotFoundError that reads like our bug.
pytest.importorskip(
    "jsonschema",
    reason="needs cyclonedx-python-lib[validation]; install .[dev]",
)
from cyclonedx.schema import SchemaVersion  # noqa: E402
from cyclonedx.validation.json import JsonStrictValidator  # noqa: E402

if not hasattr(SchemaVersion, "V1_7"):  # pragma: no cover - environment guard
    pytest.skip(
        "The installed cyclonedx-python-lib predates CycloneDX 1.7 and cannot "
        "judge it. Install .[dev] (>=11.12) — a cross-check that silently "
        "skips proves nothing.",
        allow_module_level=True,
    )

SCHEMA = {"1.6": SchemaVersion.V1_6, "1.7": SchemaVersion.V1_7}


def _doc(spec: str) -> dict[str, object]:
    return build_cyclonedx(
        [
            CheckComponent(name="click", version="8.1.7", ecosystem="pypi"),
            CheckComponent(name="zlib", version="1.3.1", ecosystem="conan"),
        ],
        CheckStats(),
        project_name="probe",
        spec_version=spec,
    )


@pytest.mark.parametrize("spec", SPEC_VERSIONS)
def test_what_we_write_is_valid_for_the_version_we_claim(spec: str) -> None:
    err = JsonStrictValidator(SCHEMA[spec]).validate_str(json.dumps(_doc(spec)))
    assert err is None, f"CycloneDX {spec}: {err}"


def test_the_default_stays_1_6() -> None:
    """1.6 is the BSI TR-03183-2 v2.1.0 minimum and what tooling reads.

    A default is a promise to whoever passes no flag, so it moves on a
    decision, not on a release.
    """
    assert SPEC_VERSION == "1.6"
    assert _doc(SPEC_VERSION)["specVersion"] == "1.6"


def test_1_7_is_reachable() -> None:
    assert "1.7" in SPEC_VERSIONS
    assert _doc("1.7")["specVersion"] == "1.7"


def test_a_version_we_do_not_emit_is_refused() -> None:
    with pytest.raises(JochwachtError, match="1.6, 1.7"):
        _doc("1.5")


def test_only_the_version_string_differs_between_1_6_and_1_7() -> None:
    """Both documents use the fields 1.6 and 1.7 define identically.

    If that ever stops being true, this test says so instead of a customer.
    """
    a, b = _doc("1.6"), _doc("1.7")
    for d in (a, b):
        d.pop("serialNumber")
        d["metadata"].pop("timestamp")  # type: ignore[union-attr]
    a["specVersion"] = b["specVersion"]
    assert a == b


def test_the_switch_reaches_the_written_file(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("click==8.1.7\n", encoding="utf-8")
    out = tmp_path / "sbom.cdx.json"
    res = CliRunner().invoke(
        main, [str(tmp_path), "--no-send", "--cyclonedx", "1.7", "--sbom", str(out)]
    )
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["specVersion"] == "1.7"
    assert JsonStrictValidator(SchemaVersion.V1_7).validate_str(json.dumps(doc)) is None
