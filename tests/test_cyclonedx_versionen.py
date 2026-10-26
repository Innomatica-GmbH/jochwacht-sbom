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


@pytest.mark.parametrize("spec", SPEC_VERSIONS)
@pytest.mark.parametrize("stated", ["BSD License", "MIT", "mit", "Apache-2.0 OR MIT", "unknown"])
def test_whatever_a_build_file_states_the_bill_stays_valid(spec: str, stated: str) -> None:
    """``license.id`` takes an SPDX identifier and nothing else.

    "BSD License" is what a PyPI classifier yields, and it used to go
    straight into that field — which made the customer's whole bill invalid
    against the published schema. Measured 2026-10-26.
    """
    doc = build_cyclonedx(
        [CheckComponent(name="jinja2", version="3.1.2", ecosystem="pypi", license=stated)],
        CheckStats(), project_name="probe", spec_version=spec,
    )
    err = JsonStrictValidator(SCHEMA[spec]).validate_str(json.dumps(doc))
    assert err is None, f"{stated!r} in CycloneDX {spec}: {err}"


@pytest.mark.parametrize(
    ("stated", "expected"),
    [
        ("BSD License", {"license": {"name": "BSD License"}}),
        ("MIT", {"license": {"id": "MIT"}}),
        ("mit", {"license": {"id": "MIT"}}),
        ("Apache-2.0 OR MIT", {"expression": "Apache-2.0 OR MIT"}),
    ],
)
def test_wording_goes_to_the_field_that_fits_it(stated: str, expected: dict) -> None:
    from jochwacht_sbom.licenses import cyclonedx_licenses

    assert cyclonedx_licenses(stated) == [expected]


def test_the_vendored_list_matches_the_one_the_schemas_carry() -> None:
    """An identifier can be right per SPDX and still fail validation."""
    import importlib.resources as resources

    import cyclonedx.schema._res as schema_res

    from jochwacht_sbom.licenses import _spdx_identifiers, spdx_license_list_version

    spdx_schema = json.loads(
        resources.files(schema_res)
        .joinpath("spdx.SNAPSHOT.schema.json")
        .read_text(encoding="utf-8"),
    )
    assert set(_spdx_identifiers().values()) <= set(spdx_schema["enum"])
    assert spdx_license_list_version() in str(spdx_schema.get("$comment", ""))
