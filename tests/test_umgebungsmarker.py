"""The collector agrees with the suite about what ships.

Ported from the suite (jochwacht 0.17.0, 14.10.2026). The two halves must
answer the same way about the same lockfile, or a customer who runs the free
check and one who runs the suite get different bills.

Measured on a real lockfile (innoscout-platform, 128 packages): six
resolutions reach no target environment, and the component count stays at
120 — nothing is deleted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from jochwacht_sbom.payload import CheckComponent
from jochwacht_sbom.sbom.markers import evaluate, parse_target_spec
from jochwacht_sbom.sbom.scanner import (
    scan_poetry_lock,
    scan_requirements_txt,
    scan_uv_lock,
)

_MARKER_3_13 = [
    "python_full_version >= '3.14' and platform_machine == 'aarch64' and sys_platform == 'linux'",
    "python_full_version == '3.13.*' and platform_machine == 'aarch64' "
    "and sys_platform == 'linux'",
]
_MARKER_VOR_3_13 = [
    "python_full_version < '3.11' and platform_machine == 'aarch64' and sys_platform == 'linux'",
    "python_full_version < '3.11' and platform_machine != 'aarch64' and sys_platform == 'linux'",
]
_ZIEL = "python=3.10;platform=linux;arch=aarch64,x86_64"


def _lock(tmp_path: Path, *eintraege: str) -> Path:
    lock = tmp_path / "uv.lock"
    lock.write_text("version = 1\n\n" + "".join(eintraege), encoding="utf-8")
    return lock


def _paket(name: str, version: str, markers: list[str]) -> str:
    zeilen = ",\n    ".join(f'"{m}"' for m in markers)
    return (
        f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
        f'source = {{ registry = "https://pypi.org/simple" }}\n'
        f"resolution-markers = [\n    {zeilen},\n]\n\n"
    )


def test_a_resolution_for_an_unshipped_python_is_not_shipped(tmp_path: Path) -> None:
    lock = _lock(
        tmp_path,
        _paket("onnx", "1.19.0", _MARKER_3_13),
        _paket("onnx", "1.22.0", _MARKER_VOR_3_13),
    )
    envs, warnungen = parse_target_spec(_ZIEL)
    assert warnungen == []
    deps = {(d.name, d.version): d for d in scan_uv_lock(lock, target_envs=envs)}
    assert deps[("onnx", "1.19.0")].scope == "excluded"
    assert deps[("onnx", "1.22.0")].scope != "excluded"
    assert len(deps) == 2, "nothing is deleted"


def test_without_a_target_environment_nothing_is_recorded(tmp_path: Path) -> None:
    lock = _lock(tmp_path, _paket("onnx", "1.19.0", _MARKER_3_13))
    dep = next(iter(scan_uv_lock(lock)))
    assert dep.scope != "excluded"
    assert dep.markers == ()
    assert dep.scope_reason == ""
    assert dep.marker_note == ""


def test_the_reason_never_leaves_the_machine() -> None:
    """The promise is that only names and versions travel.

    The reason belongs in the LOCAL bill. If it ever appears in a payload
    dump, the preview shown before --send would be incomplete.
    """
    c = CheckComponent(
        name="onnx", version="1.19.0", scope="excluded",
        scope_reason="no marker is true for any target environment (python=3.10)",
        markers=("python_full_version >= '3.13'",),
        marker_note="something",
    )
    roh = c.model_dump_json()
    assert "no marker is true" not in roh
    assert "python_full_version" not in roh
    assert "something" not in roh
    # …but the object keeps them for the local bill.
    assert c.scope_reason
    assert c.markers


def test_the_local_bill_carries_the_reason(tmp_path: Path) -> None:
    from jochwacht_sbom.payload import CheckStats
    from jochwacht_sbom.sbom_out import write_cyclonedx

    c = CheckComponent(
        name="onnx", version="1.19.0", ecosystem="pypi", scope="excluded",
        scope_reason="no marker is true for any target environment (python=3.10)",
        markers=("python_full_version >= '3.13'",),
    )
    ziel = tmp_path / "sbom.cdx.json"
    write_cyclonedx(ziel, [c], CheckStats(), project_name="demo")
    doc = json.loads(ziel.read_text(encoding="utf-8"))
    eigenschaften = {
        p["name"]: p["value"] for p in doc["components"][0]["properties"]
    }
    assert "no marker is true" in eigenschaften["jochwacht:not-shipped-reason"]
    assert "python_full_version" in eigenschaften["jochwacht:environment-markers"]


def test_an_undeclared_variable_is_never_taken_from_the_build_host() -> None:
    nur_python, _ = parse_target_spec("python=3.10")
    urteil = evaluate(["platform_machine == 'x86_64'"], nur_python)
    assert urteil.shipped is True
    assert urteil.undecidable is True


@pytest.mark.parametrize("roh", ["platform.machine == 'aarch64'", "os.name == 'nt'"])
def test_a_legacy_spelling_does_not_slip_past_the_guard(roh: str) -> None:
    nur_python, _ = parse_target_spec("python=3.10")
    assert evaluate([roh], nur_python).undecidable is True


def test_requirements_and_poetry_evaluate_markers_too(tmp_path: Path) -> None:
    envs, _ = parse_target_spec("python=3.10;platform=linux;arch=x86_64")

    req = tmp_path / "requirements.txt"
    req.write_text(
        "\n".join([
            'onnx==1.19.0 ; python_version >= "3.13"',
            'colorama==0.4.6 ; sys_platform == "win32"  # only on Windows',
            "numpy==1.26.3  # see ticket #12; reason follows",
            "jinja2==3.1.2",
            "",
        ]),
        encoding="utf-8",
    )
    aus = {d.name: d for d in scan_requirements_txt(req, target_envs=envs)}
    assert aus["onnx"].scope == "excluded"
    assert aus["colorama"].scope == "excluded", "a comment must not break the marker"
    assert aus["numpy"].markers == (), "a ';' inside a comment invents no marker"
    assert aus["jinja2"].scope != "excluded"

    poetry = tmp_path / "poetry.lock"
    poetry.write_text(
        "\n".join([
            "[[package]]",
            'name = "pywin32"',
            'version = "306"',
            "markers = 'sys_platform == \"win32\"'",
            "",
        ]),
        encoding="utf-8",
    )
    assert {d.name: d for d in scan_poetry_lock(poetry, target_envs=envs)}[
        "pywin32"
    ].scope == "excluded"


def test_the_two_halves_agree() -> None:
    """The same markers must yield the same verdict here and in the suite.

    Pinned by value rather than by importing the suite: the collector ships
    without it, and a difference must fail here, not at a customer.
    """
    envs, _ = parse_target_spec(_ZIEL)
    assert evaluate(_MARKER_3_13, envs).shipped is False
    assert evaluate(_MARKER_VOR_3_13, envs).shipped is True


def test_a_build_tool_name_keeps_its_marker_reason(tmp_path: Path) -> None:
    """``cmake==3.27 ; sys_platform == "win32"`` is BOTH a tool name and
    marker-excluded.

    The tooling branch of the collector built a fresh component and dropped
    the reason, so the run printed "test/example directories or dev
    tooling" for it — the false statement the summary refuses to make — and
    the suite kept the reason, so the halves disagreed (found in review,
    14.10.2026).
    """
    from jochwacht_sbom.collector import collect_components

    req = tmp_path / "requirements.txt"
    req.write_text(
        "\n".join([
            'cmake==3.27.0 ; sys_platform == "win32"',
            "jinja2==3.1.2",
            "",
        ]),
        encoding="utf-8",
    )
    envs, _ = parse_target_spec("python=3.10;platform=linux;arch=x86_64")
    komponenten, _ = collect_components(tmp_path, target_envs=envs)
    nach_namen = {c.name: c for c in komponenten}

    cmake = nach_namen["cmake"]
    assert cmake.scope == "excluded"
    assert "no marker is true" in cmake.scope_reason, (
        "the reason must survive the tooling branch, or the summary calls a "
        "marker exclusion 'test material'"
    )
    assert cmake.markers == ('sys_platform == "win32"',)


# --------------------------------------------------------------------------
# Edge markers (ported from the suite, 15.10.2026)
# --------------------------------------------------------------------------

def _ws(tmp_path: Path, mitglied: str, pakete: str) -> Path:
    lock = tmp_path / "uv.lock"
    lock.write_text(
        'version = 1\n\n[[package]]\nname = "produkt"\nversion = "0.1.0"\n'
        f'source = {{ editable = "." }}\ndependencies = [{mitglied}]\n\n' + pakete,
        encoding="utf-8",
    )
    return lock


def _pkg(name: str, version: str = "1.0.0", deps: str = "") -> str:
    zeile = f"dependencies = [{deps}]\n" if deps else ""
    return (
        f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
        f'source = {{ registry = "https://pypi.org/simple" }}\n{zeile}\n'
    )


def test_a_package_reached_only_by_a_false_edge_is_not_shipped(tmp_path: Path) -> None:
    lock = _ws(
        tmp_path, '{ name = "click" }',
        _pkg("click", deps='{ name = "colorama", marker = "sys_platform == \'win32\'" }')
        + _pkg("colorama", "0.4.6"),
    )
    envs, _ = parse_target_spec("python=3.10;platform=linux;arch=x86_64")
    deps = {d.name: d for d in scan_uv_lock(lock, target_envs=envs)}
    assert deps["colorama"].scope == "excluded"
    assert "dependency condition" in deps["colorama"].scope_reason
    assert deps["click"].scope != "excluded"


def test_development_material_never_enters_the_difference(tmp_path: Path) -> None:
    """This reader has no dev-scope closure — the two traversals make that safe.

    Development material is unreachable in BOTH traversals, so it cannot
    appear in the difference and can never be called a marker exclusion.
    """
    lock = _ws(tmp_path, '{ name = "click" }', _pkg("click") + _pkg("mypy", "1.11.0"))
    envs, _ = parse_target_spec("python=3.10;platform=linux;arch=x86_64")
    mypy = next(d for d in scan_uv_lock(lock, target_envs=envs) if d.name == "mypy")
    assert mypy.scope != "excluded"
    assert mypy.scope_reason == ""


def test_a_lockfile_without_members_is_left_alone(tmp_path: Path) -> None:
    lock = tmp_path / "uv.lock"
    lock.write_text("version = 1\n\n" + _pkg("click") + _pkg("colorama", "0.4.6"),
                    encoding="utf-8")
    envs, _ = parse_target_spec("python=3.10;platform=linux;arch=x86_64")
    deps = scan_uv_lock(lock, target_envs=envs)
    assert len(deps) == 2
    assert all(d.scope != "excluded" for d in deps)


def test_without_a_target_the_graph_is_not_even_built(tmp_path: Path) -> None:
    lock = _ws(
        tmp_path, '{ name = "click" }',
        _pkg("click", deps='{ name = "colorama", marker = "sys_platform == \'win32\'" }')
        + _pkg("colorama", "0.4.6"),
    )
    deps = {d.name: d for d in scan_uv_lock(lock)}
    assert all(d.scope != "excluded" for d in deps.values())
    assert all(d.markers == () for d in deps.values())


def test_the_halves_agree_on_the_edge_rule() -> None:
    """Pinned by value: the collector ships without the suite, so a
    divergence must fail here and not at a customer.

    Measured 15.10.2026 on the same real lockfile, both halves named the
    same nine resolutions — six from package entries, three from edges.
    """
    envs, _ = parse_target_spec("python=3.10;platform=linux;arch=aarch64,x86_64")
    from jochwacht_sbom.sbom.markers import evaluate

    # The three edge conditions of that measurement, and their verdicts.
    assert evaluate(["sys_platform == 'win32'"], envs).shipped is False
    assert evaluate(["sys_platform == '_'"], envs).shipped is False
    assert evaluate(["python_full_version >= '3.12'"], envs).shipped is False
    # And the one that looks similar but holds — joblib's edge.
    assert evaluate(["python_full_version < '3.11'"], envs).shipped is True
