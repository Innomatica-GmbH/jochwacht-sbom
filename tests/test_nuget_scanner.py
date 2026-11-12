"""NuGet / .NET readers (nachgezogen aus der Suite 0.15.66, order nuget-scanner).

packages.lock.json is the resolved truth (versions, SHA-512 content hash,
edges); *.csproj / Directory.Build.props carry declared references = manifest
floors, never an invented version; packages.config is the classic installed
set. Fixtures are unmodified files of two public projects (see
fixtures/nuget/README.md) that are also rows of the kettenlauf basket.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from jochwacht_sbom.sbom.scanner import (
    _SCANNERS,
    Dependency,
    nuget_version_fields,
    prefer_locked,
    scan_directory,
    scan_directory_recursive,
    scan_msbuild_project,
    scan_packages_config,
    scan_packages_lock_json,
)

FIXTURES = Path(__file__).parent / "fixtures" / "nuget"


def _by_name(deps: list[Dependency]) -> dict[str, Dependency]:
    return {d.name: d for d in deps}


# --- packages.lock.json -----------------------------------------------------------


class TestPackagesLockJson:
    def test_real_siemens_lockfile_resolved_versions_hashes_and_edges(self) -> None:
        deps = scan_packages_lock_json(FIXTURES / "siemens-broker" / "packages.lock.json")
        raw = json.loads(
            (FIXTURES / "siemens-broker" / "packages.lock.json").read_text(encoding="utf-8-sig"))
        entries = raw["dependencies"]["net8.0"]
        third_party = {n for n, i in entries.items() if i["type"] != "Project"}
        assert {d.name for d in deps} == third_party
        assert len(deps) == 36  # 38 entries, 2 ProjectReferences (Binary, Client) are internal
        by = _by_name(deps)
        log4net = by["log4net"]
        assert log4net.version == "3.0.3" and log4net.ecosystem == "nuget"
        assert log4net.purl == "pkg:nuget/log4net@3.0.3"
        assert log4net.dependencies == ["System.Configuration.ConfigurationManager"]
        # contentHash is the base64 SHA-512 of the .nupkg — carried as hex
        expected = base64.b64decode(entries["log4net"]["contentHash"]).hex()
        assert log4net.hash_sha512 == expected and len(expected) == 128
        assert all(d.hash_sha512 and len(d.hash_sha512) == 128 for d in deps)
        assert all(d.source_kind == "" and d.declared_range == "" for d in deps)
        assert "Binary" not in by and "Client" not in by

    def test_same_package_for_two_frameworks_is_one_component_with_merged_edges(
        self, tmp_path: Path,
    ) -> None:
        f = tmp_path / "packages.lock.json"
        f.write_text(json.dumps({
            "version": 1,
            "dependencies": {
                "net6.0": {"A": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0",
                                 "contentHash": "", "dependencies": {"B": "2.0.0"}}},
                "net8.0": {"A": {"type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0",
                                 "contentHash": "", "dependencies": {"C": "3.0.0"}},
                           "a": {"type": "Transitive", "resolved": "0.9.0"}},
            },
        }))
        deps = scan_packages_lock_json(f)
        assert [(d.name, d.version) for d in deps] == [("A", "1.0.0"), ("a", "0.9.0")]
        assert deps[0].dependencies == ["B", "C"]
        assert deps[0].hash_sha512 is None  # empty/invalid hash → no claim

    def test_broken_or_foreign_json_yields_nothing(self, tmp_path: Path) -> None:
        f = tmp_path / "packages.lock.json"
        f.write_text("{not json")
        assert scan_packages_lock_json(f) == []
        f.write_text(json.dumps({"version": 1}))
        assert scan_packages_lock_json(f) == []


# --- <PackageReference> -------------------------------------------------------------


class TestVersionFields:
    @pytest.mark.parametrize(("raw", "expected"), [
        ("13.0.3", ("13.0.3", "")),            # bare = floor (NuGet reads >=)
        ("[13.0.3]", ("13.0.3", "")),          # exact pin
        ("[1.0, 2.0)", ("1.0", "[1.0, 2.0)")),  # inclusive floor, range kept
        ("[1.2.3, )", ("1.2.3", "[1.2.3, )")),
        ("(1.0, )", ("", "(1.0, )")),          # exclusive floor: no version we can state
        ("(,2.0]", ("", "(,2.0]")),
        ("1.0.*", ("", "1.0.*")),               # floating
        ("*", ("", "*")),
        ("$(PkgVersion)", ("", "$(PkgVersion)")),  # MSBuild property
        ("", ("", "")),
    ])
    def test_floor_or_unresolved_never_invented(self, raw: str, expected: tuple[str, str]) -> None:
        assert nuget_version_fields(raw) == expected


class TestMsbuildProject:
    def test_real_siemens_csproj_attribute_child_and_update(self) -> None:
        deps = scan_msbuild_project(FIXTURES / "siemens-broker" / "Broker.csproj")
        by = _by_name(deps)
        # <Version> child, Version= attribute — both floors from the manifest
        assert by["log4net"].version == "3.0.3" and by["log4net"].source_kind == "manifest"
        assert by["Microsoft.NetCore.Analyzers"].version == "3.3.2"
        assert by["MQTTnet"].purl == "pkg:nuget/MQTTnet@4.3.7.1207"
        # <PackageReference Update=…> edits an imported item, declares nothing
        assert "Microsoft.SourceLink.GitHub" not in by
        assert len(deps) == 4

    def test_real_directory_build_props_is_a_manifest_too(self) -> None:
        deps = scan_msbuild_project(FIXTURES / "siemens-broker" / "Directory.Build.props")
        assert [(d.name, d.version) for d in deps] == [
            ("Microsoft.SourceLink.GitHub", "1.0.0")]

    def test_ranges_floating_and_properties_stay_unresolved(self, tmp_path: Path) -> None:
        f = tmp_path / "App.csproj"
        f.write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
            '<PackageReference Include="Ranged" Version="[1.0, 2.0)" />'
            '<PackageReference Include="Floating" Version="1.0.*" />'
            '<PackageReference Include="Prop" Version="$(SerilogVersion)" />'
            '<PackageReference Include="Exact" Version="[2.3.4]" />'
            '<PackageReference Include="NoVersion" />'
            "</ItemGroup></Project>"
        )
        by = _by_name(scan_msbuild_project(f))
        assert by["Ranged"].version == "1.0" and by["Ranged"].declared_range == "[1.0, 2.0)"
        assert by["Ranged"].purl == "pkg:nuget/Ranged@1.0"
        assert by["Floating"].version == "" and by["Floating"].declared_range == "1.0.*"
        assert by["Floating"].purl == "pkg:nuget/Floating"  # no invented version in the purl
        assert by["Prop"].version == "" and by["Prop"].declared_range == "$(SerilogVersion)"
        assert by["Exact"].version == "2.3.4" and by["Exact"].declared_range == ""
        assert by["NoVersion"].version == "" and by["NoVersion"].declared_range == ""
        assert all(d.source_kind == "manifest" for d in by.values())

    def test_central_package_management_resolves_from_directory_packages_props(
        self, tmp_path: Path,
    ) -> None:
        (tmp_path / "Directory.Packages.props").write_text(
            "<Project><PropertyGroup><ManagePackageVersionsCentrally>true"
            "</ManagePackageVersionsCentrally></PropertyGroup><ItemGroup>"
            '<PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />'
            '<PackageVersion Include="Serilog" Version="[3.1.1]" />'
            "</ItemGroup></Project>"
        )
        proj = tmp_path / "src" / "App"
        proj.mkdir(parents=True)
        f = proj / "App.csproj"
        f.write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
            '<PackageReference Include="newtonsoft.json" />'
            '<PackageReference Include="Serilog" VersionOverride="4.0.0" />'
            '<PackageReference Include="Unknown" />'
            "</ItemGroup></Project>"
        )
        by = _by_name(scan_msbuild_project(f))
        assert by["newtonsoft.json"].version == "13.0.3"  # id lookup is case-insensitive
        assert by["Serilog"].version == "4.0.0"           # override beats the central version
        assert by["Unknown"].version == "" and by["Unknown"].declared_range == ""

    def test_old_style_namespaced_project_and_fsproj(self, tmp_path: Path) -> None:
        f = tmp_path / "Lib.fsproj"
        f.write_text(
            '<?xml version="1.0" encoding="utf-8"?>'
            '<Project ToolsVersion="15.0" '
            'xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
            '<ItemGroup><PackageReference Include="FSharp.Core">'
            "<Version>8.0.100</Version></PackageReference>"
            "</ItemGroup></Project>"
        )
        deps = scan_msbuild_project(f)
        assert [(d.name, d.version) for d in deps] == [("FSharp.Core", "8.0.100")]

    def test_unparsable_project_yields_nothing(self, tmp_path: Path) -> None:
        f = tmp_path / "Bad.csproj"
        f.write_text("<Project><ItemGroup>")
        assert scan_msbuild_project(f) == []


# --- packages.config ----------------------------------------------------------------


class TestPackagesConfig:
    def test_real_nanoframework_packages_config(self) -> None:
        deps = scan_packages_config(FIXTURES / "nano-rtc" / "packages.config")
        by = _by_name(deps)
        assert len(deps) == 6
        assert by["nanoFramework.CoreLibrary"].version == "1.17.11"
        core = by["nanoFramework.CoreLibrary"]
        assert core.purl == "pkg:nuget/nanoFramework.CoreLibrary@1.17.11"
        assert core.scope == ""  # stamped "required" by the recursive scan
        # developmentDependency = build tooling that never ships (the npm dev rule)
        assert by["Nerdbank.GitVersioning"].scope == "excluded"
        assert by["StyleCop.MSBuild"].scope == "excluded"
        assert all(d.source_kind == "" for d in deps)

    def test_entries_without_id_or_version_are_skipped(self, tmp_path: Path) -> None:
        f = tmp_path / "packages.config"
        f.write_text('<packages><package id="A" /><package version="1" />'
                     '<package id="B" version="2.0" /></packages>')
        assert [(d.name, d.version) for d in scan_packages_config(f)] == [("B", "2.0")]


# --- directory scan: registry, suffix match, lockfile precedence ---------------------


class TestDirectoryScan:
    def test_registry_knows_the_three_fixed_names(self) -> None:
        assert _SCANNERS["packages.lock.json"][0] == "packages_lock_json"
        assert _SCANNERS["packages.config"][0] == "packages_config"
        assert _SCANNERS["Directory.Build.props"][0] == "msbuild_project"

    def test_project_files_are_matched_by_suffix(self, tmp_path: Path) -> None:
        ref = ('<Project><ItemGroup><PackageReference Include="{}" Version="{}" />'
               "</ItemGroup></Project>")
        (tmp_path / "Any.Name.csproj").write_text(ref.format("X", "1.0.0"))
        (tmp_path / "Other.vbproj").write_text(ref.format("Y", "2.0.0"))
        deps = scan_directory(tmp_path)
        assert {(d.name, d.version) for d in deps} == {("X", "1.0.0"), ("Y", "2.0.0")}

    def test_lockfile_beats_the_csproj_floor_in_the_same_directory(
        self, tmp_path: Path,
    ) -> None:
        proj = tmp_path / "Broker"
        proj.mkdir()
        for name in ("packages.lock.json", "Broker.csproj"):
            (proj / name).write_bytes((FIXTURES / "siemens-broker" / name).read_bytes())
        deps = scan_directory_recursive(tmp_path)
        by = _by_name(deps)
        assert len(deps) == 36  # 4 csproj floors all shadowed by resolved versions
        assert by["log4net"].version == "3.0.3" and by["log4net"].source_kind == ""
        assert by["log4net"].hash_sha512 is not None
        assert all(d.scope == "required" for d in deps)
        assert sum(1 for d in deps if d.source_kind == "manifest") == 0

    def test_csproj_only_project_keeps_its_floors_honestly(self, tmp_path: Path) -> None:
        src = FIXTURES / "siemens-broker" / "Broker.csproj"
        (tmp_path / "App.csproj").write_bytes(src.read_bytes())
        deps = scan_directory_recursive(tmp_path)
        assert len(deps) == 4 and all(d.source_kind == "manifest" for d in deps)
        assert prefer_locked(deps) == deps

    def test_case_insensitive_ids_dedupe_across_directories(self, tmp_path: Path) -> None:
        for sub, spelling in (("a", "Newtonsoft.Json"), ("b", "newtonsoft.json")):
            d = tmp_path / sub
            d.mkdir()
            (d / "packages.config").write_text(
                f'<packages><package id="{spelling}" version="13.0.3" /></packages>')
        deps = scan_directory_recursive(tmp_path)
        assert len(deps) == 1
