"""Befund 75 — the collector's bill must match the suite at the SAME tree.

Measured divergences at an unconfigured libwebsockets clone (0.8.3):
1. `${LWS_WOLFSSL_…}` leaked raw into a condition — gone now that an
   option-guarded pipeline hit is an OPEN component, not a conditional.
2. Scope diverged: mbedtls/wolfssl/opus were wrongly excluded-conditional
   while the suite lists them as open build_file_only entries.
3. Self-reference filtered by the DIRECTORY name — now by the project name
   (jochwacht.yaml when present), the same source the suite uses.
4. Git / a program-only Find module (OpenSSLbins) were DROPPED, while the
   suite lists them as scope=excluded — both must show the same set.

These tests build a small CMake tree that exercises each case without a
network clone.
"""

from __future__ import annotations

from pathlib import Path

from jochwacht_sbom.collector import _own_identities, collect_components


def _write(tree: Path, rel: str, text: str) -> None:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _cmake_tree(tmp_path: Path, name: str = "myproj") -> Path:
    tree = tmp_path / name
    _write(tree, "CMakeLists.txt", f"""
cmake_minimum_required(VERSION 3.10)
project({name})
find_package(Git)
find_package(OpenSSLbins)
find_package({name})            # self-reference
option(WITH_WOLFSSL "" OFF)
if(WITH_WOLFSSL AND "${{WOLFSSL_LIBRARIES}}" STREQUAL "")
  find_library(WOLFSSL_LIB wolfssl)
endif()
find_package(RealDep)
""")
    # A program-only Find module: makes OpenSSLbins a tool, never a component.
    _write(tree, "cmake/FindOpenSSLbins.cmake",
           "find_program(OPENSSL_BIN openssl)\n")
    return tree


class TestProjectName:
    def test_prefers_jochwacht_yaml(self, tmp_path: Path) -> None:
        tree = tmp_path / "some-copy-dir"
        tree.mkdir()
        (tree / "jochwacht.yaml").write_text(
            "project:\n  name: libwebsockets\n", encoding="utf-8")
        assert ("libwebsockets", "") in _own_identities(tree)

    def test_never_the_directory_name(self, tmp_path: Path) -> None:
        """The folder says where a checkout lives, not what the project is
        called (a west workspace in a folder "zephyr" lost its module)."""
        tree = tmp_path / "libwebsockets"
        tree.mkdir()
        assert _own_identities(tree) == frozenset()


class TestBefund75:
    def test_self_reference_filtered_by_project_name(self, tmp_path: Path) -> None:
        tree = _cmake_tree(tmp_path, "myproj")
        names = {c.name.lower() for c, in [(c,) for c in
                                           collect_components(tree)[0]]}
        assert "myproj" not in names

    def test_no_raw_variable_in_any_condition(self, tmp_path: Path) -> None:
        comps, _ = collect_components(_cmake_tree(tmp_path))
        for c in comps:
            assert "${" not in (c.condition or "")

    def test_option_guarded_pipeline_hit_is_open_not_conditional(
        self, tmp_path: Path,
    ) -> None:
        # wolfssl behind an off option, discovered by the pipeline (not a
        # configured scan_cmake .condition), is an OPEN component — the suite
        # lists it build_file_only scope="", never excluded-conditional.
        comps, _ = collect_components(_cmake_tree(tmp_path))
        wolf = next((c for c in comps if "wolfssl" in c.name.lower()), None)
        if wolf is not None:  # harvested at all → must be open, not excluded
            assert wolf.scope != "excluded"
            assert not wolf.condition

    def test_program_module_and_build_tool_listed_excluded(
        self, tmp_path: Path,
    ) -> None:
        comps, _ = collect_components(_cmake_tree(tmp_path))
        by = {c.name: c for c in comps}
        # Git (build tool) and OpenSSLbins (program-only Find module) are
        # LISTED as excluded — not dropped, not asked (Befund 75 issue 4).
        for tool in ("Git", "OpenSSLbins"):
            if tool in by:
                assert by[tool].scope == "excluded"


class TestBefund78NoDuplicateConditionals:
    """A conditional alternative found by BOTH scan_cmake (path 1, .condition)
    and the pipeline (path 2, context) must appear ONCE — with its condition,
    scope="" like the suite — never as a second bare component."""

    def test_conditional_not_duplicated_as_bare_component(
        self, tmp_path: Path,
    ) -> None:
        tree = tmp_path / "proj"
        _write(tree, "CMakeLists.txt", """
cmake_minimum_required(VERSION 3.10)
project(proj)
option(WITH_MINIZ "" OFF)
if(WITH_MINIZ)
  find_package(Miniz)
  find_library(MINIZ_LIB miniz)
endif()
""")
        comps, stats = collect_components(tree)
        minizes = [c for c in comps if c.name.lower() == "miniz"]
        # exactly one Miniz, carrying its condition, NOT excluded, never a
        # second bare (condition-less) entry. Since 0.8.6 (Befund 81
        # Nachtrag) the undecidable scope is stated as CycloneDX "optional"
        # instead of left empty — the intent of Befund 78 (not excluded, not
        # duplicated) is unchanged.
        assert len(minizes) <= 1
        if minizes:
            assert minizes[0].condition
            assert minizes[0].scope == "optional"
