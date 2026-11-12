"""Bounds and scopes of the CMake target resolution.

K1: the resolution has a ceiling and never hangs; at the ceiling it takes
fewer own targets (a component too many, never one lost) and counts it.
K2: an IMPORTED target is a dependency, never an own target; a variable
holds only values of its file and of the parent folders; ${PROJECT_NAME}
is the nearest project() upwards. K3: a variant suffix is cut and the base
name passed on; an SDK prefix is skipped only when the SDK is in the
project.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from jochwacht_sbom.analyzer.parsers import cmake
from jochwacht_sbom.analyzer.parsers.cmake import (
    MAX_NAMES_PER_CALL,
    MAX_VALUES_PER_VARIABLE,
    CMakeProject,
    link_names,
)

ROOT = "cmake_minimum_required(VERSION 3.16)\nproject(fw C)\nadd_executable(fw main.c)\n"


def linked(files: dict[str, str], at: str = "CMakeLists.txt") -> list[str]:
    project = CMakeProject.from_files(files)
    return link_names(files[at], project.targets, inherited=project.inherited(at),
                      sdks=project.sdks)


# --- K1: a ceiling, linear, counted -------------------------------------------

@pytest.mark.parametrize(
    ("kind", "n"),
    [("values3", 150), ("values3", 300), ("values2", 3000), ("chain", 3000),
     ("function", 8000), ("sets", 50000), ("word", 2_000_000)],
)
def test_the_resolution_never_hangs(kind: str, n: int) -> None:
    build = {
        "values3": lambda: "".join(f"set(V v{i})\n" for i in range(n))
        + "add_library(${V}${V}${V} a.c)\n",
        "values2": lambda: "".join(f"set(V v{i})\n" for i in range(n))
        + "add_library(${V}${V} a.c)\n",
        "chain": lambda: "".join(f"set(A a{i}${{B}})\nset(B b{i}${{C}})\nset(C c{i})\n"
                                 for i in range(n)) + "add_library(${A} a.c)\n",
        "function": lambda: "function(f a)\n add_library(x y.c)\n" * n,
        "sets": lambda: "set(" * n,
        "word": lambda: "x" * n + "add_",
    }
    text = build[kind]()
    start = time.monotonic()
    CMakeProject.from_files({"CMakeLists.txt": text})
    assert time.monotonic() - start < 3.0


def test_at_the_ceiling_fewer_own_targets_and_a_count() -> None:
    many = "".join(f"set(V lib{i})\n" for i in range(MAX_VALUES_PER_VARIABLE + 1))
    files = {"CMakeLists.txt": ROOT + many + "add_library(${V} a.c)\n"
             "target_link_libraries(fw lib1 curl)\n"}
    project = CMakeProject.from_files(files)
    assert "lib1" not in project.targets
    assert project.capped >= 1
    assert linked(files) == ["curl", "lib1"]


def test_too_many_names_from_one_call_are_counted() -> None:
    sets = "".join(f"set(A a{i})\nset(B b{i})\n" for i in range(40))
    files = {"CMakeLists.txt": ROOT + sets + "add_library(${A}${B} a.c)\n"}
    assert MAX_NAMES_PER_CALL < 40 * 40
    project = CMakeProject.from_files(files)
    assert project.capped >= 1
    assert not any(t.startswith("a1b") for t in project.targets)


def test_a_long_wrapper_chain_stays_linear() -> None:
    """f0 calls f1 … calls f7999, defined in reverse order; only the last one
    calls add_library."""
    n = 8000
    text = "".join(f"function(f{i} a)\n  f{i + 1}(${{a}})\nendfunction()\n" for i in range(n))
    text += f"function(f{n} a)\n  add_library(${{a}} x.c)\nendfunction()\nf0(deep)\n"
    start = time.monotonic()
    project = CMakeProject.from_files({"CMakeLists.txt": text})
    assert time.monotonic() - start < 3.0
    assert "deep" in project.targets


def test_open_functions_stay_linear() -> None:
    files = {"CMakeLists.txt": "function(f a)\n add_library(${a} y.c)\n" * 8000}
    start = time.monotonic()
    CMakeProject.from_files(files)
    assert time.monotonic() - start < 3.0


# --- K2: a real dependency never becomes an own target ------------------------

@pytest.mark.parametrize(
    "decl",
    [
        "add_library(curl SHARED IMPORTED)",
        "add_library(curl UNKNOWN IMPORTED GLOBAL)",
        "add_library(curl INTERFACE IMPORTED)",
        "add_library(curl STATIC IMPORTED)",
    ],
)
def test_an_imported_target_is_a_dependency(decl: str) -> None:
    files = {"CMakeLists.txt": ROOT + decl + "\ntarget_link_libraries(fw PRIVATE curl)\n"}
    assert "curl" not in CMakeProject.from_files(files).targets
    assert linked(files) == ["curl"]


def test_an_import_wrapper_makes_no_own_target() -> None:
    files = {
        "CMakeLists.txt": ROOT + "include(cmake/Import.cmake)\nimport_lib(curl)\n"
                          "import_lib(mosquitto)\n"
                          "target_link_libraries(fw PRIVATE curl mosquitto pq)\n",
        "cmake/Import.cmake": "function(import_lib name)\n  add_library(${name} UNKNOWN IMPORTED)\n"
                              "endfunction()\n",
    }
    assert linked(files) == ["curl", "libpq", "mosquitto"]


def test_an_alias_is_own_only_when_its_target_is() -> None:
    files = {"CMakeLists.txt": ROOT + "add_library(curl SHARED IMPORTED)\n"
             "add_library(mycurl ALIAS curl)\nadd_library(core a.c)\n"
             "add_library(fw::core ALIAS core)\n"}
    targets = CMakeProject.from_files(files).targets
    assert "mycurl" not in targets
    assert {"core", "fw::core"} <= targets


def test_a_variable_of_a_sibling_folder_is_not_seen() -> None:
    files = {
        "CMakeLists.txt": ROOT + "add_subdirectory(lib)\nadd_subdirectory(tests)\n"
                          "target_link_libraries(fw PRIVATE curl fwcore)\n",
        "lib/CMakeLists.txt": "set(LIB fwcore)\nadd_library(${LIB} core.c)\n",
        "tests/CMakeLists.txt": "set(LIB curl)\ntarget_link_libraries(t ${LIB})\n",
    }
    project = CMakeProject.from_files(files)
    assert "fwcore" in project.targets and "curl" not in project.targets
    assert linked(files) == ["curl"]


def test_a_parent_variable_is_seen_below() -> None:
    files = {
        "CMakeLists.txt": ROOT + "set(EXTRA_LIBS curl mosquitto)\nadd_subdirectory(src)\n",
        "src/CMakeLists.txt": "add_executable(app a.c)\ntarget_link_libraries(app ${EXTRA_LIBS})\n",
    }
    assert linked(files, "src/CMakeLists.txt") == ["curl", "mosquitto"]


def test_project_name_is_the_nearest_project_upwards() -> None:
    files = {
        "CMakeLists.txt": ROOT + "add_library(${PROJECT_NAME}_core a.c)\n"
                          "target_link_libraries(fw PRIVATE curl)\n",
        "tests/CMakeLists.txt": "project(curl C)\nadd_executable(${PROJECT_NAME}_test t.c)\n",
        "src/x/CMakeLists.txt": "add_library(${PROJECT_NAME}_x x.c)\n",
    }
    targets = CMakeProject.from_files(files).targets
    assert {"fw_core", "curl_test", "fw_x"} <= targets
    assert "curl_core" not in targets and "curl_x" not in targets
    assert linked(files) == ["curl"]


# --- K3: suffixes cut, SDK prefixes only with the SDK --------------------------

@pytest.mark.parametrize(
    ("name", "result"),
    [
        ("libzstd_static", ["libzstd"]),
        ("nghttp2_static", ["nghttp2"]),
        ("jsoncpp_static", ["jsoncpp"]),
        ("mbedtls_shared", ["mbedtls"]),
        ("glfw_objects", ["glfw"]),
        ("sqlite3_interface", ["sqlite3"]),
        ("zlibstatic", ["zlib"]),
        ("uv_a", ["libuv"]),
        ("event_static", ["event"]),
    ],
)
def test_a_variant_suffix_is_cut(name: str, result: list[str]) -> None:
    assert linked({"CMakeLists.txt": ROOT + f"target_link_libraries(fw {name})\n"}) == result


def test_a_variant_of_an_own_target_is_dropped() -> None:
    files = {"CMakeLists.txt": ROOT + "add_library(fwcore a.c)\n"
             "target_link_libraries(fw fwcore_static curl)\n"}
    assert linked(files) == ["curl"]


def test_sdk_targets_pass_without_the_sdk() -> None:
    files = {"CMakeLists.txt": ROOT + "target_link_libraries(fw pico_stdlib hardware_spi "
             "zephyr_interface picohttpparser)\n"}
    # zephyr_interface: the variant suffix is cut (K3), the base name passes
    assert linked(files) == ["hardware_spi", "pico_stdlib", "picohttpparser", "zephyr"]


@pytest.mark.parametrize(
    "evidence",
    ["include(pico_sdk_import.cmake)\npico_sdk_init()", "pico_sdk_init()"],
)
def test_pico_targets_are_skipped_with_the_pico_sdk(evidence: str) -> None:
    files = {"CMakeLists.txt": ROOT + evidence + "\ntarget_link_libraries(fw pico_stdlib "
             "hardware_spi tinyusb_device cmsis_core curl)\n"}
    assert linked(files) == ["curl"]


def test_zephyr_targets_are_skipped_with_zephyr() -> None:
    files = {"CMakeLists.txt": "find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})\n"
             "project(app)\ntarget_link_libraries(app PRIVATE zephyr_interface curl)\n"}
    assert linked(files) == ["curl"]


@pytest.mark.parametrize("name", ["WS2_32", "Ws2_32", "Bcrypt", "IPHLPAPI", "Kernel32"])
def test_windows_system_libraries_in_any_case(name: str) -> None:
    assert linked({"CMakeLists.txt": ROOT + f"target_link_libraries(fw {name} curl)\n"}) == ["curl"]


def test_include_of_an_import_helper_is_no_component() -> None:
    assert cmake.parse("include(cmake/Import.cmake)\ninclude(cmake/import.cmake)\n") == []


# --- corpus after K2 (12.11.2026): own targets the narrower scope missed ------

def test_a_wrapper_of_a_wrapper_defines_targets() -> None:
    """mosquitto: add_mosquitto_plugin calls add_mosquitto_plugin_no_install."""
    files = {
        "CMakeLists.txt": ROOT + "add_subdirectory(plugins)\n",
        "plugins/CMakeLists.txt":
            "function(add_plugin_no_install PLUGIN_NAME SRCLIST)\n"
            "  add_library(${PLUGIN_NAME} MODULE ${SRCLIST})\nendfunction()\n"
            "function(add_plugin PLUGIN_NAME SRCLIST)\n"
            '  add_plugin_no_install("${PLUGIN_NAME}" "${SRCLIST}")\nendfunction()\n'
            "add_subdirectory(dynsec)\n",
        "plugins/dynsec/CMakeLists.txt":
            "set(PLUGIN_NAME mosq_dynsec)\n"
            'add_plugin("${PLUGIN_NAME}" "a.c")\n'
            "target_link_libraries(mosq_dynsec curl)\n",
    }
    assert "mosq_dynsec" in CMakeProject.from_files(files).targets
    assert linked(files, "plugins/dynsec/CMakeLists.txt") == ["curl"]


def test_a_wrapper_through_a_local_variable() -> None:
    """FreeRDP AddTargetWithResourceFile: set(target ${nameAndTarget})."""
    files = {
        "CMakeLists.txt": ROOT + "include(cmake/AddTarget.cmake)\nadd_subdirectory(client)\n",
        "cmake/AddTarget.cmake":
            "macro(AddTargetWithResourceFile nameAndTarget is_exe)\n"
            "  set(target ${nameAndTarget})\n  add_library(${target} ${lib_options})\n"
            "endmacro()\n",
        "client/CMakeLists.txt": "project(xfreerdp-client C)\n"
                                 'addtargetwithresourcefile(${PROJECT_NAME} "SHARED")\n',
        "client/cli/CMakeLists.txt": "target_link_libraries(xfreerdp xfreerdp-client curl)\n",
    }
    assert "xfreerdp-client" in CMakeProject.from_files(files).targets
    # xfreerdp is the target that links, no library
    assert linked(files, "client/cli/CMakeLists.txt") == ["curl"]


def test_an_included_file_sees_the_variables_of_its_includer() -> None:
    """include() runs a .cmake file in the scope of the file that includes it."""
    files = {
        "CMakeLists.txt": ROOT + "add_subdirectory(ports/unix)\n",
        "ports/unix/CMakeLists.txt": "set(MICROPY_TARGET micropython)\n"
                                     "include(${CMAKE_CURRENT_LIST_DIR}/../../py/mkrules.cmake)\n",
        "py/mkrules.cmake": "add_executable(${MICROPY_TARGET} main.c)\n",
        "ports/unix/sub/CMakeLists.txt": "target_link_libraries(x micropython curl)\n",
    }
    assert "micropython" in CMakeProject.from_files(files).targets
    assert linked(files, "ports/unix/sub/CMakeLists.txt") == ["curl"]


def test_haiku_gnu_is_a_system_library() -> None:
    files = {"CMakeLists.txt": ROOT + "list(APPEND SYS_LIBS gnu network)\n"
             "target_link_libraries(fw ${SYS_LIBS} curl)\n"}
    assert linked(files) == ["curl"]


@pytest.mark.parametrize("evidence", ["zephyr_library()", "zephyr_interface_library_named(CW)",
                                      "zephyr_library_named(cw)"])
def test_a_zephyr_module_is_zephyr(evidence: str) -> None:
    """civetweb: a Zephyr module calls zephyr_library() without find_package."""
    files = {"CMakeLists.txt": ROOT + f"if(ZEPHYR)\n  {evidence}\nendif()\n"
             "target_link_libraries(fw zephyr_interface curl)\n"}
    assert linked(files) == ["curl"]


# --- the one build-file limit (core.file_limit) also for the target walk -------

def test_the_target_walk_uses_the_build_file_limit(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """tier 4 read the project's CMake files for own targets with a limit of
    its own (_MAX_TARGET_FILE); a file over the build-file limit is now
    skipped there too, as everywhere (one limit)."""
    from jochwacht_sbom.analyzer.pipeline import tier4_regex

    (tmp_path / "lib").mkdir()
    (tmp_path / "CMakeLists.txt").write_text(
        ROOT + "add_subdirectory(lib)\ntarget_link_libraries(fw fwcore curl)\n", encoding="utf-8")
    (tmp_path / "lib" / "CMakeLists.txt").write_text(
        "add_library(fwcore a.c)\n" + "# pad\n" * 1000, encoding="utf-8")
    monkeypatch.setattr(tier4_regex, "MAX_FILE_BYTES", 2000)
    scanner = tier4_regex.RegexScanner()
    scanner._ensure_db = lambda: False  # type: ignore[method-assign]
    result = scanner.scan("cmake", tmp_path / "CMakeLists.txt", tmp_path)
    assert {d.name for d in result.dependencies} == {"curl", "fwcore"}


def test_the_target_walk_asks_too_large(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from jochwacht_sbom.analyzer.pipeline import tier4_regex

    (tmp_path / "lib").mkdir()
    (tmp_path / "CMakeLists.txt").write_text(
        ROOT + "add_subdirectory(lib)\ntarget_link_libraries(fw fwcore curl)\n", encoding="utf-8")
    (tmp_path / "lib" / "CMakeLists.txt").write_text("add_library(fwcore a.c)\n", encoding="utf-8")
    monkeypatch.setattr(tier4_regex, "too_large", lambda p: p.parent.name == "lib")
    scanner = tier4_regex.RegexScanner()
    scanner._ensure_db = lambda: False  # type: ignore[method-assign]
    result = scanner.scan("cmake", tmp_path / "CMakeLists.txt", tmp_path)
    assert {d.name for d in result.dependencies} == {"curl", "fwcore"}
