"""CMake links named by their bare name are read.

Measured 12.11.2026 on d5c9f76, suite and collector alike: only -l inside
target_link_libraries was read. ``target_link_libraries(fw z pq curl)``,
the PRIVATE/PUBLIC/INTERFACE forms, link_libraries and ${LIBS} from
set()/list(APPEND) gave no component at all. A bare name may also be one
of the project's own targets (add_library/add_executable in any CMake file
of the project): those are no dependency.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from jochwacht_sbom.analyzer.parsers.cmake import defined_targets, link_names

HEAD = "add_executable(fw main.c)\n"


def names(body: str, own: frozenset[str] = frozenset()) -> list[str]:
    content = HEAD + body
    return link_names(content, own | defined_targets(content))


@pytest.mark.parametrize(
    "body",
    [
        "target_link_libraries(fw mosquitto curl)",
        "target_link_libraries(fw PRIVATE mosquitto curl)",
        "target_link_libraries(fw PUBLIC mosquitto INTERFACE curl)",
        "target_link_libraries(fw LINK_PRIVATE mosquitto LINK_PUBLIC curl)",
        "target_link_libraries(fw\n  PRIVATE\n    mosquitto\n    curl\n)",
        'target_link_libraries(fw "mosquitto" "curl")',
        "TARGET_LINK_LIBRARIES(fw mosquitto curl)",
        "link_libraries(mosquitto curl)",
        "target_link_libraries(fw -lmosquitto -lcurl)",
        "set(LIBS mosquitto curl)\ntarget_link_libraries(fw ${LIBS})",
        "set(LIBS mosquitto)\nlist(APPEND LIBS curl)\ntarget_link_libraries(fw PRIVATE ${LIBS})",
        'set(LIBS mosquitto curl CACHE STRING "libraries")\ntarget_link_libraries(fw ${LIBS})',
        "set(LIBS ${OTHER} mosquitto curl)\ntarget_link_libraries(fw ${LIBS})",
        "set(LIBS mosquitto curl PARENT_SCOPE)\nlink_libraries(${LIBS})",
    ],
)
def test_the_forms_name_mosquitto_and_curl(body: str) -> None:
    assert names(body) == ["curl", "mosquitto"]


def test_three_bare_names() -> None:
    assert names("target_link_libraries(fw z pq curl)") == ["curl", "libpq", "zlib"]


@pytest.mark.parametrize(
    "body",
    [
        "target_link_libraries(fw ${UNKNOWN_LIBS})",
        "target_link_libraries(fw $<$<PLATFORM_ID:Linux>:dl>)",
        "target_link_libraries(fw CURL::libcurl Threads::Threads)",
        "target_link_libraries(fw /usr/lib/libfoo.so ../lib/libbar.a)",
        "target_link_libraries(fw foo.lib)",
        "target_link_libraries(fw -pthread -Wl,--as-needed)",
        'target_link_libraries(fw "-framework Cocoa")',
        "target_link_libraries(fw -framework Cocoa)",
        "target_link_libraries(fw m dl pthread rt stdc++ gcc_s)",
        "target_link_libraries(fw ws2_32 iphlpapi kernel32 advapi32 crypt32 bcrypt)",
        "target_link_libraries(fw log android)",
        "target_link_libraries(fw ab)",
        "target_link_libraries(fw ${CMAKE_DL_LIBS} ${CMAKE_THREAD_LIBS_INIT})",
        "set(X ${Y})\ntarget_link_libraries(fw ${X})",
        "target_link_libraries(fw debug mosquittod)",
        "target_link_libraries(fw)",
    ],
)
def test_no_library_here(body: str) -> None:
    assert names(body) == []


def test_debug_variant_is_left_to_the_release_name() -> None:
    body = "target_link_libraries(fw debug mosquittod optimized mosquitto general curl)"
    assert names(body) == ["curl", "mosquitto"]


@pytest.mark.parametrize(
    "body",
    [
        "add_library(fwcore STATIC core.c)\ntarget_link_libraries(fw fwcore mosquitto)",
        "add_library(fwcore SHARED core.c)\ntarget_link_libraries(fw PRIVATE fwcore mosquitto)",
        "add_library(fwcfg INTERFACE)\ntarget_link_libraries(fw fwcfg mosquitto)",
        "add_library(fw::core ALIAS fwcore)\nadd_library(fwcore core.c)\n"
        "target_link_libraries(fw fwcore fw::core mosquitto)",
        "add_executable(tool tool.c)\ntarget_link_libraries(tool fw mosquitto)",
        "qt_add_executable(app main.cpp)\ntarget_link_libraries(fw app mosquitto)",
        "pico_add_library(pico_extra)\ntarget_link_libraries(fw pico_extra mosquitto)",
    ],
)
def test_own_targets_of_the_same_file_are_no_dependency(body: str) -> None:
    assert names(body) == ["mosquitto"]


def test_an_imported_target_is_a_dependency_not_an_own_target() -> None:
    """add_library(… IMPORTED) declares a library from outside."""
    body = "add_library(mosq_imported SHARED IMPORTED)\ntarget_link_libraries(fw mosq_imported)"
    assert names(body) == ["mosq_imported"]


def test_own_targets_of_other_files_are_no_dependency() -> None:
    body = "target_link_libraries(fw fwcore fwutil mosquitto)"
    assert names(body, frozenset({"fwcore", "fwutil"})) == ["mosquitto"]


def test_defined_targets_reads_every_form() -> None:
    content = ("add_library(a a.c)\nadd_library(b STATIC b.c)\nADD_EXECUTABLE(c c.c)\n"
               "add_library(ns::d ALIAS a)\nqt_add_library(e)\n"
               "add_library(${PROJECT_NAME} x.c)\n")
    assert defined_targets(content) == {"a", "b", "c", "ns::d", "e"}


def test_commented_lines_count_nothing() -> None:
    assert names("# target_link_libraries(fw mosquitto)") == []


# --- the customer's path: collector with the project-wide target list --------

def _project(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def test_the_collector_reads_bare_names(tmp_path: Path) -> None:
    from jochwacht_sbom.collector import collect_components

    _project(tmp_path, {"CMakeLists.txt": "cmake_minimum_required(VERSION 3.16)\n"
                        "project(fw C)\nadd_executable(fw main.c)\n"
                        "target_link_libraries(fw z pq curl)\n"})
    assert {c.name for c in collect_components(tmp_path)[0]} == {"zlib", "libpq", "curl"}


def test_the_collector_knows_targets_of_other_files(tmp_path: Path) -> None:
    from jochwacht_sbom.collector import collect_components

    _project(tmp_path, {
        "CMakeLists.txt": "project(fw C)\nadd_subdirectory(lib)\nadd_subdirectory(app)\n",
        "lib/CMakeLists.txt": "add_library(fwcore STATIC core.c)\n"
                              "target_link_libraries(fwcore PUBLIC mosquitto)\n",
        "app/CMakeLists.txt": "add_executable(fw main.c)\n"
                              "target_link_libraries(fw PRIVATE fwcore fwutil curl)\n",
        "cmake/util.cmake": "add_library(fwutil INTERFACE)\n",
    })
    assert {c.name for c in collect_components(tmp_path)[0]} == {"mosquitto", "curl"}


# --- corpus round 1 (12.11.2026): 164 new names, most of them own targets ----
# Measured on 50 projects: own targets named through a variable (curl
# set(LIB_SHARED "libcurl_shared"), cJSON "${CJSON_LIB}", libcoap
# "coap-${LIBCOAP_API_VERSION}"), through a wrapper function (libevent
# add_event_library(event_extra …)), SDK component targets (micropython
# pico_*, hardware_*; zephyr_interface) and compiler runtime (stdc++fs, ssp).

from jochwacht_sbom.analyzer.parsers.cmake import project_targets  # noqa: E402


@pytest.mark.parametrize(
    ("files", "linked"),
    [
        (['set(LIB_SHARED "libcurl_shared")\nadd_library(${LIB_SHARED} SHARED a.c)'],
         "target_link_libraries(fw libcurl_shared curl)"),
        (['set(CJSON_LIB cjson)\nadd_library("${CJSON_LIB}" a.c)'],
         "target_link_libraries(fw cjson curl)"),
        (['set(LIBCOAP_API_VERSION 3)\nset(COAP_LIBRARY_NAME "coap-${LIBCOAP_API_VERSION}")\n'
          "add_library(${COAP_LIBRARY_NAME})"],
         "target_link_libraries(fw coap-3 curl)"),
        (["set(PLUGIN_NAME mosq_dynsec)", "add_library(${PLUGIN_NAME} MODULE a.c)"],
         "target_link_libraries(fw mosq_dynsec curl)"),
        (["function(add_event_library LIBNAME)\n  add_library(${LIBNAME} a.c)\nendfunction()",
          "add_event_library(event_extra SOURCES x.c)"],
         "target_link_libraries(fw event_extra curl)"),
        (["macro(make_lib name)\n  add_library(${name} STATIC a.c)\nendmacro()\n"
          "make_lib(fwcore)"],
         "target_link_libraries(fw fwcore curl)"),
        (["function(add_plugin)\n  add_library(${ARGV0} MODULE a.c)\nendfunction()\n"
          "add_plugin(fwplug)"],
         "target_link_libraries(fw fwplug curl)"),
        (["project(xfreerdp-client C)", "add_library(${PROJECT_NAME} a.c)"],
         "target_link_libraries(fw xfreerdp-client curl)"),
    ],
)
def test_own_targets_through_variables_and_wrappers(files: list[str], linked: str) -> None:
    own = project_targets(files)
    assert link_names(HEAD + linked, own) == ["curl"]


@pytest.mark.parametrize(
    "name",
    # SDK prefixes only with the SDK in the project: test_cmake_bounds;
    # a variant of the own target fw is dropped
    ["fw_shared", "fw_static", "fw_objects",
     "fw_obj", "fw_interface", "stdc++fs", "c++fs", "ssp", "ssp_nonshared", "c++abi"],
)
def test_sdk_targets_runtime_and_target_suffixes_are_no_component(name: str) -> None:
    assert names(f"target_link_libraries(fw {name} curl)") == ["curl"]


def test_freertos_and_real_libraries_stay() -> None:
    body = "target_link_libraries(fw freertos_kernel mpg123 pcap)"
    assert names(body) == ["freertos_kernel", "mpg123", "pcap"]
