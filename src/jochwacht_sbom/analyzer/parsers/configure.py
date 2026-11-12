"""Deterministic configure-script parser (FFmpeg-style).

FFmpeg and similar projects use custom configure scripts (not autotools)
with patterns like:
- EXTERNAL_LIBRARY_LIST / EXTERNAL_AUTODETECT_LIBRARY_LIST
- enabled/disabled library lists
- check_pkg_config name ...
- check_lib name header.h func -lflag
- require_pkg_config name version
"""

from __future__ import annotations

import re

from jochwacht_sbom.analyzer.parsers.short_libs import short_library
from jochwacht_sbom.analyzer.parsers.system_libs import is_system_library

# Lists of library names in configure scripts:
# EXTERNAL_LIBRARY_LIST="
#     lib1
#     lib2
# "
_LIBRARY_LIST = re.compile(
    r"(?:EXTERNAL_LIBRARY_LIST|EXTERNAL_AUTODETECT_LIBRARY_LIST|"
    r"HW_CODECS_LIST|HWACCEL_LIBRARY_LIST|"
    r"THREADS_LIST|SYSTEM_LIBRARY_LIST)\s*=\s*\"(.*?)\"",
    re.DOTALL,
)

# check_pkg_config name "pkg-config-name >= version"
_CHECK_PKG_CONFIG = re.compile(
    r"check_pkg_config\s+(\w+)\s+['\"]?([a-zA-Z0-9_][a-zA-Z0-9_.+-]*)",
)

# check_lib name header.h func -lflag
_CHECK_LIB = re.compile(
    r"check_lib\s+(\w+)\s+",
)

# require_pkg_config name version
_REQUIRE_PKG_CONFIG = re.compile(
    r"require_pkg_config\s+(\w+)",
)

# --enable-libfoo / --disable-libfoo options
_ENABLE_LIB = re.compile(
    r"--enable-(lib\w+)",
)

# enabled libfoo && ... patterns
_ENABLED_CHECK = re.compile(
    r"enabled\s+(lib\w+)",
)

# die_license_disabled ... libfoo
_LICENSE_DISABLED = re.compile(
    r"die_license_disabled\s+\w+\s+(lib\w+)",
)

# Generic -l flags in shell variable assignments (catches nginx ngx_feature_libs="-lxml2 -lxslt")
_SHELL_LINK_FLAGS = re.compile(
    r'(?:_libs|_LIBS|LDFLAGS|LDADD)\s*=\s*["\']([^"\']+)["\']',
)
_LFLAG = re.compile(r"-l(\w[\w.+-]*)")  # stdc++ is one name

# System libs and platform-specific libs to skip (not SBOM deps)
# (the C library and compiler runtime: system_libs, one list on every path)
_SKIP_LIBS: set[str] = {
    # macOS frameworks captured by check_lib
    "applicationservices", "coregraphics", "coreimage", "coremedia",
    "corevideo", "coreservices", "corefoundation", "coretext",
    "coreaudio", "audiotoolbox", "avfoundation", "videotoolbox",
    "cocoa", "appkit", "iokit", "metal", "security",
    "foundation", "quartzcore",
    # Windows system libs
    "advapi32", "bcrypt", "kernel32", "ole32", "shell32", "psapi",
    "user32", "ws2_32", "winmm", "gdi32",
    # Android platform libs
    "camera2ndk", "mediandk", "android", "opensles", "aaudio",
    # Internal function tests (not libraries)
    "clock_gettime", "nanosleep", "custom_allocator",
    # Xlib components (captured as separate check_lib entries)
    "xlib_x11", "xlib_xext", "xlib_xv",
    # GnuPG executables/components (not library deps)
    "gpg", "gpgsm", "gpgconf", "gpg-agent", "scdaemon", "dirmngr", "pinentry",
}


def _extract_list_items(text: str) -> set[str]:
    """Extract individual items from a multiline list."""
    items: set[str] = set()
    for line in text.split("\n"):
        line = line.strip()
        if line and not line.startswith("#") and re.match(r"^[a-zA-Z]", line):
            items.add(line)
    return items


def parse(content: str) -> list[str]:
    """Extract dependency names from configure script content."""
    deps: set[str] = set()

    # Library lists
    for m in _LIBRARY_LIST.finditer(content):
        deps.update(_extract_list_items(m.group(1)))

    # check_pkg_config
    for m in _CHECK_PKG_CONFIG.finditer(content):
        deps.add(m.group(1))

    # check_lib — skip platform-specific and internal test entries
    for m in _CHECK_LIB.finditer(content):
        name = m.group(1)
        if short_library(name):
            deps.add(short_library(name))
        elif (name and not name.startswith("_") and name.lower() not in _SKIP_LIBS
                and not is_system_library(name.lower())):
            deps.add(name)

    # require_pkg_config
    for m in _REQUIRE_PKG_CONFIG.finditer(content):
        deps.add(m.group(1))

    # --enable-lib* patterns
    for m in _ENABLE_LIB.finditer(content):
        deps.add(m.group(1))

    # enabled lib* checks
    for m in _ENABLED_CHECK.finditer(content):
        deps.add(m.group(1))

    # License-disabled libs
    for m in _LICENSE_DISABLED.finditer(content):
        deps.add(m.group(1))

    # Shell variable assignments with -l flags (nginx, etc.)
    for m in _SHELL_LINK_FLAGS.finditer(content):
        for lm in _LFLAG.finditer(m.group(1)):
            lib = lm.group(1)
            if short_library(lib):
                deps.add(short_library(lib))
            elif lib.lower() not in _SKIP_LIBS and not is_system_library(lib.lower()):
                deps.add(lib)

    return sorted(deps)
