"""Shared dependency name normalization.

Consolidated from reconciler._normalize_name() and eval.normalize_dep_name()
to provide a single source of truth for name matching across the analyzer.
"""

from __future__ import annotations

import re

# Version suffix pattern: _0_3, _1_0, _2, _3_0, _2_11, etc.
# Applied AFTER separator normalization (- → _), so dots become _.
_VERSION_SUFFIX = re.compile(r"(?:_\d+)+$")

# Component suffixes commonly appended to pkg-config names
_COMPONENT_SUFFIXES = (
    "_client", "_server", "_base", "_core", "_common",
    "_egl", "_cursor", "_protocols", "_generic",
    "_video", "_app", "_riff", "_pbutils", "_audio",
    "_simple", "_allocators",
)

# CMake Find-module names often differ from pkg-config / canonical names.
# Map normalized aliases → canonical normalized name.
#: Link names that are a part of a package: the component carries the
#: package's name, the one that has its key in the knowledge base
#: (openssl has a CPE, ssl and crypto have none).
LINK_NAME_PACKAGES: dict[str, str] = {"ssl": "openssl", "crypto": "openssl"}

_ALIASES: dict[str, str] = {
    # pkg-config → canonical
    "cares": "c_ares",
    "pulse": "pulseaudio",
    "pulse_simple": "pulseaudio",
    "avcodec": "ffmpeg",
    "avformat": "ffmpeg",
    "avutil": "ffmpeg",
    "swscale": "ffmpeg",
    "swresample": "ffmpeg",
    "avdevice": "ffmpeg",
    "avfilter": "ffmpeg",
    "postproc": "ffmpeg",
    "gtk2": "gtk",
    "gtk3": "gtk",
    "gtk4": "gtk",
    "gtk_3": "gtk",
    "gstreamer": "gstreamer",
    "gstreamer_base": "gstreamer",
    "gstreamer_video": "gstreamer",
    "gstreamer_app": "gstreamer",
    "gstreamer_riff": "gstreamer",
    "gstreamer_pbutils": "gstreamer",
    # CMake module variants
    "dbus1": "dbus",
    "dbus_1": "dbus",
    "sdl2": "sdl",
    "sdl3": "sdl",
    "qt6widgets": "qt",
    "qt5widgets": "qt",
    "qt6core": "qt",
    "qt5core": "qt",
    "qt6gui": "qt",
    "qt5gui": "qt",
    "qt6": "qt",
    "qt5": "qt",
    "gtest": "googletest",
    "gmock": "googletest",
    "pythoninterp": "python",
    "pythonlibs": "python",
    "python3": "python",
    "cudnn": "cudnn",
    "cudatoolkit": "cuda",
    "threads": "pthread",
    "pthreads": "pthread",
    # -l flag names → package names
    **LINK_NAME_PACKAGES,
    "z": "zlib",
    # OpenCV-specific
    "onnxruntime": "onnx_runtime",
    # Wayland components
    "wayland_scanner": "wayland",
    # glib variants (with and without version suffix)
    "glib_2": "glib",
    "gobject_2": "glib",
    "gobject": "glib",
    "gmodule": "glib",
    "gmodule_2": "glib",
    "gio_2": "glib",
    "gio": "glib",
    # mesa / graphics
    "glslangvalidator": "glslang",
    "sensors": "lmsensors",
}


def normalize_dep_name(name: str) -> str:
    """Normalize a dependency name for matching.

    Lowercases, strips common prefixes (lib, python-, py-),
    strips version suffixes and component suffixes from pkg-config names,
    normalizes separators (-, ., +, space → _), and applies alias mappings.
    """
    n = name.lower().strip()
    # Strip common prefixes
    for prefix in ("lib", "python-", "py-"):
        if n.startswith(prefix) and len(n) > len(prefix) + 1:
            n = n[len(prefix):]
            break
    # Remove + (gtk+ → gtk)
    n = n.replace("+", "")
    # Normalize separators
    n = n.replace("-", "_").replace(".", "_").replace(" ", "_")
    # Strip version suffixes (e.g. pipewire_0_3 → pipewire)
    n = _VERSION_SUFFIX.sub("", n)
    # Strip component suffixes (e.g. wayland_client → wayland)
    for suffix in _COMPONENT_SUFFIXES:
        if n.endswith(suffix) and len(n) > len(suffix):
            n = n[: -len(suffix)]
            break
    # Apply alias mappings
    n = _ALIASES.get(n, n)
    return n
