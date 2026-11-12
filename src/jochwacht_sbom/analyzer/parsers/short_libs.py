"""Real libraries whose link name has one or two characters.

The build-file parsers dropped every ``-l`` name under three characters
("-ln -s" is make's ignore-errors prefix before ``ln``, not a
library), and the regex tier drops names of two characters or fewer. That
lost real libraries silently — measured 12.11.2026: ``-lz`` (zlib,
CVE-2022-37434 and others) vanished on every path,
the standalone collector included; ``-lpq``, ``-luv``, ``-lgd`` the same.

This fixed list names the real ones, each found on Ubuntu 24.04 as
``lib<name>.so`` with the Debian package that ships it, and the component
name a parser reports instead of the bare link name. The glibc parts
(c, m, dl, rt, util, resolv, pthread …) are not here: they stay out
(system_libs).

Some names are ambiguous across systems (ss, ts, GL and others): the entry
follows Ubuntu. Without a version the mapping is only a hint: no later
step gives such a component a version (measured 12.11.2026:
the worker's convert step lists it under "NO VERSION" and derives no
query key from it), so it names the library, never a vulnerability.
A shared leaf module (collector twin).
"""

from __future__ import annotations

#: link name (as after ``-l``, case kept) → component name.
#: The comment names the Debian package measured with ``dpkg -S``.
SHORT_LIBRARIES: dict[str, str] = {
    "z": "zlib",            # zlib1g
    "pq": "libpq",          # libpq5 (PostgreSQL client)
    "uv": "libuv",          # libuv1t64
    "gd": "libgd",          # libgd3
    "gs": "ghostscript",    # libgs10
    "ev": "libev",          # libev4t64
    "jq": "libjq",          # libjq1
    "fl": "flex",           # libfl2 (flex runtime)
    "gc": "bdwgc",          # libgc1 (Boehm GC)
    "md": "libmd",          # libmd0
    "SM": "libSM",          # libsm6
    "Xt": "libXt",          # libxt6t64
    "Xi": "libXi",          # libxi6
    "Xv": "libXv",          # libxv1
    "GL": "libglvnd",       # libgl1 (libglvnd)
    "dw": "elfutils",       # libdw1t64
    "nm": "libnm",          # libnm0 (NetworkManager)
    "ss": "libss",          # libss2 (e2fsprogs)
    "sz": "libaec",         # libsz2 (libaec szip)
    "ts": "tslib",          # libts0t64
    "va": "libva",          # libva2
    "aa": "aalib",          # libaa1
    "ao": "libao",          # libao4
    "b2": "libb2",          # libb2-1
    "dv": "libdv",          # libdv4t64
    "ei": "libei",          # libei1
    "eb": "libeb",          # libeb16t64
    "hd": "hwinfo",         # libhd21t64
    "iw": "wireless-tools", # libiw30t64
    "z3": "libz3",          # libz3-4
    "v8": "libv8",          # libnode-dev
}


def short_library(name: str) -> str:
    """The component name of a short link name, or ``""`` when it is none."""
    return SHORT_LIBRARIES.get(name, "")
