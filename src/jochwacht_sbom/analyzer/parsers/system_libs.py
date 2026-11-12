"""System libraries a link step names that are no SBOM component.

One list for every build-file reader (make, autotools, configure, CMake).
AC_SEARCH_LIBS returned c, m, rt, pthread and posix4 as
components, the make path let anl and gcc_s through. These are parts of the
C library or of the compiler runtime; the SBOM names the C library and the
toolchain elsewhere, not as a dependency of the project's build files.
"""

from __future__ import annotations

SYSTEM_LIBRARIES: frozenset[str] = frozenset({
    # parts of glibc
    "c", "m", "dl", "rt", "pthread", "resolv", "util", "anl", "nsl", "mvec",
    "crypt",
    # compiler runtime
    "gcc", "gcc_s", "stdc++", "supc++", "atomic", "cc", "stdc++fs", "c++fs", "c++",
    "c++abi", "ssp", "ssp_nonshared",
    # other C libraries' names for the same parts (Solaris, MinGW)
    "posix4", "socket", "gen", "pthreads",
    # operating system interfaces a CMake or make build names on other
    # targets (Windows, Android, Haiku): part of the system, no component
    "ws2_32", "wsock32", "mswsock", "iphlpapi", "kernel32", "user32", "gdi32",
    "advapi32", "shell32", "ole32", "oleaut32", "comdlg32", "comctl32", "winmm",
    "crypt32", "secur32", "bcrypt", "ncrypt", "userenv", "psapi", "dbghelp",
    "shlwapi", "version", "rpcrt4", "setupapi", "cfgmgr32", "ntdll", "winhttp",
    "wininet", "dnsapi", "netapi32", "imm32", "opengl32", "wtsapi32", "powrprof",
    "log", "android", "network", "gnu",
})


def is_system_library(name: str) -> bool:
    """True for a link name that is a part of the C library or compiler runtime."""
    return name in SYSTEM_LIBRARIES
