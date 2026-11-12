"""One size limit for every build file and lockfile a reader takes.

The tree walk named a file over 64 MiB as skipped, and the
pipeline still read it whole — measured 12.11.2026 through the collector
(both tools alike) with ten 65 MiB files: tier2_structured read
Cargo.toml, build.gradle, conanfile.txt, go.mod, meson.build, package.json
and pom.xml (five components came out of them), the CMake context read
CMakeCache.txt. Every gate asks :func:`too_large` now: the tree walk
(sbom/scanner.py), the pipeline's file collection
(analyzer/scanner.py collect_build_files), the regex tier and the CMake
context. A leaf module, shared with the collector twin.
"""

from __future__ import annotations

import os
from pathlib import Path

from jochwacht_sbom.core.log import get_logger

logger = get_logger(__name__)

#: Largest build file or lockfile read.
MAX_BUILD_FILE = 64 * 1024 * 1024


def too_large(path: str | os.PathLike[str] | Path) -> bool:
    """Whether *path* is over :data:`MAX_BUILD_FILE` bytes. A file that
    cannot be stat'ed is not "too large" here — its reader reports it."""
    try:
        return os.stat(path).st_size > MAX_BUILD_FILE
    except OSError:
        return False


#: The files skipped as too large in this run: resolved path → (name, size).
#: Every gate notes here; the collector reads it into its counts, each file
#: once (a skipped jochwacht-deps.yaml was only a log line).
_SKIPPED: dict[str, tuple[str, int]] = {}


def note_skipped(path: str | os.PathLike[str] | Path) -> None:
    """Record *path* as skipped for its size and name it once per run."""
    p = Path(path)
    try:
        key = str(p.resolve())
        size = p.stat().st_size
    except OSError:
        key, size = str(p), -1
    if key in _SKIPPED:
        return
    _SKIPPED[key] = (p.name, size)
    logger.warning("Skipped %s: %d bytes, more than the %d a build file may have",
                   p, size, MAX_BUILD_FILE)


def reset_skipped() -> None:
    _SKIPPED.clear()


def skipped_names() -> list[str]:
    """File NAMES (never paths) of the skipped files, sorted, each once."""
    return sorted(name for name, _size in _SKIPPED.values())
