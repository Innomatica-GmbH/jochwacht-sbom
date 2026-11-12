"""Local diagnosis file for a failed run — nothing leaves the machine.

when the tool
fails, it writes ONE local file, names the path and asks in one sentence
for a mail to support@innomatica.de. No network, no question at the end
of the run, no automatic sending. The user opens the file first.

The boundary, readable here and pinned by ``tests/test_diagnosis.py``:
**the file may contain nothing the customer would not show a stranger.**

Allowed:
    tool version, Python version, operating system (no host name), which
    reader failed, the exception TYPE, the call chain inside THIS package
    (package-relative, no absolute paths), the file PATTERN that triggered
    it (a literal from our own tables, never the customer's file name), and
    for an unsupported build the labels of build-system markers from our
    own list with their counts.

Never:
    package names, versions, licenses (the bill of materials is the
    customer's product secret), full paths (project names live there),
    file contents, environment variables, host names, and the exception
    MESSAGE — a ``KeyError``'s message is the key, and the key is often a
    package name.

Two kinds of failure are told apart, because only one is a defect:

``tool_error``
    A reader crashed (or the tool crashed outside a reader). That is a bug
    in jochwacht-sbom, not in the customer's project — the bill is
    incomplete and the run ends with exit 1.
``unsupported_build``
    Nothing we read was found, but markers of build systems we do not read
    yet were. That is a roadmap line, not a bug — the run keeps exit 2.
"""

from __future__ import annotations

import fnmatch
import json
import platform
import tempfile
import traceback
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from jochwacht_sbom import __version__, env

#: Name of the diagnosis file; it is written next to the SBOM (the project
#: directory, or the directory of ``--sbom``) and replaced on every failed run.
DIAGNOSIS_FILENAME = "jochwacht-sbom-diagnosis.json"

#: Where the customer is asked to send the file — by hand, never by the tool.
SUPPORT_ADDRESS = "support@innomatica.de"

#: Environment variable that turns the sanitised report back into a plain
#: Python traceback on the terminal (for developers; nothing else changes).
#: Spelled once, in :mod:`jochwacht_sbom.env`, which also still answers to
#: the pre-rename ``JOCHWACHT_SBOM_TRACEBACK``.
TRACEBACK_ENV = env.TRACEBACK_ENV

#: Build systems jochwacht-sbom does not read yet, keyed by OUR label; the
#: values are basename globs. A hit is reported by label and count only —
#: the customer's file names never appear anywhere. Keep this list to what
#: is not covered by ``sbom.scanner._SCANNERS``, ``analyzer.scanner.
#: BUILD_FILE_PATTERNS``, the FPGA readers and the Yocto/Buildroot output
#: readers, so a label here always means "no reader exists".
UNSUPPORTED_MARKERS: dict[str, tuple[str, ...]] = {
    "bazel": ("BUILD.bazel", "MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel"),
    "buck": ("BUCK",),
    "gn": ("BUILD.gn", ".gn"),
    "scons": ("SConstruct", "SConscript"),
    "waf": ("wscript",),
    "premake": ("premake5.lua", "premake4.lua"),
    "xmake": ("xmake.lua",),
    "qmake": ("*.pro", "*.pri"),
    "qbs": ("*.qbs",),
    "msbuild-cpp": ("*.vcxproj",),
    "zig": ("build.zig", "build.zig.zon"),
    "swiftpm": ("Package.swift", "Package.resolved"),
    "cocoapods": ("Podfile", "Podfile.lock"),
    "dart-pub": ("pubspec.yaml", "pubspec.lock"),
    "rubygems": ("Gemfile", "Gemfile.lock"),
    "composer": ("composer.json", "composer.lock"),
    "hex": ("mix.exs", "mix.lock", "rebar.config", "rebar.lock"),
    "haskell": ("stack.yaml", "cabal.project", "*.cabal"),
    "opam": ("dune-project", "*.opam"),
    "dub": ("dub.json", "dub.sdl"),
    "nimble": ("*.nimble",),
    "sbt": ("build.sbt",),
    "leiningen": ("project.clj",),
    "ant-ivy": ("ivy.xml",),
    "deno": ("deno.json", "deno.lock"),
    "bun": ("bun.lockb", "bun.lock"),
    "julia": ("Manifest.toml",),
    "r-renv": ("renv.lock",),
    "nix": ("flake.nix", "default.nix", "shell.nix"),
    "gprbuild": ("*.gpr",),
    "platformio": ("platformio.ini",),
    "arduino": ("library.properties", "sketch.yaml"),
    "mbed": ("mbed_app.json", "mbed-os.lib", ".mbed"),
    "esp-idf-components": ("idf_component.yml",),
    "keil": ("*.uvprojx", "*.uvproj"),
    "iar": ("*.ewp", "*.eww"),
    "eclipse-cdt": (".cproject",),
    "stm32cubemx": ("*.ioc",),
    "ti-ccs": (".ccsproject",),
    "atmel-studio": ("*.cproj", "*.atsln"),
    "segger-es": ("*.emProject",),
    "codeblocks": ("*.cbp",),
    "vivado-project": ("*.xpr",),
    "quartus-project": ("*.qpf", "*.qsf"),
    "libero-project": ("*.prjx",),
    "lattice-project": ("*.ldf", "*.rdf"),
    "gowin-project": ("*.gprj",),
    "yocto-layer": ("*.bb", "*.bbappend", "layer.conf"),
    "buildroot-external": ("external.desc", "external.mk"),
}

_PKG_ROOT = Path(__file__).resolve().parent

_ABOUT = (
    "Written by jochwacht-sbom after a failed run, for a mail to "
    f"{SUPPORT_ADDRESS}. It contains no package names, versions, licenses, "
    "file paths, file contents, environment variables or host names — open "
    "it and check. Nothing is sent automatically: this file leaves your "
    "machine only if you send it."
)


@dataclass
class ReaderFailure:
    """One crashed reader — the sanitised trace of a defect in this tool."""

    #: A key from our own tables: ``pom_xml``, ``tier2:structured-pom-xml``,
    #: ``build_output`` — or ``""`` when the tool crashed outside a reader.
    reader: str
    #: The file pattern the reader was called for, as a literal from our
    #: tables (``pom.xml``, ``*.csproj``, ``maven``) — never a real name.
    pattern: str
    #: The exception's class name only. Its message is never recorded.
    exc_type: str
    #: Frames inside this package, innermost last: ``sbom/scanner.py:
    #: scan_pom_xml:951``. Frames from the standard library, from other
    #: packages and from anything else on the machine are dropped.
    frames: list[str] = field(default_factory=list)


_failures: list[ReaderFailure] = []


def reset() -> None:
    """Forget recorded failures (start of a run, and between tests)."""
    _failures.clear()


def failures() -> list[ReaderFailure]:
    """The failures recorded so far in this process, oldest first."""
    return list(_failures)


def own_frames(exc: BaseException) -> list[str]:
    """The call chain of *exc* restricted to this package.

    A frame is kept only when its source file lies under ``jochwacht_sbom``;
    it is written package-relative (``sbom/scanner.py:scan_pom_xml:951``),
    so no absolute path — and therefore no user name, project name or
    virtualenv location — reaches the file. Source lines are not copied.
    """
    out: list[str] = []
    for fr in traceback.extract_tb(exc.__traceback__):
        try:
            rel = Path(fr.filename).resolve().relative_to(_PKG_ROOT)
        except (ValueError, OSError):
            continue
        out.append(f"{rel.as_posix()}:{fr.name}:{fr.lineno}")
    return out


def record_failure(reader: str, pattern: str, exc: BaseException) -> ReaderFailure:
    """Record a crashed reader; the caller continues with the next file.

    Only the exception's TYPE and its in-package frames are kept — see the
    module docstring for why the message must not be.
    """
    failure = ReaderFailure(
        reader=reader,
        pattern=pattern,
        exc_type=type(exc).__name__,
        frames=own_frames(exc),
    )
    _failures.append(failure)
    return failure


def _platform_line() -> str:
    """Operating system and machine — ``platform.platform()`` carries no
    host name (``platform.node()`` is deliberately never used)."""
    try:
        return platform.platform()
    except Exception:  # noqa: BLE001 — a diagnosis must never crash itself
        return "unknown"


def _base_report(kind: str, *, build_files_scanned: int) -> dict[str, object]:
    return {
        "_about": _ABOUT,
        "kind": kind,
        "tool": "jochwacht-sbom",
        "tool_version": __version__,
        "python": platform.python_version(),
        "platform": _platform_line(),
        "written_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "build_files_scanned": build_files_scanned,
    }


def tool_error_report(
    recorded: list[ReaderFailure], *, build_files_scanned: int,
) -> dict[str, object]:
    """Report for ``kind: tool_error`` — one or more readers crashed."""
    report = _base_report("tool_error", build_files_scanned=build_files_scanned)
    report["failures"] = [asdict(f) for f in recorded]
    return report


def crash_report(exc: BaseException, *, build_files_scanned: int = 0) -> dict[str, object]:
    """Report for a crash OUTSIDE a reader (payload, SBOM writer, …)."""
    failure = record_failure("", "", exc)
    return tool_error_report([failure], build_files_scanned=build_files_scanned)


def unsupported_build_report(
    markers: dict[str, int], *, build_files_scanned: int,
) -> dict[str, object]:
    """Report for ``kind: unsupported_build`` — labels and counts only."""
    report = _base_report("unsupported_build", build_files_scanned=build_files_scanned)
    report["unsupported_markers"] = dict(sorted(markers.items()))
    return report


def write_report(report: dict[str, object], *, near: Path) -> Path:
    """Write *report* as pretty JSON next to the SBOM and return the path.

    When that directory cannot be written, the file goes to the system's
    temporary directory instead — the run must still be able to say where
    the diagnosis is.
    """
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    target = near / DIAGNOSIS_FILENAME
    try:
        target.write_text(text, encoding="utf-8")
        return target
    except OSError:
        fallback = Path(tempfile.gettempdir()) / DIAGNOSIS_FILENAME
        fallback.write_text(text, encoding="utf-8")
        return fallback


def find_unsupported_markers(path: Path, *, max_depth: int = 5) -> dict[str, int]:
    """Count marker files of build systems we do not read, by OUR label.

    Walks the tree with the same rules as the dependency scan (hidden and
    build-output directories skipped, ``.jochwachtignore`` honoured, same
    depth). Returns ``{label: count}`` for labels with at least one hit —
    never a file name.
    """
    # Local import: the scanner records failures through this module.
    from jochwacht_sbom.sbom.scanner import (
        DEFAULT_EXCLUDE_DIRS,
        _is_ignored,
        load_ignore_patterns,
    )

    patterns = load_ignore_patterns(path)
    counts: dict[str, int] = {}

    def _label(name: str) -> str | None:
        for label, globs in UNSUPPORTED_MARKERS.items():
            if any(fnmatch.fnmatchcase(name, g) for g in globs):
                return label
        return None

    def _walk(current: Path, depth: int) -> None:
        try:
            entries = sorted(current.iterdir())
        except OSError:
            return
        for entry in entries:
            name = entry.name
            label = _label(name)
            if label is not None:
                counts[label] = counts.get(label, 0) + 1
            if not entry.is_dir() or depth >= max_depth:
                continue
            if name.startswith(".") or name in DEFAULT_EXCLUDE_DIRS:
                continue
            try:
                rel = entry.relative_to(path).as_posix()
            except ValueError:
                rel = name
            if _is_ignored(rel, name, patterns):
                continue
            _walk(entry, depth + 1)

    _walk(path, 0)
    return counts


def format_markers(markers: dict[str, int]) -> str:
    """``bazel (3), keil (1)`` — labels and counts, sorted by label."""
    return ", ".join(f"{label} ({n})" for label, n in sorted(markers.items()))
