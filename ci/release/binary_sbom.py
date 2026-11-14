"""The SBOM of the standalone Linux binary (coordination, 14.11.2026).

One CycloneDX 1.6 bill per release, for the binary only: the Python
interpreter and everything PyInstaller bundled into it, read from
PyInstaller's own table of contents (``build/<name>/Analysis-00.toc``) in the
build environment the binary was built from. Nothing is guessed:

- every bundled Python module and extension is mapped to the distribution
  that installed it (``importlib.metadata`` RECORD); each such distribution
  must be pinned in the release lock (``ci/release/*.txt``), else the run
  fails: a bundled library without a pin is a gap, never silent;
- ``libpython`` and the interpreter's own extension modules form the
  CPython component, with the version of the interpreter that built it;
- any other shared library is named by its file name with its SHA-256 and,
  where dpkg knows the file, the Debian package and version; otherwise the
  version is left out and the gap is said in a property;
- PyInstaller's bootloader is part of the binary and listed as such.

File entries carry their name inside the binary and SHA-256, never a path
of the build machine.

Usage (publish workflow, after pyinstaller):
    python ci/release/binary_sbom.py --toc build/jochwacht-sbom \\
        --binary dist/jochwacht-sbom-0.21.0-linux-x86_64 \\
        --lock ci/release/runtime.txt --lock ci/release/build.txt \\
        --version 0.21.0 -o dist/jochwacht-sbom-0.21.0-linux-x86_64.cdx.json
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata as md
import json
import re
import shutil
import subprocess
import sys
import sysconfig
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")
_BUNDLED_KINDS = ("PYMODULE", "PYSOURCE", "EXTENSION", "BINARY")


class SbomError(Exception):
    """A bundled part the bill cannot account for."""


def normalize(name: str) -> str:
    """PEP 503 name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def read_pins(locks: list[Path]) -> dict[str, str]:
    """``name==version`` lines of the hashed lock files."""
    pins: dict[str, str] = {}
    for lock in locks:
        for line in lock.read_text(encoding="utf-8").splitlines():
            m = _PIN.match(line.strip())
            if m:
                pins[normalize(m.group(1))] = m.group(2)
    return pins


def toc_entries(toc_dir: Path) -> list[tuple[str, str, str]]:
    """(name in the binary, source path, kind) of every bundled entry."""
    data = ast.literal_eval((toc_dir / "Analysis-00.toc").read_text(encoding="utf-8"))
    found: list[tuple[str, str, str]] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, (list, tuple)):
            if obj and all(isinstance(e, tuple) and len(e) == 3
                           and all(isinstance(x, str) for x in e) for e in obj):
                found.extend(e for e in obj if e[2] in _BUNDLED_KINDS)
                return
            for item in obj:
                walk(item)

    walk(data)
    return found


def file_owners() -> dict[Path, md.Distribution]:
    """Every file installed by a distribution of this environment → it."""
    owners: dict[Path, md.Distribution] = {}
    for dist in md.distributions():
        for f in dist.files or []:
            try:
                owners[Path(str(dist.locate_file(f))).resolve()] = dist
            except OSError:
                continue
    return owners


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _file(name: str, path: Path) -> dict[str, Any]:
    return {"type": "file", "name": name, "bom-ref": f"file:{name}",
            "hashes": [{"alg": "SHA-256", "content": sha256(path)}]}


def _os_id() -> str:
    """The distribution's ID from /etc/os-release (the purl namespace)."""
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("ID="):
                return line[3:].strip().strip('"')
    except OSError:
        pass
    return ""


def _dpkg(path: Path) -> tuple[str, str, str]:
    """(Debian package, architecture, version) that installed *path*, or
    empty strings. ``dpkg -S`` answers ``pkg:arch: /path``; the version is
    asked for exactly that package and architecture (multiarch installs
    several)."""
    if shutil.which("dpkg") is None:
        return "", "", ""
    try:
        out = subprocess.run(["dpkg", "-S", str(path)], capture_output=True, text=True,
                             check=False, timeout=30).stdout
        first = out.splitlines()[0] if out else ""
        if ": " not in first:
            return "", "", ""
        owner = first.split(": ", 1)[0].split(",")[0].strip()
        package, _, arch = owner.partition(":")
        version = subprocess.run(["dpkg-query", "-W", "-f=${Version}", owner],
                                 capture_output=True, text=True, check=False,
                                 timeout=30).stdout.strip()
        return package, arch, version
    except (OSError, subprocess.SubprocessError):
        return "", "", ""


def _licence(dist: md.Distribution) -> list[dict[str, Any]]:
    """Only what the distribution declares as an SPDX expression (PEP 639)."""
    expr = (dist.metadata.get("License-Expression") or "").strip()
    return [{"expression": expr}] if expr else []


def build_bill(toc_dir: Path, binary: Path, locks: list[Path], version: str,
               own: Path) -> dict[str, Any]:
    """The CycloneDX document of the binary; *own* is the tool's source tree
    (its modules are the binary's own component)."""
    pins = read_pins(locks)
    own = own.resolve()
    owners = file_owners()
    stdlib = Path(sysconfig.get_paths()["stdlib"]).resolve()
    libdir = Path(sysconfig.get_config_var("LIBDIR") or stdlib.parent).resolve()
    dists: dict[str, dict[str, Any]] = {}
    python_files: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    unpinned: set[str] = set()
    for name, source, kind in toc_entries(toc_dir):
        if not source:
            continue
        path = Path(source).resolve()
        if path.is_relative_to(own):
            continue           # the tool itself: metadata.component
        dist = owners.get(path)
        if dist is not None:
            key = normalize(dist.metadata["Name"])
            if key not in pins:
                unpinned.add(f"{dist.metadata['Name']} ({name})")
                continue
            if key == "pyinstaller":
                continue       # PyInstaller's runtime modules: the bootloader component
            if pins[key] != dist.version:
                raise SbomError(f"{dist.metadata['Name']} is {dist.version} in the build "
                                f"environment but pinned {pins[key]}")
            purl = f"pkg:pypi/{key}@{dist.version}"
            entry = dists.setdefault(key, {
                "type": "library", "name": dist.metadata["Name"], "version": dist.version,
                "purl": purl, "bom-ref": purl, "components": []})
            if kind in ("EXTENSION", "BINARY"):
                entry["components"].append(_file(name, path))
            continue
        if path.is_relative_to(stdlib) or path.is_relative_to(libdir) \
                or Path(name).name.startswith("libpython"):
            if kind in ("EXTENSION", "BINARY"):
                python_files.append(_file(name, path))
            continue           # pure stdlib modules: part of the interpreter
        if kind in ("EXTENSION", "BINARY"):
            package, arch, deb_version = _dpkg(path)
            comp: dict[str, Any] = {"type": "library", "name": package or Path(name).name,
                                    "bom-ref": f"bundled:{Path(name).name}",
                                    "components": [_file(name, path)]}
            if package and deb_version:
                comp["version"] = deb_version
                namespace = _os_id() or "debian"
                qualifier = f"?arch={arch}" if arch else ""
                comp["purl"] = (f"pkg:deb/{namespace}/{package}@"
                                f"{quote(deb_version, safe='')}{qualifier}")
            else:
                comp["properties"] = [{"name": "jochwacht:version-unresolved",
                                       "value": "no package database knows this file"}]
            others.append(comp)
        else:
            raise SbomError(f"bundled module {name} belongs to no distribution and is not "
                            "part of the standard library")
    if unpinned:
        raise SbomError("bundled but not pinned in the release lock: "
                        + ", ".join(sorted(unpinned)))
    for entry in dists.values():
        if not entry["components"]:
            del entry["components"]
        dist = md.distribution(entry["name"])
        licences = _licence(dist)
        if licences:
            entry["licenses"] = licences
    py = sys.version_info
    py_version = f"{py.major}.{py.minor}.{py.micro}"
    cpython: dict[str, Any] = {
        "type": "application", "name": "cpython", "version": py_version,
        "purl": f"pkg:generic/cpython@{py_version}", "bom-ref": f"pkg:generic/cpython@{py_version}",
        "licenses": [{"license": {"id": "PSF-2.0"}}]}
    if python_files:
        cpython["components"] = sorted(python_files, key=lambda f: f["name"])
    pyinstaller = pins.get("pyinstaller", "")
    bootloader: dict[str, Any] = {
        "type": "library", "name": "pyinstaller", "version": pyinstaller,
        "purl": f"pkg:pypi/pyinstaller@{pyinstaller}",
        "bom-ref": f"pkg:pypi/pyinstaller@{pyinstaller}#bootloader",
        "properties": [{"name": "jochwacht:bundled-part",
                        "value": "bootloader and runtime modules"}]}
    components = [cpython, bootloader,
                  *sorted(dists.values(), key=lambda c: c["name"].lower()),
                  *sorted(others, key=lambda c: c["name"])]
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(tz=UTC).isoformat(timespec="seconds"),
            "lifecycles": [{"phase": "build"}],
            "tools": {"components": [{"type": "application", "name": "binary_sbom.py",
                                      "publisher": "Innomatica GmbH"}]},
            "component": {
                "type": "application", "name": "jochwacht-sbom", "version": version,
                "bom-ref": "jochwacht-sbom-binary",
                "purl": f"pkg:github/innomatica-gmbh/jochwacht-sbom@v{version}",
                "supplier": {"name": "Innomatica GmbH"},
                "licenses": [{"license": {"id": "GPL-3.0-or-later"}}],
                "hashes": [{"alg": "SHA-256", "content": sha256(binary)}],
                "properties": [{"name": "jochwacht:release-lock", "value": "sha256:"
                                + hashlib.sha256(b"".join(p.read_bytes() for p in locks))
                                .hexdigest()}],
            },
        },
        "components": components,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--toc", type=Path, required=True)
    ap.add_argument("--binary", type=Path, required=True)
    ap.add_argument("--lock", type=Path, action="append", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--own", type=Path, default=Path("src"),
                    help="the tool's own source tree (default: src)")
    ap.add_argument("-o", "--output", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        doc = build_bill(args.toc, args.binary, args.lock, args.version, args.own)
    except SbomError as exc:
        print(f"binary SBOM: {exc}", file=sys.stderr)
        return 1
    args.output.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print(f"binary SBOM: {len(doc['components'])} components -> {args.output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
