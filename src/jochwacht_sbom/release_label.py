"""Where the release label comes from when --release names none.

Coordination, 13.11.2026: without --release / JOCHWACHT_RELEASE the collector
takes what is proven, never a guess:

1. the git tag exactly on the current commit (as ``git describe --tags
   --exact-match``), lightweight or annotated, loose or packed;
2. else the product version the one build directory states, when it is the
   customer's and not a tool default (Buildroot's own version, which
   generate-cyclonedx writes when no --project-version is given; Yocto's
   PV "1.0", bitbake's default for an image recipe). A default would give
   every new firmware the same label, and per the contract of 27 the same
   label replaces the previous version of that release.

Never the "next" tag, never a commit hash. The repository is read as files;
git itself is never run, because a scanned repository (a pull request from a
fork in CI) must not get its configuration executed. Only ``<path>/.git``
as a folder inside the scanned path is read.
"""

from __future__ import annotations

import re
import zlib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jochwacht_sbom.payload import CheckStats

_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")   # SHA-1 or SHA-256
_REF_LIMIT = 1 << 20          # packed-refs, HEAD and loose refs: never more than 1 MiB
_OBJECT_LIMIT = 1 << 16       # a tag object holds a few lines; more is not one


def _inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError):
        return False


def _read(path: Path, git: Path, limit: int = _REF_LIMIT) -> bytes | None:
    """A file of the repository, only inside it, never through a link out."""
    if not path.is_file() or not _inside(path, git):
        return None
    try:
        with path.open("rb") as fh:
            data = fh.read(limit + 1)
    except OSError:
        return None
    return data if len(data) <= limit else None


def _text(data: bytes | None) -> str:
    return data.decode("utf-8", errors="replace") if data is not None else ""


def _packed(git: Path) -> tuple[dict[str, str], dict[str, str]]:
    """(ref → object, ref → peeled commit) from packed-refs."""
    refs: dict[str, str] = {}
    peeled: dict[str, str] = {}
    last = ""
    for line in _text(_read(git / "packed-refs", git)).splitlines():
        if line.startswith("^") and last and _SHA.fullmatch(line[1:].strip()):
            peeled[last] = line[1:].strip()
            continue
        parts = line.split(" ", 1)
        if len(parts) == 2 and _SHA.fullmatch(parts[0]):
            last = parts[1].strip()
            refs[last] = parts[0]
        else:
            last = ""
    return refs, peeled


def _ref(git: Path, name: str, packed: dict[str, str]) -> str:
    loose = _text(_read(git / name, git)).strip()
    if _SHA.fullmatch(loose):
        return loose
    return packed.get(name, "")


def _head(git: Path, packed: dict[str, str]) -> str:
    head = _text(_read(git / "HEAD", git)).strip()
    if _SHA.fullmatch(head):
        return head                      # detached, as in most CI checkouts
    if head.startswith("ref: refs/"):
        return _ref(git, head[5:].strip(), packed)
    return ""


def _tag_target(git: Path, sha: str) -> str:
    """The object a loose annotated tag object points to, "" when it is no
    loose tag object (a commit, or a packed object we do not read)."""
    raw = _read(git / "objects" / sha[:2] / sha[2:], git, _OBJECT_LIMIT)
    if raw is None:
        return ""
    try:
        data = zlib.decompressobj().decompress(raw, _OBJECT_LIMIT)
    except zlib.error:
        return ""
    header, _, body = data.partition(b"\0")
    if not header.startswith(b"tag "):
        return ""
    m = re.match(rb"object ([0-9a-f]{40}(?:[0-9a-f]{24})?)\n", body)
    return m.group(1).decode() if m else ""


def _loose_tags(git: Path) -> dict[str, str]:
    tags: dict[str, str] = {}
    root = git / "refs" / "tags"
    if not root.is_dir() or not _inside(root, git):
        return tags
    for path in sorted(root.rglob("*")):
        sha = _text(_read(path, git)).strip()
        if _SHA.fullmatch(sha):
            tags["refs/tags/" + path.relative_to(root).as_posix()] = sha
    return tags


def git_tag_on_head(path: Path) -> tuple[list[str], str]:
    """(tags exactly on HEAD, sorted; a note why nothing was read, or "").

    A tag counts when its ref, or the annotated tag object it names, points at
    the HEAD commit. An annotated tag whose object lies only in a pack is not
    proven here and does not count (``git pack-refs`` writes the peeled
    commit, which is read).
    """
    git = path / ".git"
    if git.is_symlink() or (git.exists() and not _inside(git, path)):
        return [], ".git points outside the scanned folder; not read"
    if git.is_file():
        return [], ".git is a file (a worktree or a submodule); its repository is not read"
    if not git.is_dir():
        return [], ""
    packed, peeled = _packed(git)
    head = _head(git, packed)
    if not head:
        return [], ""
    refs = {name: sha for name, sha in packed.items() if name.startswith("refs/tags/")}
    refs.update(_loose_tags(git))        # a loose ref wins over its packed copy
    found: list[str] = []
    for name, sha in refs.items():
        on_head = (
            sha == head                                              # lightweight
            or (packed.get(name) == sha and peeled.get(name) == head)  # packed, peeled
            or _tag_target(git, sha) == head                         # loose tag object
        )
        if on_head:
            found.append(name[len("refs/tags/"):])
    return sorted(found), ""


def build_version_is_default(kind: str, version: str, tool_version: str) -> bool:
    """A product version a build tool writes by itself, never the customer's:
    Buildroot's own version (generate-cyclonedx --project-version defaults to
    BR2_VERSION_FULL), Yocto's PV "1.0" (bitbake's default for a recipe whose
    file name carries no version, as an image recipe's)."""
    if kind == "buildroot":
        # Without the .config header Buildroot's own version is unknown, and
        # the product version cannot be shown to be the customer's.
        return not version or not tool_version or version == tool_version
    if kind == "yocto":
        return not version or version == "1.0"
    return True


def derive(path: Path, stats: CheckStats) -> tuple[str, str, str]:
    """(label, where it comes from, why none was found) for a run without
    --release. Several tags on the commit are not chosen between: the
    customer names one."""
    tags, note = git_tag_on_head(path)
    if len(tags) == 1:
        return tags[0], "the git tag on the current commit", ""
    if len(tags) > 1:
        return "", "", (f"the current commit carries several git tags ({', '.join(tags)}); "
                        "name the one this version is")
    why = [note or "no git tag on the current commit"]
    if stats.build_product and stats.build_product_kind:
        name, version = stats.build_product
        kind, tool = stats.build_product_kind, stats.build_tool_version
        if not build_version_is_default(kind, version, tool):
            where = ("the Buildroot build (product version in legal-info/buildroot.cdx.json)"
                     if kind == "buildroot" else
                     f"the Yocto build (PV of the image recipe {name} in testdata.json)")
            return version, where, ""
        if kind == "buildroot" and version and version == tool:
            why.append(f"the Buildroot build states Buildroot's own version {version} "
                       "(generate-cyclonedx without --project-version), not your release")
        elif kind == "buildroot" and version:
            why.append(f"the Buildroot build states {version}, but without its .config it "
                       "cannot be told from Buildroot's own version")
        elif kind == "yocto" and version:
            why.append(f'the Yocto build states PV "{version}" for {name}, bitbake\'s '
                       "default, not your release")
    return "", "", "; ".join(why)
