"""What a Yocto build directory proves (pure core, order suite-d).

Shared file: the open collector carries a generated copy (ci/sync-twin.py),
so suite and collector read a Yocto build with the same code — standard
library and :mod:`jochwacht_sbom.sbom.build_files` only, no model of either half
(:func:`yocto_build` is the composition both map onto their records).

Delivered is the image (sicherheit-2, TR-03183-2 §3.2.1/§3.2.2/§8.1.11,
13.11.2026). A runtime package is a logical component; its regular files in
the image's root file system are the file components. Everything is proven
by the build's own records, never by a file name:

* :func:`yocto_evidence` — files per runtime package. The rootfs is the tar
  the image recipe wrote (``IMAGE_NAME`` + a ``tar*`` entry of
  ``IMAGE_FSTYPES``, both from the image's ``*.testdata.json``); the owner of
  a path is the runtime package whose ``pkgdata/<machine>/runtime/<pkg>``
  lists it in ``FILES_INFO``; the key is the output name ``PKG:<pkg>`` (after
  debian renaming, as create-spdx names its package documents). A path two
  packages list belongs to neither. Symlinks, devices and members leaving the
  root are no files.
* :func:`yocto_image_evidence` — the image files (``IMAGE_NAME.<fstype>``),
  the kernel (``KERNEL_IMAGETYPE`` link in the deploy folder, assigned to
  ``PREFERRED_PROVIDER_virtual/kernel``) and the rootfs files no package
  lists (written at image time: ld.so.cache, passwd, the package database).
* :func:`yocto_feed_evidence` — the package archive per runtime package from
  the feed (RPM header against pkgdata). Only for a product that ships its
  feed; not the default path (§8.1.11 scope of delivery).

Hashes and flags come from :func:`~jochwacht_sbom.sbom.build_evidence.file_facts`
and :func:`~jochwacht_sbom.sbom.build_evidence.file_facts_from_stream` — one rule.
"""

from __future__ import annotations

import json
import logging
import os
import struct
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from jochwacht_sbom.sbom.build_files import (
    REASON_CREATOR_NO_URL,
    REASON_NO_DELIVERED_FILE,
    REASON_NO_EXECUTABLE_FILE,
    REASON_NOT_DELIVERED,
    ComponentEvidence,
    Creator,
    EntryEvidence,
    FileFacts,
    FileRecord,
    component_files,
    file_facts,
    file_facts_from_stream,
)

logger = logging.getLogger(__name__)

ORIGIN_YOCTO_RPM = "yocto:deploy/rpm"
ORIGIN_YOCTO_ROOTFS = "yocto:rootfs (pkgdata FILES_INFO)"
ORIGIN_YOCTO_IMAGES = "yocto:deploy/images (IMAGE_NAME, IMAGE_FSTYPES)"
ORIGIN_YOCTO_KERNEL = "yocto:deploy/images (KERNEL_IMAGETYPE, PREFERRED_PROVIDER_virtual/kernel)"

#: tar compressions Python's tarfile reads (``tar.zst`` needs Python 3.14).
_TAR_FSTYPES = {"tar": "r:", "tar.gz": "r:gz", "tar.bz2": "r:bz2", "tar.xz": "r:xz"}

#: Feed directory below ``deploy/`` per ``IMAGE_PKGTYPE``.
_FEED_DIRS = {"rpm": "rpm", "ipk": "ipk", "deb": "deb"}

_RPM_LEAD_MAGIC = b"\xed\xab\xee\xdb"
_RPM_HEADER_MAGIC = b"\x8e\xad\xe8\x01"
_RPM_LEAD_LEN = 96
#: Sanity bounds of a header: far above any real package, small enough that
#: a damaged count cannot make us read gigabytes.
_RPM_MAX_INDEX = 65536
_RPM_MAX_STORE = 64 << 20

_TAG_NAME, _TAG_VERSION, _TAG_RELEASE, _TAG_EPOCH = 1000, 1001, 1002, 1003
_TYPE_INT32, _TYPE_STRING = 4, 6

#: (name, epoch, version, release) — epoch "" when the package has none.
RpmIdentity = tuple[str, str, str, str]


def _read_header(fh: BinaryIO, *, pad: bool) -> dict[int, tuple[int, int, int, bytes]]:
    """One RPM header structure: {tag: (type, offset, count, store)}."""
    read = fh.read
    intro = read(16)
    if len(intro) != 16 or intro[:4] != _RPM_HEADER_MAGIC:
        raise ValueError("no RPM header magic")
    nindex, hsize = struct.unpack(">II", intro[8:16])
    if nindex > _RPM_MAX_INDEX or hsize > _RPM_MAX_STORE:
        raise ValueError("RPM header out of bounds")
    index = read(16 * nindex)
    store = read(hsize)
    if len(index) != 16 * nindex or len(store) != hsize:
        raise ValueError("truncated RPM header")
    if pad:
        read((8 - hsize % 8) % 8)  # the signature header is padded to 8
    tags: dict[int, tuple[int, int, int, bytes]] = {}
    for i in range(nindex):
        tag, typ, offset, count = struct.unpack(">iiii", index[16 * i:16 * i + 16])
        tags[tag] = (typ, offset, count, store)
    return tags


def _string(tags: dict[int, tuple[int, int, int, bytes]], tag: int) -> str:
    typ, offset, _count, store = tags[tag]
    if typ != _TYPE_STRING or not 0 <= offset < len(store):
        raise ValueError(f"RPM tag {tag} is no string")
    end = store.find(b"\x00", offset)
    if end < 0:
        raise ValueError(f"RPM tag {tag} is not terminated")
    return store[offset:end].decode("utf-8")


def rpm_identity(path: Path) -> RpmIdentity:
    """NAME, EPOCH, VERSION, RELEASE from the header of the RPM at *path*.

    Raises:
        ValueError: not an RPM, or a damaged header.
        OSError: the file cannot be read.
    """
    with path.open("rb") as fh:
        lead = fh.read(_RPM_LEAD_LEN)
        if len(lead) != _RPM_LEAD_LEN or lead[:4] != _RPM_LEAD_MAGIC:
            raise ValueError("no RPM lead")
        _read_header(fh, pad=True)            # signature header
        tags = _read_header(fh, pad=False)    # main header
    epoch = ""
    if _TAG_EPOCH in tags:
        typ, offset, count, store = tags[_TAG_EPOCH]
        if typ != _TYPE_INT32 or count < 1 or not 0 <= offset <= len(store) - 4:
            raise ValueError("RPM epoch is no int32")
        epoch = str(struct.unpack(">i", store[offset:offset + 4])[0])
    try:
        return (_string(tags, _TAG_NAME), epoch,
                _string(tags, _TAG_VERSION), _string(tags, _TAG_RELEASE))
    except KeyError as exc:
        raise ValueError(f"RPM header lacks tag {exc}") from exc


def _within(path: Path, root: Path) -> bool:
    """*path* resolves to a place inside *root* (review suite-c, Y1: no root
    of the reading may be a link out of the build directory)."""
    try:
        return path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError):
        return False


def _tmp_dir(build_dir: Path) -> Path | None:
    """The bitbake TMPDIR: *build_dir*/tmp, or *build_dir* itself.

    Only inside *build_dir*: a ``tmp`` that is a link elsewhere is not read
    (a TMPDIR on another disk is named as the build directory itself).
    """
    for candidate in (build_dir / "tmp", build_dir):
        if (candidate / "deploy").is_dir() and (candidate / "pkgdata").is_dir() \
                and _within(candidate, build_dir) and _within(candidate / "deploy", candidate) \
                and _within(candidate / "pkgdata", candidate):
            return candidate
    return None


#: Roots of the reading below TMPDIR (globs), checked for links out of it.
_ROOTS = ("deploy", "pkgdata", "deploy/images", "deploy/images/*", "pkgdata/*",
          "pkgdata/*/runtime", "deploy/spdx", "deploy/rpm", "deploy/ipk", "deploy/deb")


def outside_roots(build_dir: Path) -> list[str]:
    """Warnings for every root of the reading that points outside the build
    directory and is therefore not read — named, not dropped silently."""
    out: list[str] = []
    for tmp in (build_dir / "tmp", build_dir):
        if tmp.exists() and tmp != build_dir and not _within(tmp, build_dir):
            out.append(f"{tmp.name} points outside the build directory; not read")
            continue
        if not (tmp / "deploy").exists() and not (tmp / "pkgdata").exists():
            continue
        for pattern in _ROOTS:
            for root in sorted(tmp.glob(pattern)):
                if root.exists() and not _within(root, tmp):
                    out.append(f"{root.relative_to(build_dir).as_posix()} points outside "
                               "the build directory; not read")
        break
    return out


def _image_statements(tmp: Path) -> tuple[set[str], set[str]]:
    """(IMAGE_PKGTYPE values, PKGDATA_DIR basenames) the images state."""
    pkgtypes: set[str] = set()
    pkgdata: set[str] = set()
    images = tmp / "deploy" / "images"
    if not images.is_dir():
        return pkgtypes, pkgdata
    for testdata in sorted(images.rglob("*.testdata.json")):
        if testdata.is_symlink():
            continue  # the dated file is read, its 'latest' link would repeat it
        try:
            data = json.loads(testdata.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        if isinstance(data.get("IMAGE_PKGTYPE"), str):
            pkgtypes.add(data["IMAGE_PKGTYPE"])
        if isinstance(data.get("PKGDATA_DIR"), str):
            pkgdata.add(Path(data["PKGDATA_DIR"]).name)
    return pkgtypes, pkgdata


def _feed(tmp: Path, pkgtypes: set[str]) -> str | None:
    """The feed type the image is installed from, or None when not proven."""
    present = {t for t, d in _FEED_DIRS.items() if (tmp / "deploy" / d).is_dir()}
    if pkgtypes:
        if len(pkgtypes) != 1:
            logger.warning("Yocto evidence: images name several feed types %s", sorted(pkgtypes))
            return None
        (stated,) = pkgtypes
        return stated if stated in present else None
    if len(present) == 1:
        return next(iter(present))
    if present:
        logger.warning("Yocto evidence: feeds %s and no IMAGE_PKGTYPE — not proven",
                       sorted(present))
    return None


def _walk_files(root: Path, suffix: str) -> list[str]:
    """Regular files ending in *suffix* below *root*, relative, no symlinks."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if name.endswith(suffix) and not path.is_symlink() and path.is_file():
                found.append(path.relative_to(root).as_posix())
    return found


def _rpm_index(feed_root: Path) -> dict[RpmIdentity, list[str]]:
    """Every readable RPM of the feed by the identity its header states."""
    index: dict[RpmIdentity, list[str]] = {}
    skipped = 0
    for rel in _walk_files(feed_root, ".rpm"):
        try:
            identity = rpm_identity(feed_root / rel)
        except (ValueError, OSError, UnicodeDecodeError):
            skipped += 1
            continue
        index.setdefault(identity, []).append(rel)
    if skipped:
        logger.warning("Yocto evidence: %d unreadable RPM file(s) in %s skipped",
                       skipped, feed_root)
    return index


def _pkgdata_fields(path: Path, pkg: str) -> dict[str, str]:
    """The keys of one pkgdata runtime file this reader needs."""
    wanted = {f"PKG:{pkg}": "PKG", "PKGE": "PKGE", "PKGV": "PKGV", "PKGR": "PKGR"}
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = line.partition(": ")
        if sep and key in wanted:
            fields[wanted[key]] = value.strip()
    return fields


def _runtime_dirs(tmp: Path, stated: set[str]) -> list[Path]:
    pkgdata = tmp / "pkgdata"
    if stated:
        dirs = [pkgdata / name / "runtime" for name in sorted(stated)]
    else:
        dirs = sorted(pkgdata.glob("*/runtime"))
    return [d for d in dirs if d.is_dir() and not d.is_symlink() and _within(d, tmp)]


def yocto_feed_evidence(build_dir: Path) -> dict[str, ComponentEvidence]:
    """The package archive per Yocto runtime package (product ships its feed).

    Keys are output package names (``PKG``, as create-spdx names its
    package documents). A packaged runtime package whose archive the feed
    does not hold, and a package bitbake never wrote, get no file. Without
    pkgdata or a proven feed: an empty result (nothing proven).
    """
    tmp = _tmp_dir(build_dir)
    if tmp is None:
        return {}
    pkgtypes, stated_pkgdata = _image_statements(tmp)
    feed = _feed(tmp, pkgtypes)
    if feed is None:
        return {}
    if feed != "rpm":
        logger.warning("Yocto evidence: feed type %s is not read yet", feed)
        return {}
    feed_root = tmp / "deploy" / _FEED_DIRS[feed]
    if not _within(feed_root, tmp):
        return {}
    runtime_dirs = _runtime_dirs(tmp, stated_pkgdata)
    if not runtime_dirs:
        return {}
    index = _rpm_index(feed_root)

    result: dict[str, ComponentEvidence] = {}
    for runtime in runtime_dirs:
        for entry in sorted(runtime.iterdir()):
            pkg = entry.name
            if pkg.endswith(".packaged") or entry.is_symlink() or not entry.is_file():
                continue
            try:
                fields = _pkgdata_fields(entry, pkg)
            except OSError:
                continue
            name = fields.get("PKG") or pkg
            files: list[FileFacts] = []
            if (runtime / f"{pkg}.packaged").is_file() and "PKGV" in fields:
                identity = (name, fields.get("PKGE", ""),
                            fields["PKGV"].replace("-", "+"), fields.get("PKGR", ""))
                for rel in index.get(identity, []):
                    try:
                        files.append(file_facts(feed_root, rel))
                    except (ValueError, OSError):
                        continue
            known = result.get(name)
            if known is not None:
                files = [*known.files, *(f for f in files if f not in known.files)]
            result[name] = ComponentEvidence(name, tuple(files), ORIGIN_YOCTO_RPM)
    return result


# ---------------------------------------------------------------------------
# The image: rootfs files per runtime package, image files, kernel
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class YoctoImageEvidence:
    """What the deploy folder delivers besides the packages' files."""

    per_package: dict[str, list[FileFacts]] = field(default_factory=dict)  # kernel
    images: list[FileFacts] = field(default_factory=list)   # IMAGE_NAME.<fstype>
    unowned: list[FileFacts] = field(default_factory=list)  # rootfs, no package
    #: rootfs paths that occur more than once in the tar: extraction keeps the
    #: last, so no hash is claimed for them (review sicherheit-2, YE1).
    duplicates: list[str] = field(default_factory=list)
    #: hard-link members: no file of their own, named instead of skipped.
    hardlinks: list[str] = field(default_factory=list)
    #: why the rootfs was not read at all ("" = read).
    aborted: str = ""


#: Limits of the rootfs tar (a customer upload in the worker): exceeding one
#: aborts the reading — nothing is proven, nothing is truncated.
MAX_ROOTFS_MEMBERS = 1_000_000
MAX_ROOTFS_BYTES = 32 << 30


class _RootfsLimitError(Exception):
    """The rootfs tar exceeds a reading limit."""


@dataclass(frozen=True)
class _Image:
    folder: Path              # DEPLOY_DIR_IMAGE
    data: dict[str, object]   # the testdata keys


def _stated_images(tmp: Path) -> list[_Image]:
    """Every image a regular ``*.testdata.json`` describes."""
    found: list[_Image] = []
    images = tmp / "deploy" / "images"
    if not images.is_dir():
        return found
    for testdata in sorted(images.glob("*/*.testdata.json")):
        if testdata.is_symlink():
            continue  # the IMAGE_LINK_NAME alias of a dated file
        if not _within(testdata.parent, tmp):
            continue  # a machine folder linked from elsewhere (named by outside_roots)
        try:
            data = json.loads(testdata.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("IMAGE_NAME"), str):
            found.append(_Image(testdata.parent, data))
    return found


def _fstypes(image: _Image) -> list[str]:
    value = image.data.get("IMAGE_FSTYPES")
    return value.split() if isinstance(value, str) else []


def _regular(folder: Path, name: str) -> Path | None:
    """*name* in *folder* as a regular file; a link only to a file in *folder*."""
    if not name or "/" in name or name in (".", ".."):
        return None
    path = folder / name
    if path.is_symlink():
        target = Path(os.readlink(path))
        if target.is_absolute() or len(target.parts) != 1:
            return None  # the link leaves the deploy folder
        path = folder / target.name
        if path.is_symlink():
            return None
    return path if path.is_file() else None


def _owners(tmp: Path, images: list[_Image]) -> dict[str, set[str]]:
    """rootfs path -> output package names that list it in FILES_INFO."""
    stated = {Path(str(i.data["PKGDATA_DIR"])).name for i in images
              if isinstance(i.data.get("PKGDATA_DIR"), str)}
    owners: dict[str, set[str]] = {}
    for runtime in _runtime_dirs(tmp, stated):
        for entry in sorted(runtime.iterdir()):
            pkg = entry.name
            if pkg.endswith(".packaged") or entry.is_symlink() or not entry.is_file():
                continue
            name, paths = pkg, []
            prefix_pkg, prefix_files = f"PKG:{pkg}: ", f"FILES_INFO:{pkg}: "
            try:
                lines = entry.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for line in lines:
                if line.startswith(prefix_pkg):
                    name = line[len(prefix_pkg):].strip() or pkg
                elif line.startswith(prefix_files):
                    try:
                        listed = json.loads(line[len(prefix_files):])
                    except ValueError:
                        listed = {}
                    paths = [str(p) for p in listed] if isinstance(listed, dict) else []
            for path in paths:
                owners.setdefault(path, set()).add(name)
    return owners


def _member_path(name: str) -> str | None:
    """A tar member name as a path relative to the rootfs, or None."""
    rel = name[2:] if name.startswith("./") else name
    pure = PurePosixPath(rel)
    if not rel or pure.is_absolute() or ".." in pure.parts or rel in (".",):
        return None
    return pure.as_posix()


def _scan(build_dir: Path) -> tuple[dict[str, ComponentEvidence], YoctoImageEvidence]:
    tmp = _tmp_dir(build_dir)
    if tmp is None:
        return {}, YoctoImageEvidence()
    images = _stated_images(tmp)
    owners = _owners(tmp, images)
    per_package: dict[str, list[FileFacts]] = {}
    unowned: list[FileFacts] = []
    image_files: list[FileFacts] = []
    kernels: dict[str, list[FileFacts]] = {}
    read_rootfs = False
    aborted = ""
    duplicates: list[str] = []
    hardlinks: list[str] = []
    for image in images:
        name = str(image.data["IMAGE_NAME"])
        for fstype in _fstypes(image):
            path = _regular(image.folder, f"{name}.{fstype}")
            if path is None:
                continue  # stated, but not in the folder: not invented
            try:
                image_files.append(file_facts(image.folder, path.name))
            except (ValueError, OSError):
                continue
            mode = _TAR_FSTYPES.get(fstype)
            if mode is None or not owners:
                if fstype.startswith("tar"):
                    logger.warning("Yocto evidence: %s cannot be read (no reader for %s)",
                                   path.name, fstype)
                continue
            try:
                dup, links = _read_rootfs(path, mode, owners, per_package, unowned)
                duplicates.extend(dup)
                hardlinks.extend(links)
                read_rootfs = True
            except _RootfsLimitError as exc:
                aborted = f"{path.name}: {exc}"
                logger.warning("Yocto evidence: %s — nothing read from the rootfs", aborted)
                per_package.clear()
                unowned.clear()
                break
            except (tarfile.TarError, OSError, EOFError) as exc:
                logger.warning("Yocto evidence: %s unreadable: %s", path.name, exc)
        kernel_type = image.data.get("KERNEL_IMAGETYPE")
        provider = image.data.get("PREFERRED_PROVIDER_virtual/kernel")
        if isinstance(kernel_type, str) and isinstance(provider, str) and provider:
            path = _regular(image.folder, kernel_type)
            if path is not None:
                try:
                    facts = file_facts(image.folder, path.name)
                except (ValueError, OSError):
                    continue
                known = kernels.setdefault(provider, [])
                if facts not in known:
                    known.append(facts)
    evidence: dict[str, ComponentEvidence] = {}
    if read_rootfs and not aborted:
        evidence = {pkg: ComponentEvidence(pkg, tuple(files), ORIGIN_YOCTO_ROOTFS)
                    for pkg, files in sorted(per_package.items())}
    return evidence, YoctoImageEvidence(kernels, image_files, unowned,
                                        sorted(set(duplicates)), sorted(set(hardlinks)), aborted)


def _read_rootfs(
    path: Path, mode: str, owners: dict[str, set[str]],
    per_package: dict[str, list[FileFacts]], unowned: list[FileFacts],
) -> tuple[list[str], list[str]]:
    """Read one rootfs tar as extraction delivers it; return (duplicates, hard links).

    A path that occurs more than once (any member type) is left out
    entirely: tar keeps the last occurrence, and a hash of either would be a
    claim about bytes that may not be delivered (review sicherheit-2, YE1).

    Raises:
        _RootfsLimitError: more members or bytes than the reading limits.
    """
    known = {f.path for files in per_package.values() for f in files} | {f.path for f in unowned}
    facts_by_path: dict[str, FileFacts] = {}
    occurrences: dict[str, int] = {}
    hardlinks: list[str] = []
    members = 0
    total = 0
    with tarfile.open(path, mode) as tf:  # type: ignore[call-overload]
        for member in tf:
            members += 1
            if members > MAX_ROOTFS_MEMBERS:
                raise _RootfsLimitError(f"more than {MAX_ROOTFS_MEMBERS} members (limit)")
            rel = _member_path(member.name)
            if rel is None:
                continue
            occurrences[rel] = occurrences.get(rel, 0) + 1
            if member.islnk():
                hardlinks.append(rel)
                continue
            if not member.isreg() or rel in known:
                continue  # directories, symlinks, devices: no file
            total += member.size
            if total > MAX_ROOTFS_BYTES:
                raise _RootfsLimitError(f"more than {MAX_ROOTFS_BYTES} bytes of files (limit)")
            fh = tf.extractfile(member)
            if fh is None:
                continue
            facts_by_path[rel] = file_facts_from_stream(rel, fh, member.mode)
    duplicates = sorted(p for p, n in occurrences.items() if n > 1)
    for rel in duplicates:
        facts_by_path.pop(rel, None)
    for rel, facts in facts_by_path.items():
        names = owners.get(f"/{rel}", set())
        if len(names) == 1:
            per_package.setdefault(next(iter(names)), []).append(facts)
        else:
            unowned.append(facts)  # none, or two packages claim it
    return duplicates, [h for h in hardlinks if h not in duplicates]


def yocto_product(build_dir: Path) -> tuple[str, str]:
    """(name, version) of the product: the image recipe as testdata.json
    states it (``IMAGE_BASENAME``, the image recipe's ``PV``). Only for
    exactly one stated image — of several, none is "the" product."""
    tmp = _tmp_dir(build_dir)
    if tmp is None:
        return "", ""
    stated = {(str(i.data.get("IMAGE_BASENAME") or ""), str(i.data.get("PV") or ""))
              for i in _stated_images(tmp)}
    if len(stated) != 1:
        return "", ""
    name, version = next(iter(stated))
    return (name, version) if name else ("", "")


class ManifestUnreadableError(ValueError):
    """An image manifest exists but cannot be read."""


def yocto_recipe_packages(build_dir: Path) -> dict[str, set[str]]:
    """PN -> output package names (PKG) of that recipe, from pkgdata."""
    tmp = _tmp_dir(build_dir)
    if tmp is None:
        return {}
    stated = {Path(str(i.data["PKGDATA_DIR"])).name for i in _stated_images(tmp)
              if isinstance(i.data.get("PKGDATA_DIR"), str)}
    out: dict[str, set[str]] = {}
    for runtime in _runtime_dirs(tmp, stated):
        for entry in sorted(runtime.iterdir()):
            pkg = entry.name
            if pkg.endswith(".packaged") or entry.is_symlink() or not entry.is_file():
                continue
            try:
                lines = entry.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            fields = dict(line.partition(": ")[::2] for line in lines)
            pn = fields.get("PN", "").strip()
            if pn:
                out.setdefault(pn, set()).add((fields.get(f"PKG:{pkg}") or pkg).strip())
    return out


def _manifest_paths(tmp: Path) -> list[Path]:
    """The image manifests: IMAGE_NAME.manifest of every stated image, else
    every regular ``*.manifest`` in the deploy image folders."""
    paths: list[Path] = []
    for image in _stated_images(tmp):
        path = _regular(image.folder, f"{image.data['IMAGE_NAME']}.manifest")
        if path is not None:
            paths.append(path)
    if not paths:
        folder = tmp / "deploy" / "images"
        paths = sorted(p for p in folder.glob("*/*.manifest")
                       if p.is_file() and not p.is_symlink()) if folder.is_dir() else []
    return [p for p in paths if _within(p, tmp)]


def yocto_manifest_entries(build_dir: Path) -> list[tuple[str, str]]:
    """(name, version) of the image manifest(s), in their order, each name
    once — the components the collector reads with (it has no create-spdx
    reading). Lines are ``name arch version``; a line without version keeps
    the name and an empty version. Raises :class:`ManifestUnreadableError`
    for a manifest that cannot be read."""
    tmp = _tmp_dir(build_dir) or (build_dir if (build_dir / "deploy").is_dir() else None)
    if tmp is None:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for path in _manifest_paths(tmp):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise ManifestUnreadableError(f"{path.name}: {exc}") from exc
        for line in lines:
            parts = line.split()
            if parts and parts[0] not in seen:
                seen.add(parts[0])
                out.append((parts[0], parts[2] if len(parts) >= 3 else ""))
    return out


def yocto_image_packages(build_dir: Path) -> tuple[set[str], list[str]] | None:
    """Package names the delivered images install, and the manifests read.

    The manifest ``IMAGE_NAME.manifest`` of every image a testdata.json
    states (lines ``name arch version``, written by the image recipe of the
    same build). Without a stated image, every ``*.manifest`` in the deploy
    image folders; ``None`` when there is none (nothing proven, nothing
    excluded).
    """
    tmp = _tmp_dir(build_dir) or (build_dir if (build_dir / "deploy").is_dir() else None)
    if tmp is None:
        return None
    paths = _manifest_paths(tmp)
    if not paths:
        return None
    names: set[str] = set()
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            # A manifest we cannot read proves nothing; the caller names it.
            raise ManifestUnreadableError(f"{path.name}: {exc}") from exc
        names.update(line.split()[0] for line in lines if line.strip())
    return names, [p.name for p in paths]


def yocto_evidence(build_dir: Path) -> dict[str, ComponentEvidence]:
    """Regular files of the image's root file system per runtime package.

    Keys are output package names (``PKG``). Packages that are not in the
    image are not listed. Without a readable rootfs tar, the image's
    testdata or pkgdata: an empty result (nothing proven).
    """
    return _scan(build_dir)[0]


def yocto_image_evidence(build_dir: Path) -> YoctoImageEvidence:
    """Image files, the kernel per providing recipe, rootfs files without package."""
    return _scan(build_dir)[1]




# ---------------------------------------------------------------------------
# The creator URL the build states: the recipe's HOMEPAGE (create-spdx)
# ---------------------------------------------------------------------------

ORIGIN_YOCTO_HOMEPAGE = "yocto: recipe HOMEPAGE (create-spdx)"

#: The HOMEPAGE names a package portal or an encyclopedia, not the creator's
#: project page (sicherheit-2: no mirror, no fork, no package portal).
REASON_CREATOR_NOT_A_PROJECT_PAGE = "creator_url_not_a_project_page"
#: The kernel recipe names yoctoproject.org, but its source is not proven to
#: come from there (a BSP layer's vendor git): the HOMEPAGE would name the
#: wrong creator (sicherheit-2, §8.1.8, 13.11.2026).
REASON_CREATOR_KERNEL_SOURCE_NOT_YOCTO = "creator_kernel_source_not_yocto"

#: The host whose kernel tree the Yocto project maintains (linux-yocto).
_YOCTO_GIT_HOST = "git.yoctoproject.org"

#: Curated, documented exclusion list (coordination 13.11.2026) — a decision,
#: not a heuristic: hosts that are package portals or encyclopedias. A host
#: matches itself and its subdomains (en.wikipedia.org).
NOT_A_PROJECT_PAGE_HOSTS: tuple[str, ...] = (
    "packages.debian.org", "tracker.debian.org", "wikipedia.org",
)


@dataclass(frozen=True)
class CreatorStatement:
    """What the build says about a component's creator: a URL or a gap."""

    url: str = ""
    origin: str = ""
    gap: str = ""


def _recipe_homepages(tmp: Path) -> dict[str, tuple[str, list[str]]]:
    """PN -> (HOMEPAGE, download locations) of every create-spdx 2.x recipe
    document; '' = no HOMEPAGE. The locations are what the recipe fetched
    (``SPDXRef-Download-*`` packages: SRC_URI as the build resolved it)."""
    out: dict[str, tuple[str, list[str]]] = {}
    spdx = tmp / "deploy" / "spdx"
    if not spdx.is_dir() or not _within(spdx, tmp):
        return out
    for path in sorted(spdx.rglob("recipe-*.spdx.json")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        packages = doc.get("packages") if isinstance(doc, dict) else None
        recipe, homepage, downloads = "", "", []
        for pkg in packages if isinstance(packages, list) else []:
            if not isinstance(pkg, dict):
                continue
            spdx_id = str(pkg.get("SPDXID", ""))
            if spdx_id.startswith("SPDXRef-Recipe"):
                recipe = str(pkg.get("name") or "")
                value = pkg.get("homepage")
                homepage = value if isinstance(value, str) and \
                    value not in ("NOASSERTION", "NONE") else ""
            elif spdx_id.startswith("SPDXRef-Download"):
                location = pkg.get("downloadLocation")
                if isinstance(location, str) and location not in ("NOASSERTION", "NONE"):
                    downloads.append(location)
        if recipe:
            out[recipe] = (homepage, downloads)
    return out


def _download_host(location: str) -> str:
    """Host of a create-spdx download location ("git+https://host/...@rev")."""
    from urllib.parse import urlsplit

    url = location.split("+", 1)[1] if "+" in location.split("://", 1)[0] else location
    return (urlsplit(url).hostname or "").lower()


def _excluded_host(url: str) -> bool:
    from urllib.parse import urlsplit

    host = (urlsplit(url).hostname or "").lower()
    return any(host == h or host.endswith(f".{h}") for h in NOT_A_PROJECT_PAGE_HOSTS)


def yocto_creators(build_dir: Path) -> dict[str, CreatorStatement]:
    """Creator statement per output package name (PKG) and per recipe (PN).

    Only where the recipe's create-spdx document exists: its HOMEPAGE is the
    URL (marked with recipe and version), unless the host is on the curated
    exclusion list — then a named gap. The kernel recipe naming
    yoctoproject.org (linux-yocto) counts only when every fetched source is
    at git.yoctoproject.org (sicherheit-2, §8.1.8); other kernel recipes
    follow the general rule. No HOMEPAGE is a gap too; that a recipe is OpenEmbedded's
    own is not provable from the tree (supplier "OpenEmbedded" stands on
    every recipe), so no rule gives it yoctoproject.org.
    """
    from urllib.parse import urlsplit

    tmp = _tmp_dir(build_dir)
    if tmp is None:
        return {}
    homepages = _recipe_homepages(tmp)
    if not homepages:
        return {}
    images = _stated_images(tmp)
    kernels = {str(i.data.get("PREFERRED_PROVIDER_virtual/kernel") or "") for i in images}
    stated = {Path(str(i.data["PKGDATA_DIR"])).name for i in images
              if isinstance(i.data.get("PKGDATA_DIR"), str)}
    recipe_of: dict[str, tuple[str, str]] = {}   # PKG -> (PN, PV)
    for runtime in _runtime_dirs(tmp, stated):
        for entry in sorted(runtime.iterdir()):
            pkg = entry.name
            if pkg.endswith(".packaged") or entry.is_symlink() or not entry.is_file():
                continue
            fields: dict[str, str] = {}
            try:
                for line in entry.read_text(encoding="utf-8", errors="replace").splitlines():
                    key, sep, value = line.partition(": ")
                    if sep and key in (f"PKG:{pkg}", "PN", "PV"):
                        fields[key] = value.strip()
            except OSError:
                continue
            if fields.get("PN"):
                recipe_of[fields.get(f"PKG:{pkg}") or pkg] = (fields["PN"], fields.get("PV", ""))

    def decide(pn: str, pv: str) -> CreatorStatement:
        url, downloads = homepages[pn]
        if not url:
            return CreatorStatement(gap=REASON_CREATOR_NO_URL)
        if _excluded_host(url):
            return CreatorStatement(gap=REASON_CREATOR_NOT_A_PROJECT_PAGE)
        version = f" {pv}" if pv else ""
        origin = f"{ORIGIN_YOCTO_HOMEPAGE}, {pn}{version}"
        host = (urlsplit(url).hostname or "").lower()
        if pn in kernels and (host == "yoctoproject.org" or host.endswith(".yoctoproject.org")):
            # linux-yocto: the Yocto project maintains the tree (§8.1.8) —
            # only if every fetched source is proven to be its tree.
            hosts = {_download_host(d) for d in downloads}
            if not downloads or hosts != {_YOCTO_GIT_HOST}:
                return CreatorStatement(gap=REASON_CREATOR_KERNEL_SOURCE_NOT_YOCTO)
            origin = f"{origin}; kernel source at {_YOCTO_GIT_HOST} (create-spdx download)"
        return CreatorStatement(url=url, origin=origin)

    out: dict[str, CreatorStatement] = {}
    for name, (pn, pv) in recipe_of.items():
        if pn in homepages:
            out[name] = decide(pn, pv)
    versions = {pn: pv for pn, pv in recipe_of.values()}
    for pn in homepages:
        out.setdefault(pn, decide(pn, versions.get(pn, "")))
    return out


# ---------------------------------------------------------------------------
# The composition for suite and collector (form of build_files.BuildEvidence)
# ---------------------------------------------------------------------------


@dataclass
class YoctoBuildEvidence:
    """A Yocto build as suite and collector describe it, for given names.

    ``entries`` follow the given names in order; ``excluded`` is the scope of
    delivery from the image manifest (TR §8.1.11), ``scope_reason`` its
    sentence. ``images`` are delivered without a package (image files, the
    kernel when its recipe is not among the delivered names).
    ``product_names`` are the delivered entry names; None without a
    manifest (then no product row is claimed).
    """

    entries: list[EntryEvidence]
    scope_reason: str
    images: list[FileRecord]
    warnings: list[str]
    sources: list[str]
    product_name: str
    product_version: str
    product_evidence: str
    product_names: list[str] | None


def yocto_build(build_dir: Path, names: list[str]) -> YoctoBuildEvidence:
    """Scope, delivered files, images and creator for the components *names*.

    The suite passes the names its create-spdx reading found, the collector
    the image manifest's. Nothing is invented: without a manifest nothing is
    excluded, without a readable rootfs no file is proven (``not_evidenced``
    stays ""), without a recipe document no creator is said.
    """
    warnings: list[str] = outside_roots(build_dir)
    sources: list[str] = []
    try:
        shipped = yocto_image_packages(build_dir)
    except ManifestUnreadableError as exc:
        shipped = None
        warnings.append(f"image manifest not read, scope of delivery unknown: {exc}")
    scope_reason, product_evidence = "", ""
    # A recipe that stands for a shipped runtime package (review suite-b):
    # the manifest names packages (libc6), a bill may carry only the recipe
    # (glibc). Delivered when one of its packages (pkgdata PN) is in the image
    # and no entry of that package is given; its evidence is its packages'.
    stands_for: dict[str, set[str]] = {}
    excluded: dict[str, bool] = {name: False for name in names}
    if shipped is not None:
        manifest_names, manifests = shipped
        listed = ", ".join(manifests)
        product_evidence = f"yocto: image manifest ({listed})"
        scope_reason = f"Yocto: not in the image manifest ({listed}), built but not shipped"
        given = set(names)
        for pn, pkgs in yocto_recipe_packages(build_dir).items():
            shipped_pkgs = pkgs & manifest_names
            if pn not in manifest_names and shipped_pkgs and not shipped_pkgs & given:
                stands_for[pn] = shipped_pkgs
        excluded = {name: name not in manifest_names and name not in stands_for
                    for name in names}

    evidence, images = _scan(build_dir)
    for pn, pkgs in stands_for.items():
        union = tuple(f for pkg in sorted(pkgs) if pkg in evidence for f in evidence[pkg].files)
        if union and pn not in evidence:
            evidence[pn] = ComponentEvidence(pn, union, ORIGIN_YOCTO_ROOTFS)
    if evidence:
        sources.append(ORIGIN_YOCTO_ROOTFS)
        executable = sum(1 for f in images.unowned if f.executable is True)
        warnings.append(
            "rootfs files without a package (inside the image archive): "
            f"{len(images.unowned)}, executable among them: {executable}")
    if images.duplicates:
        warnings.append(
            "rootfs paths that appear more than once in the image tar (no hash "
            "claimed, extraction keeps the last): " + ", ".join(images.duplicates))
    if images.hardlinks:
        warnings.append("rootfs hard links (no file of their own, not listed): "
                        + ", ".join(images.hardlinks))
    if images.aborted:
        warnings.append(f"rootfs not read: {images.aborted}")

    creators = yocto_creators(build_dir)
    entries: list[EntryEvidence] = []
    by_name: dict[str, EntryEvidence] = {}
    for name in names:
        out = excluded[name]
        files: list[FileRecord] = []
        unclassified, reason = 0, ""
        if evidence:
            if out:
                reason = REASON_NOT_DELIVERED
            else:
                ev = evidence.get(name) or ComponentEvidence(name, (), ORIGIN_YOCTO_ROOTFS)
                files, unclassified = component_files(ev)
                reason = (REASON_NO_DELIVERED_FILE if not ev.files
                          else "" if files else REASON_NO_EXECUTABLE_FILE)
        said = creators.get(name)
        entry = EntryEvidence(
            name, out, files, unclassified, reason,
            Creator(said.url, said.origin) if said is not None and said.url else None,
            said.gap if said is not None else "")
        entries.append(entry)
        by_name.setdefault(name, entry)

    image_records: list[FileRecord] = []
    for provider, kernel in sorted(images.per_package.items()):
        records = component_files(
            ComponentEvidence(provider, tuple(kernel), ORIGIN_YOCTO_KERNEL), every_file=True)[0]
        owner = by_name.get(provider)
        if owner is not None and not owner.excluded:
            known = {f.path for f in owner.files}
            owner.files += [r for r in records if r.path not in known]
            if owner.files and owner.not_evidenced in (REASON_NO_DELIVERED_FILE,
                                                       REASON_NO_EXECUTABLE_FILE, ""):
                owner.not_evidenced = ""
        else:
            image_records += records
    image_records += component_files(
        ComponentEvidence("images", tuple(images.images), ORIGIN_YOCTO_IMAGES),
        every_file=True)[0]

    product_name, product_version = yocto_product(build_dir)
    return YoctoBuildEvidence(
        entries=entries, scope_reason=scope_reason, images=image_records,
        warnings=warnings, sources=sources, product_name=product_name,
        product_version=product_version, product_evidence=product_evidence,
        product_names=([n for n in names if not excluded[n]]
                       if shipped is not None else None))
