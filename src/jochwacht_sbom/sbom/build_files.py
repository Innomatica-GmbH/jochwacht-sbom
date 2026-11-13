"""What a build directory proves about the delivered files (pure core).

Shared file: the open collector carries a generated copy (ci/sync-twin.py),
so suite and collector read a build with the same code. Standard library
only; no model of either half. The suite maps it onto its Dependency (its
build_evidence module); the collector onto its own records.

Order suite-c (coordination 13.11.2026). What the build actually delivered
(Buildroot ``target/`` and ``images/``, the Buildroot source for the creator
URL) becomes facts with SHA-512, filename and the executable/archive/
structured properties.

Rules (sicherheit-2): only proven values. A property comes from magic bytes
or mode bits, never from a file-name ending; ``structured``: a known
container format is structured, ELF and scripts are unstructured (§8.1.6,
table 7), a compressed stream or a file-system image stays open. What is not
proven stays ``None``. Nothing leaves the named root: no ``..``, no absolute
path, no symlink is followed; the Buildroot source is read only inside the
build folder or when the caller names it (BE1).
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

#: Gap reasons (``jochwacht:not-evidenced``) on the logical component.
REASON_NOT_DELIVERED = "not_delivered"            # scope excluded (Buildroot host package)
REASON_NO_DELIVERED_FILE = "no_delivered_file"    # the build lists no file for it
REASON_NO_EXECUTABLE_FILE = "no_executable_file"  # only configuration/data files
#: Gap reason on a file component: the package license names parts
#: ("(programs)", "(libraries)"); which part this file is, is not proven.
REASON_LICENSE_BY_PART = "license_by_part"

#: Bytes read for the magic checks (tar's ``ustar`` sits at offset 257, the
#: x86 boot header at 0x202).
_HEAD = 4096

#: Linux kernel images are no ELF; their boot header proves they are code:
#: (offset, magic) per the kernel's boot protocols.
_KERNEL_BOOT_MAGIC: tuple[tuple[int, bytes], ...] = (
    (0x202, b"HdrS"),              # x86 bzImage (Documentation/arch/x86/boot.rst)
    (0x38, b"ARM\x64"),            # arm64 Image (Documentation/arch/arm64/booting.rst)
    (0x24, b"\x18\x28\x6f\x01"),   # ARM zImage, 0x016f2818 little endian
)

#: Container formats: archive and structured (metadata of the content kept).
_CONTAINER_MAGIC: tuple[bytes, ...] = (
    b"PK\x03\x04",                # zip
    b"7z\xbc\xaf\x27\x1c",        # 7z
    b"!<arch>\n",                 # ar (deb, ipk)
    b"\xed\xab\xee\xdb",          # rpm
    b"070701", b"070702", b"070707",  # cpio (newc, crc, odc)
)
#: Archives whose structure is not proven by the first bytes: a compressed
#: stream (a .tar.gz or a raw kernel?) or a file-system image.
_ARCHIVE_OPEN_MAGIC: tuple[bytes, ...] = (
    b"\x1f\x8b",                  # gzip
    b"\xfd7zXZ\x00",              # xz
    b"BZh",                       # bzip2
    b"\x28\xb5\x2f\xfd",          # zstd
    b"\x04\x22\x4d\x18",          # lz4 frame
    b"hsqs", b"sqsh",             # squashfs
)


#: U-Boot legacy image (uImage, u-boot.img): magic, and ih_type at offset 30
#: (U-Boot include/image.h): 1 standalone, 2 kernel, 5 firmware are code.
_UIMAGE_MAGIC = b"\x27\x05\x19\x56"
_UIMAGE_TYPE_OFFSET = 30
_UIMAGE_EXECUTABLE_TYPES = frozenset({1, 2, 5})
#: Flattened device tree (.dtb).
_FDT_MAGIC = b"\xd0\x0d\xfe\xed"
#: A FIT image is an FDT whose root holds an "images" node (FDT_BEGIN_NODE
#: token 0x00000001 followed by the node name).
_FIT_IMAGES_NODE = b"\x00\x00\x00\x01images\x00"
#: ext2/3/4: superblock at 1024, s_magic 0xEF53 at offset 56 within it.
_EXT_MAGIC_OFFSET = 0x438


@dataclass(frozen=True)
class FileFacts:
    """What one delivered file proves about itself."""

    path: str                 # relative to the root of the evidence
    sha512: str               # hex digest of the bytes read
    executable: bool | None   # None = not proven
    archive: bool | None
    structured: bool | None


@dataclass(frozen=True)
class ComponentEvidence:
    """The delivered files of one component and where the assignment came from."""

    name: str                       # component name as the import names it
    files: tuple[FileFacts, ...]
    origin: str                     # e.g. "buildroot:packages-file-list.txt"


def _inside(root: Path, rel: str) -> Path:
    """*rel* under *root*, refusing anything that leaves it or passes a symlink."""
    if not rel or os.path.isabs(rel):
        raise ValueError(f"{rel!r} is outside the root {root}")
    parts = Path(rel).parts
    if ".." in parts:
        raise ValueError(f"{rel!r} is outside the root {root}")
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{rel!r} passes a symlink ({current}); "
                             "a symlink is not a delivered file")
    return current


def _flags(head: bytes, mode: int | None) -> tuple[bool | None, bool | None, bool | None]:
    """(executable, archive, structured) from magic bytes and mode bits only.

    *mode* None: the delivery's mode bits say nothing (images/ holds firmware
    without x-bit); then only the bytes count.
    """
    any_x = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)) if mode is not None \
        else None
    if head.startswith(b"\x7fELF"):
        return True, False, False  # machine code: executable, unstructured
    if head.startswith(b"#!"):
        return (True if any_x else None), False, (False if any_x else None)
    if head.startswith(_UIMAGE_MAGIC) and len(head) > _UIMAGE_TYPE_OFFSET:
        # U-Boot legacy image: the header names the payload type.
        if head[_UIMAGE_TYPE_OFFSET] in _UIMAGE_EXECUTABLE_TYPES:
            return True, False, None
        return None, None, None
    if head.startswith(_FDT_MAGIC):
        if _FIT_IMAGES_NODE in head:
            return None, True, True  # FIT image: a container (/images) of payloads
        return False, False, None  # device tree: data, not code, no archive
    if head.startswith(_CONTAINER_MAGIC) or head[257:262] == b"ustar":
        return False, True, True
    if head.startswith(_ARCHIVE_OPEN_MAGIC):
        return False, True, None
    # Marks at an offset, only after every mark at the start: a container
    # whose payload happens to carry such bytes stays a container.
    if any(head[o:o + len(m)] == m for o, m in _KERNEL_BOOT_MAGIC):
        return True, False, None
    if head[_EXT_MAGIC_OFFSET:_EXT_MAGIC_OFFSET + 2] == b"\x53\xef":
        return False, True, None  # ext2/3/4 file system image
    if head[510:512] == b"\x55\xaa":
        if head[0x36:0x39] == b"FAT" or head[0x52:0x55] == b"FAT":
            return False, True, None  # FAT file system image
        if any(head[e + 4] != 0 for e in range(0x1BE, 0x1FE, 16)):
            return False, True, None  # partitioned disk image (MBR with an entry)
    # Unknown format: without a mode bit it is not executable (where mode bits
    # mean something); whether it is an archive of a format we do not know is
    # not proven either way.
    return (False if any_x is False else None), None, None


def file_facts_from_stream(rel: str, fh: BinaryIO, mode: int | None) -> FileFacts:
    """Hash and classify the bytes of *fh* (a delivered file at *rel*).

    The one rule for files on disk and members of an archive (suite-d reads
    the Yocto rootfs tar): *mode* are the permission bits the delivery gives
    the file, None where they say nothing (images). The caller filters
    symlinks and non-regular members.
    """
    digest = hashlib.sha512()
    head = fh.read(_HEAD)
    digest.update(head)
    for chunk in iter(lambda: fh.read(1 << 20), b""):
        digest.update(chunk)
    executable, archive, structured = _flags(head, mode)
    return FileFacts(path=rel, sha512=digest.hexdigest(), executable=executable,
                     archive=archive, structured=structured)


def file_facts(root: Path, rel: str, *, mode_bits: bool = True) -> FileFacts:
    """Hash and classify the delivered file *rel* under *root*.

    ``mode_bits=False`` where the file's mode says nothing (images/).

    Raises:
        ValueError: *rel* leaves *root*, passes a symlink or is no regular file.
    """
    path = _inside(root, rel)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"{rel!r} is not a regular file")
    with path.open("rb") as fh:
        return file_facts_from_stream(rel, fh, st.st_mode if mode_bits else None)


def is_component_file(facts: FileFacts) -> bool:
    """§3.2.1: an executable file or an archive MUST be a component."""
    return facts.executable is True or facts.archive is True


def _unclassified(facts: FileFacts) -> bool:
    """Maybe executable, not proven (mode bit, unknown format)."""
    return facts.executable is None and facts.archive is not True


#: Origin of a Buildroot target assignment.
ORIGIN_BUILDROOT_TARGET = "buildroot:packages-file-list.txt"


def _buildroot_output(build_dir: Path) -> Path:
    """The Buildroot output folder: *build_dir*/output, or *build_dir* itself."""
    nested = build_dir / "output"
    return nested if (nested / "build").is_dir() else build_dir


def _outside(path: Path, build_dir: Path) -> bool:
    """*path* exists but lies, links resolved, outside *build_dir* (Y1)."""
    return (path.exists() or path.is_symlink()) and not _within(path, build_dir)


def buildroot_roots_outside(build_dir: Path) -> list[str]:
    """The roots of a Buildroot build that point outside the build folder,
    as written (relative to *build_dir*); none of them is read (Y1, found by
    suite-c in suite-d's Yocto reader and then here, 13.11.2026)."""
    out = _buildroot_output(build_dir)
    candidates = [out, out / "build" / "packages-file-list.txt", out / "target",
                  out / "images", out / ".config", build_dir / ".config"]
    found: list[str] = []
    for path in candidates:
        if path != build_dir and _outside(path, build_dir):
            rel = _rel(path, build_dir)
            if rel not in found:
                found.append(rel)
    return found


def outside_warning(rel: str) -> str:
    """The warning for a root that is not read because it points outside."""
    return f"{rel} points outside the build directory; not read"


def buildroot_evidence(
    build_dir: Path, *, counts: dict[str, int] | None = None,
) -> dict[str, ComponentEvidence]:
    """Delivered files per target package from ``build/packages-file-list.txt``.

    Only regular files under ``target/`` count; a symlink is no delivered
    file, a listed file the target no longer has (removed at target-finalize)
    is not delivered, and a path two packages claim belongs to neither. A
    package whose files are all gone is listed with no file. Without the
    list: an empty result (nothing proven). *counts* gets what was left out
    (``shared_paths``, ``not_regular_or_gone``): nothing drops silently.
    """
    out = _buildroot_output(build_dir)
    listing = out / "build" / "packages-file-list.txt"
    target = out / "target"
    if not listing.is_file() or not target.is_dir():
        return {}
    if not (_within(out, build_dir) and _within(listing, build_dir)
            and _within(target, build_dir)):
        return {}  # named by buildroot_roots_outside (Y1)
    claims: dict[str, set[str]] = {}
    packages: dict[str, list[str]] = {}
    for line in listing.read_text(encoding="utf-8", errors="replace").splitlines():
        package, sep, raw = line.partition(",")
        package = package.strip()
        if not sep or not package or not raw:
            continue
        rel = raw.strip()
        rel = rel[2:] if rel.startswith("./") else rel
        packages.setdefault(package, [])
        if rel not in packages[package]:
            packages[package].append(rel)
        claims.setdefault(rel, set()).add(package)

    result: dict[str, ComponentEvidence] = {}
    shared = {rel for rel, owners in claims.items() if len(owners) > 1}
    left_out = 0
    for package, paths in packages.items():
        files: list[FileFacts] = []
        for rel in paths:
            if rel in shared:
                continue
            try:
                files.append(file_facts(target, rel))
            except (ValueError, OSError):
                left_out += 1  # outside, a symlink, not a regular file, or gone
        result[package] = ComponentEvidence(package, tuple(files), ORIGIN_BUILDROOT_TARGET)
    if counts is not None:
        counts["shared_paths"] = len(shared)
        counts["not_regular_or_gone"] = left_out
    return result


#: Origins of an images/ assignment: Buildroot does not record images/ per
#: package; the name follows Buildroot's own rule from the .config.
ORIGIN_BUILDROOT_IMAGES_LINUX = "buildroot:images/ (linux.mk name rule, .config)"
ORIGIN_BUILDROOT_IMAGES_UBOOT = "buildroot:images/ (uboot.mk name rule, .config)"
ORIGIN_BUILDROOT_IMAGES = "buildroot:images/"

#: linux/linux.mk (Buildroot 2025.08.2): kernel image format -> file name.
#: Formats whose name depends on more than one option (cuImage, simpleImage,
#: custom targets) are not carried: such a file stays unassigned.
_LINUX_IMAGE_NAMES = {
    "BR2_LINUX_KERNEL_UIMAGE": "uImage",
    "BR2_LINUX_KERNEL_APPENDED_UIMAGE": "uImage",
    "BR2_LINUX_KERNEL_BZIMAGE": "bzImage",
    "BR2_LINUX_KERNEL_ZIMAGE": "zImage",
    "BR2_LINUX_KERNEL_ZIMAGE_EPAPR": "zImage.epapr",
    "BR2_LINUX_KERNEL_APPENDED_ZIMAGE": "zImage",
    "BR2_LINUX_KERNEL_IMAGE": "Image",
    "BR2_LINUX_KERNEL_IMAGEGZ": "Image.gz",
    "BR2_LINUX_KERNEL_LINUX_BIN": "linux.bin",
    "BR2_LINUX_KERNEL_VMLINUX_BIN": "vmlinux.bin",
    "BR2_LINUX_KERNEL_VMLINUX_EFI": "vmlinux.efi",
    "BR2_LINUX_KERNEL_VMLINUX": "vmlinux",
    "BR2_LINUX_KERNEL_VMLINUZ": "vmlinuz",
    "BR2_LINUX_KERNEL_VMLINUZ_BIN": "vmlinuz.bin",
    "BR2_LINUX_KERNEL_VMLINUZ_EFI": "vmlinuz.efi",
}

#: boot/uboot/uboot.mk (Buildroot 2025.08.2): UBOOT_BINS by format option.
_UBOOT_BIN_NAMES = {
    "BR2_TARGET_UBOOT_FORMAT_BIN": "u-boot.bin",
    "BR2_TARGET_UBOOT_FORMAT_DTB": "u-boot.dtb",
    "BR2_TARGET_UBOOT_FORMAT_ELF": "u-boot",
    "BR2_TARGET_UBOOT_FORMAT_REMAKE_ELF": "u-boot.elf",
    "BR2_TARGET_UBOOT_FORMAT_KWB": "u-boot.kwb",
    "BR2_TARGET_UBOOT_FORMAT_AIS": "u-boot.ais",
    "BR2_TARGET_UBOOT_FORMAT_NAND_BIN": "u-boot-nand.bin",
    "BR2_TARGET_UBOOT_FORMAT_DTB_IMG": "u-boot-dtb.img",
    "BR2_TARGET_UBOOT_FORMAT_DTB_IMX": "u-boot-dtb.imx",
    "BR2_TARGET_UBOOT_FORMAT_DTB_BIN": "u-boot-dtb.bin",
    "BR2_TARGET_UBOOT_FORMAT_IMG": "u-boot.img",
    "BR2_TARGET_UBOOT_FORMAT_ITB": "u-boot.itb",
    "BR2_TARGET_UBOOT_FORMAT_QSPI_BIN": "qspi.bin",
    "BR2_TARGET_UBOOT_FORMAT_IMX": "u-boot.imx",
    "BR2_TARGET_UBOOT_FORMAT_SB": "u-boot.sb",
    "BR2_TARGET_UBOOT_FORMAT_SD": "u-boot.sd",
    "BR2_TARGET_UBOOT_FORMAT_NAND": "u-boot.nand",
    "BR2_TARGET_UBOOT_FORMAT_STM32": "u-boot.stm32",
}


def _read_config(path: Path) -> dict[str, str]:
    """``KEY=value`` lines of a Buildroot .config, quotes stripped."""
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.startswith("BR2_"):
            out[key.strip()] = value.strip().strip('"')
    return out


def _image_names(config: dict[str, str]) -> dict[str, str]:
    """images/ file name -> package, by Buildroot's name rules."""
    names: dict[str, str] = {}
    if config.get("BR2_LINUX_KERNEL") == "y":
        for option, name in _LINUX_IMAGE_NAMES.items():
            if config.get(option) == "y":
                names[name] = "linux"
        if config.get("BR2_LINUX_KERNEL_DTS_SUPPORT") == "y":
            keep = config.get("BR2_LINUX_KERNEL_DTB_KEEP_DIRNAME") == "y"
            for dts in config.get("BR2_LINUX_KERNEL_INTREE_DTS_NAME", "").split():
                names[(dts if keep else Path(dts).name) + ".dtb"] = "linux"
    if config.get("BR2_TARGET_UBOOT") == "y":
        for option, name in _UBOOT_BIN_NAMES.items():
            if config.get(option) == "y":
                names[name] = "uboot"
        if config.get("BR2_TARGET_UBOOT_FORMAT_CUSTOM") == "y":
            for name in config.get("BR2_TARGET_UBOOT_FORMAT_CUSTOM_NAME", "").split():
                names[name] = "uboot"
        if config.get("BR2_TARGET_UBOOT_SPL") == "y":
            for spl in config.get("BR2_TARGET_UBOOT_SPL_NAME", "").split():
                names[Path(spl).name] = "uboot"  # cp to images/ keeps the base name
    return names


def buildroot_image_evidence(
    build_dir: Path, *, counts: dict[str, int] | None = None,
) -> tuple[dict[str, list[FileFacts]], list[FileFacts]]:
    """images/ files assigned to linux and uboot by name rule; the rest apart.

    Only regular files directly in ``images/`` (or under a kept DTB dirname)
    are read; a configured name that is missing is not invented.
    """
    out = _buildroot_output(build_dir)
    images = out / "images"
    if not images.is_dir():
        return {}, []
    if not (_within(out, build_dir) and _within(images, build_dir)):
        return {}, []  # named by buildroot_roots_outside (Y1)
    # O= build: output/.config; in-tree build: .config beside output/
    config_path = out / ".config"
    if not config_path.is_file() and out != build_dir:
        config_path = build_dir / ".config"
    # A .config from outside assigns nothing (Y1): the images stay unassigned.
    names = (_image_names(_read_config(config_path))
             if not _outside(config_path, build_dir) else {})
    per_package: dict[str, list[FileFacts]] = {}
    rest: list[FileFacts] = []
    links_outside = 0
    for path in sorted(images.rglob("*")):
        rel = path.relative_to(images).as_posix()
        try:
            facts = file_facts(images, rel, mode_bits=False)
        except (ValueError, OSError):
            # A symlink, a directory or gone. A link that leads out of
            # images/ is counted, not dropped silently (sicherheit-2).
            if path.is_symlink() and not within(path, images):
                links_outside += 1
            continue
        package = names.get(rel)
        if package:
            per_package.setdefault(package, []).append(facts)
        else:
            rest.append(facts)
    if counts is not None and links_outside:
        counts["links_outside"] = links_outside
    return per_package, rest


# --- The creator URL a Buildroot build proves --------------------------------
#
# Buildroot's maintainers keep the project's web page in the help text of each
# package symbol, a line holding only the URL. TR-03183-2 §5.2.2 accepts "the
# project's web page" as creator URL (sicherheit-2, 13.11.2026). Order suite-c.

#: Creator of the packages Buildroot keeps in its own tree (no <PKG>_SITE).
BUILDROOT_PROJECT_URL = "https://buildroot.org"

REASON_CREATOR_NO_SOURCE = "creator_no_buildroot_source"
REASON_CREATOR_SOURCE_VERSION = "creator_buildroot_source_other_version"
REASON_CREATOR_NO_URL = "creator_no_project_url"
REASON_CREATOR_FILE_LINK = "creator_url_is_a_file_link"
REASON_CREATOR_TOOLCHAIN = "creator_toolchain_is_no_creator"
REASON_CREATOR_OVERWRITTEN = "creator_file_differs_from_buildroot_tree"
#: The source tree lies outside the build folder and was not named by the
#: caller (sicherheit-2, BE1: output/Makefile is a file of the upload).
REASON_CREATOR_SOURCE_OUTSIDE = "creator_buildroot_source_outside_build_dir"

#: A bound below was hit; nothing was compared (sicherheit-2).
REASON_CREATOR_TREE_TOO_LARGE = "creator_buildroot_tree_too_large"

#: Bounds for hashing files of the Buildroot tree (sicherheit-2, BE1).
_TREE_FILE_LIMIT = 64 * 1024 * 1024
_TREE_FILE_COUNT = 20000
#: A Kconfig file larger than this is not read (Buildroot's are a few kB).
_CONFIG_IN_LIMIT = 1024 * 1024

#: Buildroot folders that hold package symbols; output/ of an in-tree build
#: (extracted package sources with their own Config.in) is never read.
_BUILDROOT_SYMBOL_DIRS = ("package", "boot", "linux", "toolchain", "fs", "system")
#: Package -> symbol where it is not BR2_PACKAGE_<NAME>.
_BUILDROOT_SYMBOLS = {"linux": "BR2_LINUX_KERNEL", "uboot": "BR2_TARGET_UBOOT"}
#: A URL into a repository's file view is a link to one file, no project page.
_FILE_LINK = re.compile(r"/(?:-/)?(?:blob|raw|tree)/")


@dataclass(frozen=True)
class Creator:
    """A creator URL and where the build proves it."""

    url: str
    origin: str


def _config_version(path: Path) -> str:
    """The Buildroot version a .config was written by ("# Buildroot X Configuration")."""
    if not path.is_file():
        return ""
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:6]:
        m = re.match(r"#\s*Buildroot\s+(\S+)\s+Configuration", line)
        if m:
            return m.group(1)
    return ""


def _source_version(src: Path) -> str:
    """BR2_VERSION of a Buildroot source tree (top-level Makefile)."""
    mk = src / "Makefile"
    if not mk.is_file():
        return ""
    m = re.search(r"^export BR2_VERSION\s*:=\s*(\S+)", mk.read_text(errors="replace"), re.M)
    return m.group(1) if m else ""


def within(path: Path, root: Path) -> bool:
    """Whether *path*, all symlinks resolved, lies inside *root* (resolved).

    The one check for every root a build reader takes (BE1, Y1); public so
    the Yocto reader (build_files_yocto) uses the same function.
    """
    return _within(path, root)


def _within(path: Path, root: Path) -> bool:
    """Whether *path*, all symlinks resolved, lies inside *root* (resolved)."""
    try:
        return path.resolve(strict=True).is_relative_to(root.resolve(strict=True))
    except OSError:
        return False


def buildroot_source(
    build_dir: Path, *, source: Path | None = None,
) -> tuple[Path | None, Path | None, str]:
    """(source tree, .config, gap) of the build.

    In-tree: the build folder (or output/'s parent inside it) holds .config and
    package/. O=: output/Makefile, generated by mkmakefile ("Automatically
    generated"), names the source in "MAKEARGS := -C <source>". That file is
    part of the upload (sicherheit-2, BE1): a path it names is read only when
    it lies inside the build folder, or when the caller names exactly that
    source (*source*, the CLI's --buildroot-source). Whoever imports foreign
    build folders (a service provider, CI with customer artefacts, a future
    portal import) does not pass it.
    """
    out = _buildroot_output(build_dir)
    for root in dict.fromkeys((build_dir, out.parent)):
        if (_within(root, build_dir) and (root / ".config").is_file()
                and (root / "package").is_dir()):
            return root.resolve(), root.resolve() / ".config", ""
    makefile = out / "Makefile"
    if not (makefile.is_file() and _within(makefile, build_dir)):
        return None, None, REASON_CREATOR_NO_SOURCE
    text = makefile.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"^MAKEARGS\s*:=\s*-C\s+(\S+)\s*$", text, re.M)
    if "Automatically generated" not in text or not m:
        return None, None, REASON_CREATOR_NO_SOURCE
    named = Path(m.group(1))
    config = out / ".config"
    if not _within(config, build_dir):
        return None, None, REASON_CREATOR_NO_SOURCE
    if _within(named, build_dir):
        src = named.resolve()
    elif source is not None and named.exists() and source.exists() \
            and named.resolve() == source.resolve():
        src = source.resolve()
    else:
        return None, None, REASON_CREATOR_SOURCE_OUTSIDE
    if not (src / "package").is_dir():
        return None, None, REASON_CREATOR_NO_SOURCE
    return src, config, ""


def _symbol_index(src: Path) -> dict[str, tuple[str, Path]]:
    """symbol -> (first URL line of its help, Config.in), Kconfig semantics:
    a help block ends at the first non-empty line without indentation."""
    index: dict[str, tuple[str, Path]] = {}
    for cfg in _walk_files(src, _BUILDROOT_SYMBOL_DIRS):
        if cfg.name.startswith("Config.in") and cfg.stat().st_size <= _CONFIG_IN_LIMIT:
            symbol, in_help, url = "", False, ""
            for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.match(r"^(?:menu)?config\s+(\S+)\s*$", line)
                if m or (line and not line[0].isspace()):
                    if symbol and symbol not in index:
                        index[symbol] = (url, cfg)
                    symbol, in_help, url = (m.group(1) if m else ""), False, ""
                    continue
                if line.strip() in ("help", "---help---"):
                    in_help = True
                    continue
                if in_help and not url and re.fullmatch(r"https?://\S+", line.strip()):
                    url = line.strip()
            if symbol and symbol not in index:
                index[symbol] = (url, cfg)
    return index


def _walk_files(root: Path, folders: tuple[str, ...]) -> list[Path]:
    """Regular files under root/<folder>, sorted; no symlink is followed, no
    file is taken that lies outside *root*."""
    found: list[Path] = []
    for folder in folders:
        base = root / folder
        if not base.is_dir() or base.is_symlink():
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames.sort()
            for name in sorted(filenames):
                p = Path(dirpath) / name
                if not p.is_symlink() and p.is_file():
                    found.append(p)
    return found


def _tree_hashes(src: Path, folders: tuple[str, ...]) -> set[str] | None:
    """SHA-512 of the regular files in src/<folders>, streamed and bounded.

    None when a bound is hit (too many files, a file too large): then nothing
    is proven (sicherheit-2, BE1).
    """
    files = _walk_files(src, folders)
    if len(files) > _TREE_FILE_COUNT:
        return None
    out: set[str] = set()
    for p in files:
        if p.stat().st_size > _TREE_FILE_LIMIT:
            return None
        digest = hashlib.sha512()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        out.add(digest.hexdigest())
    return out


def buildroot_creators(
    build_dir: Path,
    packages: list[str],
    *,
    delivered: dict[str, list[FileFacts]] | None = None,
    source: Path | None = None,
) -> tuple[dict[str, Creator], dict[str, str]]:
    """Creator URL per package, from the Buildroot source the build used.

    Returns (creators, gaps): every package in *packages* is in exactly one.
    *delivered* are the files the package delivered (all regular files, also
    configuration); a package kept in the Buildroot tree gets Buildroot as
    creator only when each of them equals a file of the tree.
    """
    src, config, why = buildroot_source(build_dir, source=source)
    if src is None or config is None:
        return {}, {p: why or REASON_CREATOR_NO_SOURCE for p in packages}
    built_by = _config_version(config)
    if not built_by or built_by != _source_version(src):
        return {}, {p: REASON_CREATOR_SOURCE_VERSION for p in packages}
    index = _symbol_index(src)
    version = f"Buildroot {built_by}"
    creators: dict[str, Creator] = {}
    gaps: dict[str, str] = {}
    for name in packages:
        if name.startswith("toolchain-external"):
            # The toolchain provider builds glibc/GCC, it creates them not (§3.2.9).
            gaps[name] = REASON_CREATOR_TOOLCHAIN
            continue
        symbol = _BUILDROOT_SYMBOLS.get(name, "BR2_PACKAGE_" + re.sub(r"[^A-Z0-9]", "_",
                                                                       name.upper()))
        url, cfg = index.get(symbol, ("", None))
        rel = cfg.relative_to(src).as_posix() if cfg else ""
        prefix = re.sub(r"[^A-Z0-9]", "_", name.upper())
        mk = cfg.parent / f"{name}.mk" if cfg else None
        in_tree = bool(mk and mk.is_file() and not re.search(
            rf"^{prefix}_SITE\s*[:?+]?=", mk.read_text(errors="replace"), re.M))
        if in_tree and cfg is not None:
            files = (delivered or {}).get(name, [])
            what = f"{version}: {rel} (package in the Buildroot tree, no {prefix}_SITE; "
            if not files:
                # sicherheit-2, BE2: nothing to compare is said as such
                creators[name] = Creator(BUILDROOT_PROJECT_URL,
                                         what + "no delivered file to compare)")
                continue
            pkg_rel = cfg.parent.relative_to(src).as_posix()
            known = _tree_hashes(src, (pkg_rel, "system"))
            if known is None:
                gaps[name] = REASON_CREATOR_TREE_TOO_LARGE
            elif all(f.sha512 in known for f in files):
                creators[name] = Creator(BUILDROOT_PROJECT_URL,
                                         what + "delivered files equal the tree)")
            else:
                gaps[name] = REASON_CREATOR_OVERWRITTEN
            continue
        if not url:
            gaps[name] = REASON_CREATOR_NO_URL
        elif _FILE_LINK.search(url):
            gaps[name] = REASON_CREATOR_FILE_LINK
        else:
            creators[name] = Creator(url, f"{version}: {rel} help of {symbol}")
    return creators, gaps


# --- Buildroot's own SBOM as plain records ----------------------------------
#
# One source of truth for the suite's import and the open collector (suite-b,
# coordination 13.11.2026), with suite-b's lossless rules: host apart with its
# reason, only valid patch types (F2), nameless counted (F4), no version made
# up, the licenses as Buildroot lists them.

#: CycloneDX 1.6 ``pedigree.patches[].type`` values; anything else fails the schema.
PATCH_TYPES = frozenset({"unofficial", "monkey", "backport", "cherry-pick"})


@dataclass(frozen=True)
class BuildrootPackage:
    """One component of Buildroot's own SBOM, without loss."""

    name: str
    version: str                       # "" when Buildroot gives none, never invented
    bom_ref: str
    purl: str                          # Buildroot's, else pkg:buildroot/<package>[@version]
    supplier: str                      # "" when none
    licenses: tuple[str, ...]          # as listed (id, name or expression), joined by the caller
    cpe: str
    patches: tuple[dict[str, object], ...]  # pedigree.patches with a valid type
    host_reason: str                   # "" | "bom-ref host-<name>" | "BR_TYPE=host"


def _sbom_candidates(build_dir: Path) -> tuple[list[Path], list[Path]]:
    """Where Buildroot's CycloneDX SBOM may lie, in order: (inside, refused).

    Only regular files inside *build_dir*, links resolved (no path out of
    what was handed in); a candidate pointing outside is returned apart so
    the caller can name it (nothing dropped silently).
    """
    candidates = [
        build_dir / "output" / "legal-info" / "buildroot.cdx.json",
        build_dir / "legal-info" / "buildroot.cdx.json",
        *sorted(build_dir.glob("output/legal-info/*.cdx.json")),
        *sorted(build_dir.glob("**/*.cdx.json")),
    ]
    found = [p for p in dict.fromkeys(candidates) if p.is_file()]
    return ([p for p in found if _within(p, build_dir)],
            [p for p in found if not _within(p, build_dir)])


def _buildroot_sbom(build_dir: Path) -> tuple[Path | None, dict[str, object] | None, str]:
    """(path, document, warning): the first candidate that is CycloneDX. An
    unreadable candidate ends the search with a warning, as in suite-b's import;
    a candidate refused for pointing outside is named in the warning."""
    import json

    inside, refused = _sbom_candidates(build_dir)
    named = "; ".join(f"{_rel(p, build_dir)} points outside the build directory; not read"
                      for p in refused)
    for path in inside:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError, RecursionError) as exc:
            return None, None, f"Failed to parse {path}: {exc}"
        if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
            return path, data, named
    return None, None, named


def _rel(path: Path, root: Path) -> str:
    """*path* relative to *root* as written, without resolving links."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def buildroot_sbom_file(build_dir: Path) -> Path | None:
    """Buildroot's CycloneDX SBOM in the build folder (legal-info), or None."""
    return _buildroot_sbom(build_dir)[0]


def _host_reason(comp: dict[str, object]) -> str:
    bom_ref = str(comp.get("bom-ref", "") or "").strip()
    if bom_ref.startswith("host-"):
        return f"bom-ref {bom_ref}"
    props = comp.get("properties")
    if isinstance(props, list) and any(
            isinstance(p, dict) and p.get("name") == "BR_TYPE" and p.get("value") == "host"
            for p in props):
        return "BR_TYPE=host"
    return ""


def _license_parts(licenses: object) -> tuple[str, ...]:
    """Every license text Buildroot lists, stripped, empty and repeats left out."""
    parts: list[str] = []
    for entry in licenses if isinstance(licenses, list) else []:
        if not isinstance(entry, dict):
            continue
        lic = entry.get("license")
        if isinstance(entry.get("expression"), str):
            text = str(entry["expression"]).strip()
        elif isinstance(lic, dict):
            text = str(lic.get("id") or lic.get("name") or "").strip()
        else:
            continue
        if text and text not in parts:
            parts.append(text)
    return tuple(parts)


def buildroot_package(comp: dict[str, object]) -> tuple[BuildrootPackage | None, int]:
    """One component of Buildroot's SBOM as a record, and the patches left out
    for want of a valid type. None for a component without name."""
    name = str(comp.get("name", "") or "").strip()
    if not name:
        return None, 0
    version = str(comp.get("version", "") or "").strip()
    bom_ref = str(comp.get("bom-ref", "") or "").strip()
    package = bom_ref if bom_ref.startswith("host-") else name
    pedigree = comp.get("pedigree")
    raw = pedigree.get("patches") if isinstance(pedigree, dict) else None
    patches = [p for p in raw if isinstance(p, dict) and p.get("type") in PATCH_TYPES] \
        if isinstance(raw, list) else []
    supplier = comp.get("supplier")
    cpe = comp.get("cpe")
    return BuildrootPackage(
        name=name, version=version, bom_ref=bom_ref,
        purl=str(comp.get("purl", "") or "") or (
            f"pkg:buildroot/{package}@{version}" if version else f"pkg:buildroot/{package}"),
        supplier=str(supplier.get("name", "") or "") if isinstance(supplier, dict) else "",
        licenses=_license_parts(comp.get("licenses")),
        cpe=str(cpe) if isinstance(cpe, str) else "",
        patches=tuple(patches),
        host_reason=_host_reason(comp),
    ), (len(raw) - len(patches)) if isinstance(raw, list) else 0


def buildroot_packages(build_dir: Path) -> tuple[list[BuildrootPackage], list[str]]:
    """The components of Buildroot's own SBOM as records, and the warnings.

    Nothing drops silently: a component without name and a patch without a
    valid CycloneDX type are counted in a warning.
    """
    path, data, note = _buildroot_sbom(build_dir)
    if path is None or data is None:
        return [], [note] if note else []
    packages: list[BuildrootPackage] = []
    nameless = dropped_patches = 0
    components = data.get("components")
    for comp in components if isinstance(components, list) else []:
        if not isinstance(comp, dict):
            continue
        pkg, dropped = buildroot_package(comp)
        if pkg is None:
            nameless += 1
            continue
        dropped_patches += dropped
        packages.append(pkg)
    warnings: list[str] = [note] if note else []
    if nameless:
        warnings.append(f"{nameless} component(s) without name in {path.name} "
                        "were not imported.")
    if dropped_patches:
        warnings.append(f"{dropped_patches} patch(es) without a valid CycloneDX type "
                        f"in {path.name} were left out.")
    return packages, warnings


def buildroot_product(build_dir: Path) -> tuple[str, str]:
    """Name and version of the product from Buildroot's own SBOM
    (``metadata.component``, set by generate-cyclonedx --project-name)."""
    doc = _buildroot_sbom(build_dir)[1]
    meta = doc.get("metadata") if isinstance(doc, dict) else None
    comp = meta.get("component") if isinstance(meta, dict) else None
    if isinstance(comp, dict) and isinstance(comp.get("name"), str):
        return comp["name"], str(comp.get("version", "") or "")
    return "", ""


# --- One composition of a Buildroot build -------------------------------------
#
# What import_buildroot composed in the suite, now once for suite and collector
# (agreed with suite-b, 13.11.2026). The suite maps it onto its Dependency, the
# collector onto its records; parity is built in.

@dataclass(frozen=True)
class FileRecord:
    """A delivered file that is a component, with where its assignment is proven."""

    path: str
    sha512: str
    executable: bool | None
    archive: bool | None
    structured: bool | None
    origin: str


def _record(f: FileFacts, origin: str) -> FileRecord:
    return FileRecord(path=f.path, sha512=f.sha512, executable=f.executable,
                      archive=f.archive, structured=f.structured, origin=origin)


def component_files(ev: ComponentEvidence, *, every_file: bool = False,
                    ) -> tuple[list[FileRecord], int]:
    """The files of *ev* that are components (§3.2.1: code or archive; with
    *every_file* each one, for images), and how many may be code but are not
    proven (counted, not listed)."""
    records = [_record(f, ev.origin) for f in ev.files if every_file or is_component_file(f)]
    unclassified = 0 if every_file else sum(1 for f in ev.files if _unclassified(f))
    return records, unclassified


def join_licenses(parts: tuple[str, ...] | list[str], *,
                  classify: Callable[[str], tuple[str, str] | None]) -> str | None:
    """suite-b's rule for Buildroot's license parts, in one place.

    *classify* is the half's own license library: (kind, value) with kind
    "id", "expression" or anything else for free text; None for no statement
    ("unknown"). Every part an SPDX id or expression: joined with AND (an
    expression in parentheses); free text among them: "; " (an expression
    would be invalid). Nothing dropped but non-statements, nothing made up.
    """
    kept = [(p, k) for p in parts if (k := classify(p)) is not None]
    if not kept:
        return None
    if len(kept) == 1:
        return kept[0][0]
    if all(k[0] in ("id", "expression") for _, k in kept):
        return " AND ".join(f"({k[1]})" if k[0] == "expression" else p for p, k in kept)
    return "; ".join(p for p, _ in kept)


def host_scope_reason(pkg: BuildrootPackage) -> str:
    """The scope reason of a host package, the same sentence in both halves."""
    if not pkg.host_reason:
        return ""
    return (f"Buildroot host package ({pkg.bom_ref}): built for the build machine, "
            "not shipped")


@dataclass
class EntryEvidence:
    """What the build directory proves for one package (by name)."""

    name: str
    excluded: bool
    files: list[FileRecord]
    unclassified: int
    not_evidenced: str
    creator: Creator | None
    creator_gap: str


@dataclass
class BuildEvidence:
    """The build directory's proof for a list of packages, plus what it holds
    without a package."""

    entries: list[EntryEvidence]
    images: list[FileRecord]           # images/ without a package: code or archive
    warnings: list[str]
    sources: list[str]


def buildroot_build_evidence(
    build_dir: Path,
    entries: list[tuple[str, bool]],
    *,
    buildroot_source: Path | None = None,
) -> BuildEvidence | None:
    """Delivered files, images/ and the creator for (name, excluded) entries.

    None without ``packages-file-list.txt``: then nothing is proven and nothing
    changes. Works for any package list (the suite's manifest.csv fallback
    brings names, not records).
    """
    left_out: dict[str, int] = {}
    evidence = buildroot_evidence(build_dir, counts=left_out)
    if not evidence:
        return None
    sources = [f"{ORIGIN_BUILDROOT_TARGET} (output/target)"]
    warnings: list[str] = [outside_warning(r) for r in buildroot_roots_outside(build_dir)]
    if any(left_out.values()):
        warnings.append(
            f"packages-file-list.txt: {left_out['not_regular_or_gone']} listed path(s) "
            "not a delivered regular file (symlink, removed at target-finalize, "
            f"outside); {left_out['shared_paths']} path(s) claimed by two packages, "
            "given to neither")
    image_origin = {"linux": ORIGIN_BUILDROOT_IMAGES_LINUX, "uboot": ORIGIN_BUILDROOT_IMAGES_UBOOT}
    image_counts: dict[str, int] = {}
    per_package, rest = buildroot_image_evidence(build_dir, counts=image_counts)
    if image_counts.get("links_outside"):
        warnings.append(f"{image_counts['links_outside']} file(s) in output/images point "
                        "outside the build directory; not read")
    delivered_names = [name for name, excluded in entries if not excluded]
    creators, creator_gaps = buildroot_creators(
        build_dir, delivered_names,
        delivered={k: list(v.files) for k, v in evidence.items()},
        source=buildroot_source)
    out: list[EntryEvidence] = []
    for name, excluded in entries:
        if excluded:
            out.append(EntryEvidence(name, True, [], 0, REASON_NOT_DELIVERED, None, ""))
            continue
        ev = evidence.get(name) or ComponentEvidence(name, (), ORIGIN_BUILDROOT_TARGET)
        files, unclassified = component_files(ev)
        reason = (REASON_NO_DELIVERED_FILE if not ev.files
                  else "" if files else REASON_NO_EXECUTABLE_FILE)
        images = per_package.get(name)
        if images:
            known = {f.path for f in files}
            files += [r for r in component_files(
                ComponentEvidence(name, tuple(images), image_origin[name]), every_file=True)[0]
                if r.path not in known]
            if files:
                reason = ""
        creator = creators.get(name)
        out.append(EntryEvidence(name, False, files, unclassified, reason, creator,
                                 "" if creator else creator_gaps.get(name, "")))
    images_rest = [_record(f, ORIGIN_BUILDROOT_IMAGES) for f in rest if is_component_file(f)]
    skipped = [f.path for f in rest if not is_component_file(f)]
    if skipped:
        warnings.append("images/ files that are no component (not code, no archive by its "
                        "bytes): " + ", ".join(skipped))
    return BuildEvidence(out, images_rest, warnings, sources)


@dataclass
class BuildrootPackageBuild:
    """A package of Buildroot's SBOM with what the build directory proves."""

    package: BuildrootPackage
    files: list[FileRecord]
    unclassified: int
    not_evidenced: str
    creator: Creator | None
    creator_gap: str
    scope_reason: str


@dataclass
class BuildrootBuild:
    """A Buildroot build as suite and collector describe it."""

    product_name: str
    product_version: str
    packages: list[BuildrootPackageBuild]
    images: list[FileRecord]
    warnings: list[str]
    sources: list[str]

    def delivered_packages(self) -> list[BuildrootPackageBuild]:
        """What the product contains of the packages (§3.2.7): not the host ones.
        The images without a package (``images``) are delivered as well."""
        return [p for p in self.packages if not p.package.host_reason]


def read_buildroot_build(
    build_dir: Path, *, buildroot_source: Path | None = None,
) -> BuildrootBuild | None:
    """Buildroot's own SBOM plus what the build directory proves, composed once.

    None when the folder holds no Buildroot SBOM and nothing to say about it.
    """
    packages, warnings = buildroot_packages(build_dir)
    if not packages and not warnings:
        return None
    sbom = buildroot_sbom_file(build_dir)
    sources = [str(sbom.relative_to(build_dir))] if sbom is not None else []
    seen: set[tuple[str, bool, str, str]] = set()
    unique: list[BuildrootPackage] = []
    for pkg in packages:  # host and target apart even with one purl (F3)
        key = (pkg.purl, bool(pkg.host_reason), pkg.name, pkg.version)
        if key not in seen:
            seen.add(key)
            unique.append(pkg)
    ev = buildroot_build_evidence(build_dir, [(p.name, bool(p.host_reason)) for p in unique],
                                  buildroot_source=buildroot_source)
    builds: list[BuildrootPackageBuild] = []
    for i, pkg in enumerate(unique):
        e = ev.entries[i] if ev is not None else None
        builds.append(BuildrootPackageBuild(
            package=pkg, files=e.files if e else [], unclassified=e.unclassified if e else 0,
            not_evidenced=e.not_evidenced if e else "", creator=e.creator if e else None,
            creator_gap=e.creator_gap if e else "", scope_reason=host_scope_reason(pkg)))
    name, version = buildroot_product(build_dir)
    return BuildrootBuild(
        product_name=name, product_version=version, packages=builds,
        images=ev.images if ev is not None else [],
        warnings=warnings + (ev.warnings if ev is not None else
                             [outside_warning(r) for r in buildroot_roots_outside(build_dir)]),
        sources=sources + (ev.sources if ev is not None else []))
