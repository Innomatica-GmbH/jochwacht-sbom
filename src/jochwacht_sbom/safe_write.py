"""Writing into a scanned repository without following a symbolic link.

A scanned repository is foreign input (sicherheit-2, S1/S2, 13.11.2026): in
CI it can be a pull request from a fork. If a file the collector writes, or
the folder ``.jochwacht`` it writes into, is a symbolic link, writing through
it would overwrite whatever the link points to. Every write goes through
:func:`write_file`, which refuses a link with a clear message.
"""

from __future__ import annotations

import os
from pathlib import Path

from jochwacht_sbom.core.exceptions import JochwachtError

#: O_NOFOLLOW where the platform has it (not on Windows: the lstat check covers it).
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)


def _refuse(path: Path, what: str) -> JochwachtError:
    return JochwachtError(
        f"{path} is a symbolic link; {what} is not written through it. Remove the "
        f"link, or write the bill elsewhere with --sbom PATH.",
        exit_code=1,
    )


def ensure_folder(folder: Path) -> None:
    """Create *folder* (``.jochwacht``) if needed; refuse it as a symbolic link."""
    if folder.is_symlink():
        raise _refuse(folder, "the folder")
    folder.mkdir(parents=True, exist_ok=True)
    if folder.is_symlink():  # created in between: refuse all the same
        raise _refuse(folder, "the folder")


def write_file(path: Path, data: bytes, *, fresh: bool = False) -> None:
    """Write *data* to *path*, never through a symbolic link.

    *fresh*: an existing regular file is removed first and the file is created
    anew with O_EXCL, so not even a link placed in between is followed.
    """
    if path.is_symlink():
        raise _refuse(path, "the file")
    if path.parent.is_symlink():
        raise _refuse(path.parent, "the folder")
    flags = os.O_WRONLY | os.O_CREAT | _NOFOLLOW | _BINARY
    if fresh:
        if path.exists():
            path.unlink()
        flags |= os.O_EXCL
    else:
        flags |= os.O_TRUNC
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        if path.is_symlink():
            raise _refuse(path, "the file") from exc
        raise
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
