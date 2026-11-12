"""When a git revision names a fixed state: tag or commit, not a branch.

Used by the west.yml reader and by FetchContent ``GIT_TAG``. A branch
(``main``, ``develop``, ``ncs-2.6``, ``feature/2.0-rework``) names a moving
target and is never a version. Pinned are:

- a commit hash (7 to 40 hex digits),
- a version number with an optional ``v``: ``3.6.0``, ``v2.6``, ``2.6``,
- a prefixed tag only together with ``v``: ``zephyr-v3.6.0``,
- each optionally with a pre-release or vendor suffix:
  ``v3.5.99-ncs1``, ``1.2.0-rc1``.

Anything with a slash or whitespace is a branch. Shared file: the open
collector carries a generated copy (ci/sync-twin.py).
"""

from __future__ import annotations

import re

_HEX = re.compile(r"[0-9a-f]{7,40}\Z")
_TAG = re.compile(
    r"(?:(?:[A-Za-z][A-Za-z0-9_]*-)?v)?"           # "v" or "zephyr-v"
    r"[0-9]+(?:\.[0-9]+)+"                           # 3.6 / 3.6.0
    r"(?:[-+.]?(?:rc|alpha|beta|pre|ncs|dev|post|p)\.?[0-9]+)?\Z",
    re.IGNORECASE,
)


def is_pinned_revision(revision: str) -> bool:
    """A tag or a commit hash pins; a branch name does not."""
    if not isinstance(revision, str):
        return False
    rev = revision.strip()
    if not rev or any(ch.isspace() for ch in rev) or "/" in rev:
        return False
    return bool(_HEX.match(rev.lower()) or _TAG.match(rev))
