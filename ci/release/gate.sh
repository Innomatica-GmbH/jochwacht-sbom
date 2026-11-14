#!/bin/sh
# The release gate (Ivan, 14.11.2026, via the coordination): before the PyPI
# and the binary upload, pip-audit checks every library that goes into the
# binary and into the wheel's resolution, as pinned in the hashed lock files.
# A known vulnerability stops the release. There is no exception list, on
# purpose: no vulnerability is ignored by id.
#
#   sh ci/release/gate.sh -r ci/release/runtime.txt -r ci/release/build.txt
#
# pip-audit itself comes from ci/release/audit.txt (pip install --require-hashes).
set -eu
exec pip-audit --strict --require-hashes --disable-pip --progress-spinner off "$@"
