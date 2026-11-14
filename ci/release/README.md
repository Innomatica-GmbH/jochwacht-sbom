# The release lock

What a release of jochwacht-sbom is built from (Ivan, 14.11.2026, via the
coordination). Every pin carries its hashes; nothing is resolved during a
release.

| File | What it pins |
|------|--------------|
| `runtime.txt` | the libraries of the tool: bundled into the binary, and the wheel's resolution at release time |
| `build.txt` | PyInstaller, `build` and the build backend `hatchling` |
| `audit.txt` | pip-audit itself |
| `selftest-vulnerable.txt` | deliberately vulnerable: CI checks that the gate stops on it |

`gate.sh` runs pip-audit over `runtime.txt` and `build.txt`; the publish
workflow's `pypi` and `binary` jobs need it. A known vulnerability stops the
release; there is no exception list. The fix is a new pin, not an ignore.

`binary_sbom.py` writes the binary's own CycloneDX SBOM from PyInstaller's
table of contents and this locked environment; it fails when a bundled
library is not pinned here.

To update the pins (Linux x86_64, Python 3.12, as the binary is built):

```bash
C="--generate-hashes --python-version 3.12 --python-platform x86_64-unknown-linux-gnu --no-header --quiet"
uv pip compile pyproject.toml $C -o ci/release/runtime.txt
uv pip compile ci/release/build.in -c ci/release/runtime.txt $C -o ci/release/build.txt
uv pip compile ci/release/audit.in $C -o ci/release/audit.txt
uv pip compile ci/release/selftest-vulnerable.in $C -o ci/release/selftest-vulnerable.txt
```
