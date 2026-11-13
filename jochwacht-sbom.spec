# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the standalone jochwacht-sbom binary.

Build with:
    pyinstaller jochwacht-sbom.spec --clean
"""

from PyInstaller.utils.hooks import collect_submodules

a = Analysis(
    ["src/jochwacht_sbom/cli.py"],
    pathex=["src"],
    binaries=[],
    # The SPDX lists of the shared licence library (sbom/licenses.py reads them
    # at run time); without them the binary could not classify a licence.
    datas=[("src/jochwacht_sbom/sbom/data/*.yaml", "jochwacht_sbom/sbom/data")],
    hiddenimports=[
        "jochwacht_sbom.payload",
        "jochwacht_sbom.collector",
        "jochwacht_sbom.upload",
        "jochwacht_sbom.analyzer.pipeline.tier1_cli",
        "jochwacht_sbom.analyzer.pipeline.tier2_structured",
        "jochwacht_sbom.analyzer.pipeline.tier4_regex",
        "jochwacht_sbom.analyzer.pipeline.merge",
        "jochwacht_sbom.analyzer.scanner",
        "jochwacht_sbom.analyzer.normalize",
        "jochwacht_sbom.sbom.scanner",
        "jochwacht_sbom.core.exceptions",
        *collect_submodules("jochwacht_sbom.analyzer.parsers"),
        "yaml",
        "pydantic",
        "click",
        "rich",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "mypy", "ruff"],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="jochwacht-sbom",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
)
