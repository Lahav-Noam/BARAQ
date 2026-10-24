# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller ONE-FILE spec: bundles everything into a single BARAQ.exe.

Build with:  venv\Scripts\pyinstaller --noconfirm --clean baraq_onefile.spec
Output:      dist\BARAQ.exe  (single file, ~220 MB)
Note:        slower startup than the folder build (extracts to a temp dir).
"""
from pathlib import Path

ROOT = Path(SPECPATH)

datas = [
    (str(ROOT / "backend" / "mitre" / "techniques.json"), "backend/mitre"),
    (str(ROOT / "backend" / "vulnscan" / "cves.json"), "backend/vulnscan"),
    (str(ROOT / "backend" / "detection" / "signatures.json"), "detection"),
    (str(ROOT / "backend" / "detection" / "correlation_rules"), "detection/correlation_rules"),
    (str(ROOT / "frontend" / "dist"), "frontend/dist"),
    (str(ROOT / "sigma_rules"), "sigma_rules"),
]

hiddenimports = [
    "pywintypes",
    "win32evtlog",
    "win32evtlogutil",
    "win32timezone",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
]

a = Analysis(
    [str(ROOT / "scripts" / "run_server.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tests", "documentation"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    exclude_binaries=False,
    name="BARAQ",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)