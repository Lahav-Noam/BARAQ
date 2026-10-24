# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the BARAQ packaged executable.

Build with:  venv\Scripts\pyinstaller --noconfirm --clean baraq.spec
Output:      dist\BARAQ\BARAQ.exe  (onedir layout)
"""
import sys
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

# Conda-built CPython on Windows: python313.dll imports zlib.dll and
# _ctypes.pyd imports ffi.dll (libffi) at runtime, but PyInstaller does not
# collect those conda library DLLs, so a frozen app dies with "DLL load
# failed while importing _ctypes". Bundle them next to the other DLLs.
_binaries = []
_base = Path(getattr(sys, "_base_executable", sys.executable)).resolve().parent
for _candidate in (
    _base / "Library" / "bin" / "zlib.dll",
    _base / "zlib.dll",
):
    if _candidate.exists():
        _binaries.append((str(_candidate), "."))
        break
for _candidate in (
    _base / "Library" / "bin" / "ffi.dll",
    _base / "Library" / "bin" / "libffi.dll",
):
    if _candidate.exists():
        _binaries.append((str(_candidate), "."))
        break

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
    binaries=_binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tests", "documentation", "matplotlib"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name="BARAQ",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="BARAQ",
)
