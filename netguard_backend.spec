# -*- mode: python ; coding: utf-8 -*-

import os
import sys
from PyInstaller.utils.hooks import collect_all

block_cipher = None

base_dir = os.path.abspath(".")

datas = [
    (os.path.join(base_dir, "models", "trained"), os.path.join("models", "trained")),
    (os.path.join(base_dir, "backend", "app"), "app"),
]

torch_datas, torch_binaries, torch_hiddenimports = collect_all('torch')
scapy_datas, scapy_binaries, scapy_hiddenimports = collect_all('scapy')

datas += torch_datas + scapy_datas
binaries = torch_binaries + scapy_binaries

hiddenimports = [
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "sklearn",
    "sklearn.preprocessing",
    "joblib",
    "numpy",
    "pandas",
    "fastapi",
    "pydantic",
    "dotenv",
] + torch_hiddenimports + scapy_hiddenimports

a = Analysis(
    ["backend_entry.py"],
    pathex=[base_dir, os.path.join(base_dir, "backend")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pyarrow", "matplotlib", "tkinter", "PIL", "pytest"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="netguard-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="netguard-backend",
)
