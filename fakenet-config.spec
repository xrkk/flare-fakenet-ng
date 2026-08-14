# -*- mode: python ; coding: utf-8 -*-
# fakenet-config GUI spec (plan v0.2 §5.6).
#
# Differences from fakenet.spec:
# - tkinter is KEPT (no TOC subtraction - that old syntax is gone in
#   PyInstaller 6 anyway);
# - no WinDivert driver files, no diverter/listener deps - the GUI is
#   pure standard library;
# - windowed (console=False) and NOT elevated (no uac_admin): the tool
#   runs as a normal user and elevates fakenet.exe itself via
#   ShellExecuteW 'runas' at launch time.

block_cipher = None

a = Analysis(
    ['fakenet/gui/main.py'],
    pathex=['fakenet'],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='fakenet-config',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon='resources/fakenet.ico',
)
