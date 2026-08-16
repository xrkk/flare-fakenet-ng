# -*- mode: python ; coding: utf-8 -*-
# fakenet-GUI spec (plan v1.14 §12.18).
#
# Differences from fakenet.spec:
# - tkinter is KEPT (no TOC subtraction - that old syntax is gone in
#   PyInstaller 6 anyway);
# - no WinDivert driver files, no diverter/listener deps - the GUI is
#   pure standard library;
# - windowed (console=False) and NOT elevated (no uac_admin): the tool
#   runs as a normal user and elevates fakenet.exe itself via
#   ShellExecuteExW 'runas' at launch time and retains the core process handle.

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

splash = Splash(
    'resources/fakenet.png',
    binaries=a.binaries,
    datas=a.datas,
    # Omitting text_pos intentionally disables PyInstaller's extraction-name
    # stream; the project image gives immediate feedback without leaking
    # internal paths such as _tcl_data\encoding\ascii.enc to users.
    minify_script=True,
    always_on_top=True,
)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    splash,
    splash.binaries,
    [],
    name='fakenet-GUI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon='resources/fakenet.ico',
)
