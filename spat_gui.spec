# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for SPAT GUI
# Build mode : onedir  (dist\spat_gui\ folder)
# UPX        : disabled (--noupx)
# Version    : Windows VERSIONINFO from version.txt
# Icon       : anticon.ico

block_cipher = None

a = Analysis(
    ['C:\\tmp\\spat_gui.py'],
    pathex=['C:\\tmp'],
    binaries=[],
    datas=[
        # ── Icons & branding ──────────────────────────────────────────────
        ('C:\\tmp\\anticon.ico',          '.'),
        ('C:\\tmp\\anticon.png',          '.'),
        ('C:\\tmp\\antilogo.png',         '.'),
        ('C:\\tmp\\ant_shield000.png',    '.'),
        ('C:\\tmp\\spat_logo_banner.png', '.'),
        # ── Backend CLI script ────────────────────────────────────────────
        ('C:\\tmp\\spat_cli\\spat_cli.py', 'spat_cli'),
        # ── API key config (bundled so exe works out-of-the-box) ─────────
        ('C:\\tmp\\spat_cli\\.env',        'spat_cli'),
    ],
    hiddenimports=[
        'PIL',
        'PIL.Image',
        'PIL.ImageTk',
        'PIL.ImageDraw',
        'PIL.ImageFont',
        'tkinter',
        'tkinter.ttk',
        'tkinter.scrolledtext',
        'tkinter.filedialog',
        'tkinter.messagebox',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],                             # onedir: no binaries/datas here → COLLECT
    exclude_binaries=True,
    name='spat_gui',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                      # --noupx
    upx_exclude=[],
    console=False,                  # GUI — no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='C:\\tmp\\version.txt',
    icon='C:\\tmp\\anticon.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,                      # --noupx on all collected binaries
    upx_exclude=[],
    name='spat_gui',                # output folder: dist\spat_gui\
)
