# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['yscan.py'],
    pathex=[],
    binaries=[],
    datas=[('tools', 'tools'), ('libs', 'libs')],
    hiddenimports=['scapy.layers.l2', 'scapy.layers.inet', 'scapy.layers.inet6', 'scapy.layers.dns', 'curl_cffi', 'Crypto.Protocol.KDF', 'yaml', 'mmh3'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='yscan',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
