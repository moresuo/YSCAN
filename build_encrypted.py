#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
构建脚本：将 tools/*.py 编译为 .pyc 后 AES-256-CBC 加密
运行时机：PyInstaller 打包之前
自动同步盐到 _decrypt_loader.py
"""
import base64
import hashlib
import marshal
import os
import py_compile
import re
import struct
import sys
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Windows GBK console workaround
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TOOLS_DIR = Path(__file__).resolve().parent / "tools"
ENCRYPTED_DIR = TOOLS_DIR / "_encrypted"

# 排除文件：不需要加密的（加载器自身 + 加密目录）
EXCLUDE = {
    "__init__.py",
    "_decrypt_loader.py",
    "online.py",
}

# ── 密钥派生（PBKDF2 + 随机盐）──
SALT = get_random_bytes(32)
PASSPHRASE = b"YSCAN::runtime::module::loader::v1"

KEY = PBKDF2(PASSPHRASE, SALT, dkLen=32, count=100_000)


def encrypt_pyc(source_path: Path) -> bytes:
    """编译 .py → .pyc，marshal 序列化后 AES-256-CBC 加密，返回密文。"""
    # 1. 编译为 .pyc（生成在 __pycache__）
    pyc_path = py_compile.compile(
        str(source_path),
        cfile=None,
        dfile=str(source_path),
        doraise=True,
        optimize=2,
    )
    # 2. 读取 .pyc，跳过 16 字节头（magic + flags + timestamp + size）
    with open(pyc_path, "rb") as f:
        header = f.read(16)
        code_bytes = f.read()

    # 3. marshal 反序列化得到 code object，再重新序列化（去除 header 依赖）
    code = marshal.loads(code_bytes)
    payload = marshal.dumps(code)
    try:
        os.unlink(pyc_path)
    except OSError:
        pass
    return payload


def aes_encrypt(plaintext: bytes) -> bytes:
    """AES-256-CBC 加密，返回 IV + ciphertext。"""
    iv = get_random_bytes(16)
    # PKCS7 padding
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(padded)


def sync_salt_to_loader(salt_b64):
    """自动将新盐写入 _decrypt_loader.py。"""
    loader_path = TOOLS_DIR / "_decrypt_loader.py"
    with open(loader_path, "r", encoding="utf-8") as f:
        content = f.read()
    new_content = re.sub(
        r'_SALT = base64\.b64decode\(b?"[^"]*"\)',
        f'_SALT = base64.b64decode("{salt_b64}")',
        content,
    )
    if new_content != content:
        with open(loader_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        print(f"  [OK] 盐已自动同步到 _decrypt_loader.py")
    else:
        print(f"  [!] 盐行未匹配，请手动检查 _decrypt_loader.py")


def build():
    ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)

    py_files = sorted(
        f for f in TOOLS_DIR.glob("*.py")
        if f.name not in EXCLUDE
    )

    if not py_files:
        print("[!] 未找到需要加密的 .py 文件")
        return

    print(f"[*] 加密 {len(py_files)} 个模块...")

    for src in py_files:
        module_name = src.stem
        try:
            payload = encrypt_pyc(src)
            encrypted = aes_encrypt(payload)
            dest = ENCRYPTED_DIR / f"{module_name}.enc"
            dest.write_bytes(encrypted)
            print(f"  [OK] {src.name} -> _encrypted/{module_name}.enc ({len(encrypted)} bytes)")
        except Exception as e:
            print(f"  [FAIL] {src.name}: {e}")
            raise

    salt_b64 = base64.b64encode(SALT).decode()
    print(f"\n[*] 密钥盐 (base64): {salt_b64}")
    sync_salt_to_loader(salt_b64)
    print(f"[*] 完成！已生成 {len(py_files)} 个加密模块到 {ENCRYPTED_DIR}")


if __name__ == "__main__":
    build()