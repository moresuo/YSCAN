#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
运行时 AES-256 解密模块加载器
通过 sys.meta_path 导入钩子拦截 tools.* 导入，内存解密 .enc 文件后执行
"""
import sys
import types
import marshal
import base64
from pathlib import Path
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import ModuleSpec

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# ── 密钥材料（与 build_encrypted.py 一致）──
_SALT = base64.b64decode("vLj4taFjtbVVUolR+k18OPrZywSo4meEHqZncquOB04=")
_PASSPHRASE = b"YSCAN::runtime::module::loader::v1"
_KEY = PBKDF2(_PASSPHRASE, _SALT, dkLen=32, count=100_000)


def _get_encrypted_dir():
    """兼容开发环境和 PyInstaller frozen 环境"""
    if getattr(sys, "frozen", False):
        base = Path(sys._MEIPASS) / "tools"
    else:
        base = Path(__file__).resolve().parent
    return base / "_encrypted"


class _DecryptLoader(MetaPathFinder, Loader):
    """sys.meta_path 导入钩子：拦截 tools.* 模块，从 .enc 文件解密加载。"""

    def __init__(self):
        self._enc_dir = _get_encrypted_dir()

    def find_spec(self, fullname, path, target=None):
        # 只处理 tools.xxx 形式的子模块
        if not fullname.startswith("tools."):
            return None
        parts = fullname.split(".")
        if len(parts) != 2:
            return None
        module_name = parts[1]
        enc_path = self._enc_dir / f"{module_name}.enc"
        if not enc_path.exists():
            return None

        spec = ModuleSpec(fullname, self, origin=str(enc_path))
        spec.has_location = False
        return spec

    def create_module(self, spec):
        mod = types.ModuleType(spec.name)
        # 将 __file__ 指向源文件路径（而非 .enc），
        # 避免各模块 Path(__file__).parent.parent 算错项目根目录
        parts = spec.name.split(".")
        module_name = parts[1] if len(parts) >= 2 else spec.name
        source = str(self._enc_dir.parent / f"{module_name}.py")
        mod.__file__ = source
        mod.__loader__ = self
        mod.__package__ = "tools"
        mod.__name__ = spec.name
        return mod

    def exec_module(self, module):
        fullname = module.__name__
        parts = fullname.split(".")
        module_name = parts[1]
        enc_path = self._enc_dir / f"{module_name}.enc"

        # 读取加密数据
        encrypted = enc_path.read_bytes()

        # AES-256-CBC 解密
        iv = encrypted[:16]
        ciphertext = encrypted[16:]
        cipher = AES.new(_KEY, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)

        # 去除 PKCS7 padding
        pad_len = padded[-1]
        if 1 <= pad_len <= 16:
            payload = padded[:-pad_len]
        else:
            payload = padded

        # marshal 反序列化 → code object
        code = marshal.loads(payload)
        exec(code, module.__dict__)


# ── 安装钩子 ──
_LOADER_INSTANCE = _DecryptLoader()


def _install():
    """安装解密导入钩子到 sys.meta_path 最前端。幂等。"""
    if _LOADER_INSTANCE not in sys.meta_path:
        sys.meta_path.insert(0, _LOADER_INSTANCE)


# 模块导入时自动安装
_install()
