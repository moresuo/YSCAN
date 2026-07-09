#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
tools 包初始化 — 安装 AES 解密导入钩子，后续所有 tools.* 模块从加密文件加载
"""
from tools._decrypt_loader import _install

_install()
