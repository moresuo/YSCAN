#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : WordlistTools.py
@Author : moresuo
@Time : 2026/6/28
@脚本说明 : 字典读取工具
"""


#读取字典，过滤空行并去重，保持原始顺序
def load_lines(path):
    lines = []
    seen = set()
    with open(file=path, mode="r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or line in seen:
                continue
            seen.add(line)
            lines.append(line)
    return lines
