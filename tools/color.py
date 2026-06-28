#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : color.py
@Author : moresuo
@Time : 2026/6/28 10:15
@脚本说明 : ANSI 颜色常量 + Rich 控制台实例
"""
from rich.console import Console
from rich.theme import Theme

# Rich 主题 — 终端样式统一管理
_theme = Theme({
    "banner":     "bold #f778ba",
    "header":     "bold #f778ba",
    "success":    "bold #3fb950",
    "fail":       "bold #f85149",
    "warn":       "bold #d2991d",
    "info":       "bold #58a6ff",
    "highlight":  "bold #a371f7",
    "dim":        "#8b949e",
    "port":       "#79c0ff",
    "service":    "#a371f7",
    "host":       "bold #ffa657",
    "url":        "#7ee787",
    "count":      "bold #f778ba",
    "accent":     "bold #c9d1d9",
})

# 全局共享 Console，所有模块导入此实例即可
console = Console(theme=_theme, highlight=False)

# ── 保留旧 ANSI 常量，兼容现有代码 ──────────────────────────────

class Colors:
    RESET         = "\033[0m"
    BLACK         = "\033[30m"
    RED           = "\033[31m"
    GREEN         = "\033[32m"
    YELLOW        = "\033[33m"
    BLUE          = "\033[34m"
    MAGENTA       = "\033[35m"
    CYAN          = "\033[36m"
    WHITE         = "\033[37m"
    BLACK_BRIGHT  = "\033[90m"
    RED_BRIGHT    = "\033[91m"
    GREEN_BRIGHT  = "\033[92m"
    YELLOW_BRIGHT = "\033[93m"
    BLUE_BRIGHT   = "\033[94m"
    MAGENTA_BRIGHT = "\033[95m"
    CYAN_BRIGHT   = "\033[96m"
    WHITE_BRIGHT  = "\033[97m"
    BG_BLACK      = "\033[40m"
    BG_RED        = "\033[41m"
    BG_GREEN      = "\033[42m"
    BG_YELLOW     = "\033[43m"
    BG_BLUE       = "\033[44m"
    BG_MAGENTA    = "\033[45m"
    BG_CYAN       = "\033[46m"
    BG_WHITE      = "\033[47m"
    BOLD          = "\033[1m"
    UNDERLINE     = "\033[4m"
    REVERSE       = "\033[7m"
