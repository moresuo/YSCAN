#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : dir_scan.py
@Author : moresuo
@Time : 2026/6/27 11:24
@脚本说明 : 目录扫描
"""
import sys
import threading
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from alive_progress import alive_bar

from tools.color import console

BASE_DIR = Path(__file__).resolve().parent.parent
DIR_PATH = BASE_DIR / "libs" / "dirpath.txt"

warnings.filterwarnings("ignore")

thread_local = threading.local()
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}


#每个线程复用自己的 Session
def get_session():
    session = getattr(thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update(_HEADERS)
        session.trust_env = False
        thread_local.session = session
    return session


#格式化响应体大小
def _fmt_size(nbytes):
    if nbytes >= 1024 * 1024:
        return f"{nbytes / (1024*1024):.1f}MB"
    elif nbytes >= 1024:
        return f"{nbytes / 1024:.1f}KB"
    return f"{nbytes}B"


#单个探测：工作线程只发请求返回结果元组，不调 console
def _scan_dir(url, timeout):
    try:
        response = get_session().get(url, verify=False, timeout=timeout)
        code = response.status_code
        if code in [200, 301, 302, 401, 403]:
            size = _fmt_size(len(response.content))
            color = {
                200: "success", 301: "info", 302: "info",
                401: "warn",   403: "fail",
            }.get(code, "dim")
            return (color, code, size, url)
    except Exception:
        pass
    return None


#多线程执行（alive_bar 进度条 + 主线程 as_completed 实时 Rich 输出）
def scan_dir_run(base_url, threads, timeout=3):
    from rich.panel import Panel

    with open(file=DIR_PATH, mode="r", encoding="utf-8") as dirpath:
        paths = [p.strip() for p in dirpath if p.strip()]

    console.print(Panel.fit(
        f"[accent]目标[/accent]  [url]{base_url}[/url]\n"
        f"[accent]字典[/accent]  [count]{len(paths)}[/count] 条路径",
        title="[header]Web 目录扫描[/header]",
        border_style="dim",
    ))

    total = len(paths)
    workers = min(threads, max(1, total))
    tasks = [base_url + p for p in paths]

    with alive_bar(
        total,
        title="目录扫描",
        bar="smooth",
        spinner="dots_waves2",
        enrich_print=False,
        file=sys.__stderr__,
        receipt=True,
        receipt_text="目录扫描完成",
    ) as _bar:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            # as_completed 主线程迭代：每完成一个立即打印，Rich 单线程访问无空行
            futures = {executor.submit(_scan_dir, url, timeout): url for url in tasks}
            for fut in as_completed(futures):
                _bar()
                item = fut.result()
                if item:
                    color, code, size, url = item
                    console.print(
                        f"  [{color}]●[/{color}] [host]{url}[/host] "
                        f"[dim]→ {code} {size}[/dim]"
                    )
