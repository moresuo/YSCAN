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
import concurrent.futures
from pathlib import Path

import requests
from alive_progress import alive_bar

from tools.color import console

BASE_DIR = Path(__file__).resolve().parent.parent
DIR_PATH = BASE_DIR / "libs" / "dirpath.txt"

thread_local = threading.local()
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}


def get_session():
    session = getattr(thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update(_HEADERS)
        session.trust_env = False
        thread_local.session = session
    return session


def _fmt_size(nbytes):
    if nbytes >= 1024 * 1024:
        return f"{nbytes / (1024*1024):.1f}MB"
    elif nbytes >= 1024:
        return f"{nbytes / 1024:.1f}KB"
    return f"{nbytes}B"


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
    results = []
    results_lock = threading.Lock()
    done = [0]
    done_lock = threading.Lock()

    def _scan(url):
        try:
            r = get_session().get(url, verify=False, timeout=timeout)
            c = r.status_code
            if c in [200, 301, 302, 401, 403]:
                s = _fmt_size(len(r.content))
                clr = {200: "success", 301: "info", 302: "info",
                       401: "warn", 403: "fail"}.get(c, "dim")
                with results_lock:
                    results.append((clr, c, s, url))
        except Exception:
            pass
        with done_lock:
            done[0] += 1

    def _flush_results():
        """主线程：打印新增结果，Rich 格式不会踏"""
        with results_lock:
            if not results:
                return
            items = list(results)
            results.clear()
        for clr, c, s, url in items:
            console.print(
                f"  [{clr}]●[/{clr}] [url]{url}[/url] "
                f"[dim][{clr}]{c}[/{clr}] {s}[/dim]"
            )

    with alive_bar(
        total, title="目录扫描", bar="smooth", spinner="dots_waves2",
        enrich_print=False, file=sys.__stderr__,
        receipt=True, receipt_text="目录扫描完成",
    ) as _bar:
        chunk = max(workers * 8, 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            last = 0
            for url in [base_url + p for p in paths]:
                futures.append(executor.submit(_scan, url))
                if len(futures) >= chunk:
                    concurrent.futures.wait(futures)
                    _bar(done[0] - last)
                    _flush_results()
                    last = done[0]
                    futures.clear()
            if futures:
                concurrent.futures.wait(futures)
                _bar(done[0] - last)
        _flush_results()
