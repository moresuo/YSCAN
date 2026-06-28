#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : dir_scan.py
@Author : moresuo
@Time : 2026/6/27 11:24
@脚本说明 : 目录扫描
"""
import threading
from pathlib import Path

import requests

from tools.SchedulerTools import run_batch
from tools.color import console

BASE_DIR = Path(__file__).resolve().parent.parent
DIR_PATH = BASE_DIR / "libs" / "dirpath.txt"

thread_local = threading.local()
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}


#每个线程复用自己的 Session
def get_session():
    session = getattr(thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update(headers)
        thread_local.session = session
    return session


#格式化响应体大小
def _fmt_size(nbytes):
    if nbytes >= 1024 * 1024:
        return f"{nbytes / (1024*1024):.1f}MB"
    elif nbytes >= 1024:
        return f"{nbytes / 1024:.1f}KB"
    return f"{nbytes}B"


#目录扫描
def scan_dir(url, timeout=3):
    try:
        response = get_session().get(url, verify=False, timeout=timeout)
        size = len(response.content)
        if response.status_code in [200, 301, 302, 401, 403]:
            color = {
                200: "success", 301: "info", 302: "info",
                401: "warn",   403: "fail",
            }.get(response.status_code, "dim")
            console.print(f"  [{color}]{response.status_code:>3}[/{color}] {_fmt_size(size):>8}  [url]{url}[/url]")
    except:
        pass


#多线程执行
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
    tasks = ((base_url + p, timeout) for p in paths)
    run_batch(tasks, scan_dir, threads)
