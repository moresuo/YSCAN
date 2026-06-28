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

BASE_DIR = Path(__file__).resolve().parent.parent
DIR_PATH = BASE_DIR / "libs" / "dirpath.txt"

thread_local = threading.local()
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}


#每个线程复用自己的 Session，避免每次请求都重新创建连接池
def get_session():
    session = getattr(thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update(headers)
        thread_local.session = session
    return session


#目录扫描
def scan_dir(url):
    try:
        response = get_session().get(url, verify=False, timeout=3)
        if response.status_code in [200, 301, 302, 401, 403]:
            print(f"[+] 存在目录[{response.status_code}]：{url}")
    except:
        pass


#多线程执行
def scan_dir_run(base_url, threads):
    with open(file=DIR_PATH, mode="r", encoding="utf-8") as dirpath:
        paths = (path.strip() for path in dirpath)
        tasks = ((base_url + path,) for path in paths if path)
        run_batch(tasks, scan_dir, threads)
