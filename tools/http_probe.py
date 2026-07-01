#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : http_probe.py
@Author : moresuo
@Time : 2026/6/30
@脚本说明 : 外网 HTTP 存活探测（httpx 式，多线程 + 进度条）

对地址列表逐个发 HTTP GET，响应 200 视为存活。地址支持
`http(s)://host[:port]`、`host`、`IP:port` 等格式，自动规整化补全协议。
"""
import sys
import threading
import concurrent.futures
import warnings
from pathlib import Path
from urllib.parse import urlparse

import requests
from alive_progress import alive_bar

from tools.color import console

warnings.filterwarnings("ignore")

# 默认线程数（外网探测 IO 密集，但需控制并发避免被目标限流）
DEFAULT_THREADS = 100
# 单请求超时（连接+读取各计时）
TIMEOUT = 5

thread_local = threading.local()

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}


# 每个线程复用自己的 Session，连接池复用提升性能
def get_session():
    session = getattr(thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update(_HEADERS)
        thread_local.session = session
    return session


# URL 规整化：补全协议，兼容 IP:port / 域名 / 已带协议地址
def normalize_url(raw):
    """把用户输入规整为完整 URL；无法识别返回 None。

    规则：
      - 已带 http(s)://：原样返回（去尾斜杠）
      - 形如 IP:port 或 host:port：补 http://
      - 纯 host：补 http://（后续探测若 https 可用优先 https）
    """
    s = raw.strip().rstrip("/")
    if not s:
        return None
    if s.startswith("http://") or s.startswith("https://"):
        return s
    # 形如 host:port 或纯 host，直接补 http://
    return "http://" + s


# 探测单个地址，存活返回 URL，否则返回 None
def probe_url(url):
    session = get_session()
    try:
        # verify=False 容忍自签证书；allow_redirects 跟随跳转看最终状态码
        resp = session.get(url, verify=False, timeout=TIMEOUT, allow_redirects=True)
        if resp.status_code == 200:
            return url
    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass
    return None


# 多线程探测入口
def scan_http_run(targets, threads=DEFAULT_THREADS, output_file=None):
    from rich.panel import Panel

    targets = list(targets)
    if not targets:
        return

    # 规整化并去重（保持顺序），跳过无效行
    seen = set()
    urls = []
    for raw in targets:
        u = normalize_url(raw)
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    console.print(Panel.fit(
        f"[accent]地址数[/accent]  [count]{len(urls)}[/count]",
        title="[header]HTTP 存活探测[/header]",
        border_style="dim",
    ))

    alive_list = []         # 存活 URL 列表
    alive_lock = threading.Lock()
    completed = [0]
    counter_lock = threading.Lock()
    _tracked = [0]

    def _probe(url):
        result = probe_url(url)
        if result:
            console.print(f"  [success]●[/success] [url]{result}[/url] [dim]200 OK[/dim]")
            with alive_lock:
                alive_list.append(result)

    def _on_done(_fut):
        with counter_lock:
            completed[0] += 1
            delta = completed[0] - _tracked[0]
            _tracked[0] = completed[0]
        if delta > 0:
            _bar(delta)

    # 进度条与端口扫描一致，输出到 stderr
    with alive_bar(
        len(urls),
        title="HTTP探测",
        bar="smooth",
        spinner="dots_waves2",
        enrich_print=False,
        file=sys.__stderr__,
        receipt=True,
        receipt_text="HTTP探测完成",
    ) as _bar:
        workers = min(threads, max(1, len(urls)))
        batch_size = max(workers * 8, 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for url in urls:
                fut = executor.submit(_probe, url)
                fut.add_done_callback(_on_done)
                futures.append(fut)
                if len(futures) >= batch_size:
                    concurrent.futures.wait(futures)
                    futures.clear()
            if futures:
                concurrent.futures.wait(futures)
        remaining = completed[0] - _tracked[0]
        if remaining > 0:
            _bar(remaining)

    # 导出存活地址到文件
    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            if alive_list:
                f.write("\n".join(alive_list) + "\n")
        console.print(f"[info]→ 已保存 {len(alive_list)} 个存活地址至 [url]{output_file}[/url]")

    console.print(f"[info]存活 {len(alive_list)} / {len(urls)}[/info]")
