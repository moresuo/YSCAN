#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : dns_resolve.py
@Author : moresuo
@Time : 2026/6/30
@脚本说明 : 域名解析为 IP（dnspython，多线程 + 进度条）

支持单个域名或域名文件（一行一个），解析成功的域名逐行打印
`domain -> ip`；可选 -o 将解析出的 IP（去重）保存到文件。
"""
import sys
import threading
import concurrent.futures
import warnings
from pathlib import Path

import dns.resolver
from alive_progress import alive_bar

from tools.color import console

warnings.filterwarnings("ignore")

# 默认线程数（dns 子命令未暴露 -T 线程参数，-T 已用于域名文件）
DEFAULT_THREADS = 100

thread_local = threading.local()


# 每个线程复用自己的 DNS Resolver，避免反复构造
def get_resolver():
    dns_resolver = getattr(thread_local, "resolver", None)
    if dns_resolver is None:
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = ["223.5.5.5", "180.76.76.76"]
        dns_resolver.timeout = 1
        dns_resolver.lifetime = 2
        thread_local.resolver = dns_resolver
    return dns_resolver


# 解析单个域名为 A 记录 IP 列表，失败返回 None
def resolve_domain(domain):
    try:
        answers = get_resolver().resolve(domain, "A")
        return [record.to_text() for record in answers]
    except Exception:
        return None


# 多线程解析入口
def scan_dns_run(domains, threads=DEFAULT_THREADS, ip_file=None):
    from rich.panel import Panel

    domains = list(domains)
    if not domains:
        return

    console.print(Panel.fit(
        f"[accent]域名数[/accent]  [count]{len(domains)}[/count]",
        title="[header]域名解析[/header]",
        border_style="dim",
    ))

    results = []           # [(domain, [ips])] 仅记录解析成功的
    results_lock = threading.Lock()
    completed = [0]        # 已完成计数（含失败）
    counter_lock = threading.Lock()
    _tracked = [0]         # 已计入进度条的数量

    def _resolve(domain):
        ips = resolve_domain(domain)
        # 解析成功才打印；失败静默跳过
        if ips:
            console.print(f"  [success]●[/success] [host]{domain}[/host] [dim]→ {', '.join(ips)}[/dim]")
            with results_lock:
                results.append((domain, ips))

    def _on_done(_fut):
        with counter_lock:
            completed[0] += 1
            delta = completed[0] - _tracked[0]
            _tracked[0] = completed[0]
        if delta > 0:
            _bar(delta)

    # 进度条与端口扫描一致，输出到 stderr 避免与 console 输出互相干扰
    with alive_bar(
        len(domains),
        title="域名解析",
        bar="smooth",
        spinner="dots_waves2",
        enrich_print=False,
        file=sys.__stderr__,
        receipt=True,
        receipt_text="域名解析完成",
    ) as _bar:
        workers = min(threads, max(1, len(domains)))
        batch_size = max(workers * 8, 1)
        # 分批提交 + done_callback 回调进度，避免大域名文件一次性创建大量 Future
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for domain in domains:
                fut = executor.submit(_resolve, domain)
                fut.add_done_callback(_on_done)
                futures.append(fut)
                if len(futures) >= batch_size:
                    concurrent.futures.wait(futures)
                    futures.clear()
            if futures:
                concurrent.futures.wait(futures)
        # 收尾补偿：done_callback 与 wait 间微小竞态
        remaining = completed[0] - _tracked[0]
        if remaining > 0:
            _bar(remaining)

    # 保存解析出的 IP 到文件（去重，保持顺序）
    if ip_file:
        ips = []
        seen = set()
        for _domain, domain_ips in results:
            for ip in domain_ips:
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
        Path(ip_file).parent.mkdir(parents=True, exist_ok=True)
        with open(ip_file, "w", encoding="utf-8") as f:
            if ips:
                f.write("\n".join(ips) + "\n")
        console.print(f"[info]→ 已保存 {len(ips)} 个 IP 至 [url]{ip_file}[/url]")

    console.print(f"[info]解析成功 {len(results)} / {len(domains)}[/info]")
