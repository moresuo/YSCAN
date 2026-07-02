#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : subdomain_scan.py
@Author : moresuo
@Time : 2026/6/27 11:56
@脚本说明 : 子域名扫描
"""
import sys
import threading
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import dns.resolver
from alive_progress import alive_bar

from tools.color import console

BASE_DIR = Path(__file__).resolve().parent.parent
DIR_PATH = BASE_DIR / "libs" / "subdomain.txt"

warnings.filterwarnings("ignore")

thread_local = threading.local()


#每个线程复用自己的 DNS Resolver
def get_resolver():
    dns_resolver = getattr(thread_local, "resolver", None)
    if dns_resolver is None:
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = ["223.5.5.5", "180.76.76.76"]
        dns_resolver.timeout = 1
        dns_resolver.lifetime = 2
        thread_local.resolver = dns_resolver
    return dns_resolver


#单个解析：工作线程只发请求返回结果元组，不调 console
def _scan_subdomain(domain, subdomain):
    full_domain = f"{subdomain}.{domain}"
    try:
        dns_result = get_resolver().resolve(full_domain, "A")
        ips = [record.to_text() for record in dns_result]
        return (full_domain, ", ".join(ips))
    except Exception:
        return None


#多线程执行（alive_bar 进度条 + 主线程 as_completed 实时 Rich 输出）
def scan_subdomain_run(domain, threads):
    from rich.panel import Panel
    with open(file=DIR_PATH, mode="r", encoding="utf-8") as subdomains:
        names = [s.strip() for s in subdomains if s.strip()]
    console.print(Panel.fit(
        f"[accent]目标域名[/accent]  [host]{domain}[/host]\n"
        f"[accent]字典条目[/accent]  [count]{len(names)}[/count]",
        title="[header]子域名爆破[/header]",
        border_style="dim",
    ))

    total = len(names)
    workers = min(threads, max(1, total))

    with alive_bar(
        total,
        title="子域名爆破",
        bar="smooth",
        spinner="dots_waves2",
        enrich_print=False,
        file=sys.__stderr__,
        receipt=True,
        receipt_text="子域名爆破完成",
    ) as _bar:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            # as_completed 主线程迭代：每完成一个立即打印，Rich 单线程访问无空行
            futures = {executor.submit(_scan_subdomain, domain, s): s for s in names}
            for fut in as_completed(futures):
                _bar()
                item = fut.result()
                if item:
                    full_domain, ips = item
                    console.print(
                        f"  [success]●[/success] [host]{full_domain}[/host] "
                        f"[dim]→ {ips}[/dim]"
                    )
