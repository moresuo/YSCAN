#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : subdomain_scan.py
@Author : moresuo
@Time : 2026/6/27 11:56
@脚本说明 : 子域名扫描
"""
import threading
import warnings
from pathlib import Path

import dns.resolver

from tools.SchedulerTools import run_batch
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


#扫描子域名
def scan_subdomain(domain, subdomain):
    full_domain = f"{subdomain}.{domain}"
    try:
        dns_result = get_resolver().resolve(full_domain, "A")
        ips = [record.to_text() for record in dns_result]
        console.print(f"  [success]●[/success] [host]{full_domain}[/host] [dim]→ {', '.join(ips)}[/dim]")
    except:
        pass


#多线程执行
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
    tasks = ((domain, s) for s in names)
    run_batch(tasks, scan_subdomain, threads)
