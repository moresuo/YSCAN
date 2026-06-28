#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : ip_scan.py
@Author : moresuo
@Time : 2026/6/27 11:11
@脚本说明 : 内网ip探测（Windows/Linux/macOS 通用）
"""
import platform
import subprocess

from tools.SchedulerTools import run_batch
from tools.color import console


def _ping_alive(ip):
    """跨平台 ping 检测，返回 True/False。

    使用 subprocess.run 列表参数 + shell=False，
    完全杜绝命令注入风险。
    """
    system = platform.system().lower()

    if system == 'windows':
        cmd = ["ping", "-n", "1", "-w", "100", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=2,
            shell=False,
        )
        if system == 'windows':
            return "TTL" in result.stdout
        else:
            return result.returncode == 0
    except Exception:
        return False


#内网使用ping检测存活
def scan_ip(ip):
    if _ping_alive(ip):
        console.print(f"  [success]●[/success] [host]{ip}[/host] [dim]存活[/dim]")


#多线程扫描
def scan_ip_run(hosts, threads):
    from rich.panel import Panel
    hosts_list = list(hosts)
    console.print(Panel.fit(
        f"[accent]探测主机数[/accent]  [count]{len(hosts_list)}[/count]",
        title="[header]ICMP 存活探测[/header]",
        border_style="dim",
    ))
    tasks = ((ip,) for ip in hosts_list)
    run_batch(tasks, scan_ip, threads)
