#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : scan_run.py
@Author : moresuo
@Time : 2026/6/28
@脚本说明 : 一键式快速扫描

流程：ARP 存活探测 → 端口扫描 → 弱口令检测 → 汇总报告。
ARP 为二层协议仅同网段有效，跨网段时自动回退全部端口扫描。
"""
import ipaddress
import sys

from alive_progress import alive_bar
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from tools.color import console
from tools.ip_scan import resolve_iface, _arp_sweep
from tools.mysql_burte import scan_mysql_run
from tools.redis_burte import scan_redis_run
from tools.ssh_burte import scan_ssh_run
from tools.tcp_port_scan import get_top_ports, scan_tcp_port_collect_hosts, PORT_SERVICE

def scan_run(hosts, threads=500, password="", username="root", top=100):
    top_ports = get_top_ports(top)
    hosts_list = list(hosts)
    host_count = len(hosts_list)
    total_tasks = host_count * len(top_ports)

    # ── 启动面板 ──
    console.print(Panel.fit(
        f"[accent]主机数[/accent]    [count]{host_count}[/count]\n"
        f"[accent]端口数[/accent]    [count]{len(top_ports)}[/count] (Top)\n"
        f"[accent]总任务[/accent]    [count]{total_tasks:,}[/count]",
        title="[header]YSCAN 一键扫描[/header]",
        subtitle="[dim]不执行目录扫描和子域名爆破[/dim]",
        border_style="dim",
    ))

    # ── ARP 存活探测（同网段二层发现，主机禁 ICMP 仍可发现）──
    dev = resolve_iface(None, hosts_list[0]) if hosts_list else None
    if dev:
        console.print()
        alive = _arp_sweep(hosts_list, dev, timeout=2, batch=256)
        alive_hosts = [ip for ip, _ in alive]
        # 按 IP 排序输出
        for ip, mac in sorted(alive, key=lambda x: ipaddress.ip_address(x[0])):
            console.print(f"  [success]●[/success] [host]{ip}[/host] [dim]| {mac} 存活[/dim]")
        console.print(f"[info]ARP 存活 {len(alive_hosts)} / {host_count}[/info]")
    else:
        # 无同网段网卡（跨网段 / 纯外网），ARP 不可达，跳过预检全部扫描
        alive_hosts = hosts_list
        console.print("[warn]⚠ 无同网段网卡，跳过 ARP 预检，直接端口扫描[/warn]")

    # ── 空存活退出 ──
    if not alive_hosts:
        console.print()
        console.print(Panel.fit(
            f"[warn]未发现任何存活主机[/warn]\n"
            f"[dim]扫描主机 {host_count} 台，存活 0 台[/dim]",
            border_style="warn",
        ))
        return

    # ── 端口扫描（仅扫 ARP 存活主机）──
    alive_count = len(alive_hosts)
    scan_tasks = alive_count * len(top_ports)
    announced = {}
    _tracked = [0]

    def on_open(host, port):
        if host not in announced:
            announced[host] = []
            console.print(f"\n[host]▸ {host}[/host]")
        announced[host].append(port)
        svc = PORT_SERVICE.get(port, "?")
        console.print(f"  [port]{port:>5}/tcp[/port]  [service]{svc}[/service]")

    def on_progress(completed, _total):
        delta = completed - _tracked[0]
        if delta > 0:
            _bar(delta)
            _tracked[0] = completed

    with alive_bar(
        scan_tasks,
        title="端口扫描",
        bar="smooth",
        spinner="dots_waves2",
        enrich_print=False,
        file=sys.__stderr__,
        receipt=True,
        receipt_text="端口扫描完成",
    ) as _bar:
        open_map = scan_tcp_port_collect_hosts(
            alive_hosts, top_ports, threads,
            on_open=on_open, on_progress=on_progress,
        )
        remaining = scan_tasks - _tracked[0]
        if remaining > 0:
            _bar(remaining)

    # ── 空端口提示 ──
    if not announced:
        console.print()
        console.print(Panel.fit(
            f"[warn]未发现开放端口[/warn]\n"
            f"[dim]ARP 存活 {alive_count} 台，开放端口 0 台[/dim]",
            border_style="warn",
        ))
        return

    # ── 弱口令检测 ──
    console.print()
    console.print(Rule("[header]弱口令检测[/header]", style="dim"))
    total_open = 0

    for alive_host in sorted(announced):
        open_ports = open_map.get(alive_host, [])
        total_open += len(open_ports)

        if not (set(open_ports) & {22, 3306, 6379}):
            continue

        console.print(f"\n[host]{alive_host}[/host]")

        if 22 in open_ports:
            console.print("  [info]→ SSH 弱口令检测[/info]")
            scan_ssh_run([alive_host], username, password, 22, threads)
        if 3306 in open_ports:
            console.print("  [info]→ MySQL 弱口令检测[/info]")
            scan_mysql_run([alive_host], username, password, 3306, threads)
        if 6379 in open_ports:
            console.print("  [info]→ Redis 弱口令检测[/info]")
            scan_redis_run([alive_host], 6379, password, None, None, 8888, threads)

    # ── 汇总表格 ──
    console.print()
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column(style="accent", justify="right")
    table.add_row("扫描主机", str(host_count))
    table.add_row("ARP 存活", f"[success]{alive_count}[/success]")
    table.add_row("开放主机", f"[highlight]{len(announced)}[/highlight]")
    table.add_row("开放端口", f"[highlight]{total_open}[/highlight]")
    console.print(Panel(table, title="[header]扫描汇总[/header]", border_style="dim"))
