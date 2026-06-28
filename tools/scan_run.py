#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : scan_run.py
@Author : moresuo
@Time : 2026/6/28
@脚本说明 : 一键式快速扫描
"""

from tools.mysql_burte import scan_mysql_run
from tools.redis_burte import scan_redis_run
from tools.ssh_burte import scan_ssh_run
from tools.tcp_port_scan import get_top_ports, scan_tcp_port_collect_hosts

SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
}


#一键式快速扫描：Top端口 + 常见服务弱口令，不做目录和子域名爆破
def scan_run(hosts, threads=500, password="", username="root", top=100):
    top_ports = get_top_ports(top)

    print(f"[*] 一键扫描启动，Top端口数量：{len(top_ports)}")
    print("[*] 不执行目录扫描和子域名爆破")

    #先把所有主机的Top端口一次性并行扫描，避免逐主机串行
    hosts_list = list(hosts)
    open_map = scan_tcp_port_collect_hosts(hosts_list, top_ports, threads)

    host_count = len(hosts_list)
    open_count = 0

    for host in hosts_list:
        open_ports = open_map.get(host, [])
        print(f"\n[*] 扫描主机：{host}")
        if not open_ports:
            print(f"[-] {host} 未发现Top端口开放")
            continue

        open_count += len(open_ports)
        print(f"[+] {host} 开放端口：")
        for port in open_ports:
            service = SERVICE_MAP.get(port, "unknown")
            print(f"    {port}/tcp {service}")

        if 22 in open_ports:
            print(f"[*] {host}:22 触发SSH弱口令检测")
            scan_ssh_run([host], username, password, 22, threads)
        if 3306 in open_ports:
            print(f"[*] {host}:3306 触发MySQL弱口令检测")
            scan_mysql_run([host], username, password, 3306, threads)
        if 6379 in open_ports:
            print(f"[*] {host}:6379 触发Redis弱口令检测")
            scan_redis_run([host], 6379, password, None, None, 8888, threads)

    print("\n[*] 一键扫描完成")
    print(f"[*] 扫描主机数：{host_count}")
    print(f"[*] 开放端口数：{open_count}")
