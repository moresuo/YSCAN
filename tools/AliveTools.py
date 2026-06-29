#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : AliveTools.py
@Author : moresuo
@Time : 2026/6/29
@脚本说明 : 弱口令爆破前的目标存活检测
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from tools.color import console


#检测目标服务端口是否可连接，可连接视为存活
def is_service_alive(host, port, timeout=2):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


#批量检测目标服务存活，不存活的目标跳过后续爆破
def filter_alive_hosts(hosts, port, threads=100, timeout=2, service_name="服务"):
    hosts_list = list(dict.fromkeys(hosts))
    if not hosts_list:
        return []

    alive_hosts = []
    worker_count = min(max(int(threads), 1), len(hosts_list), 100)

    console.print(f"[info]{service_name} 存活检测[/info]")
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(is_service_alive, host, port, timeout): host
            for host in hosts_list
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                if future.result():
                    alive_hosts.append(host)
                else:
                    console.print(f"  [fail]x {host}:{port} 不存活，跳过爆破[/fail]")
            except Exception:
                console.print(f"  [fail]x {host}:{port} 不存活，跳过爆破[/fail]")

    return alive_hosts
