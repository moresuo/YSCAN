#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""  
@Project : python
@File : ip_scan.py
@Author : moresuo
@Time : 2026/6/27 11:11  
@脚本说明 : 内网ip探测
"""
import concurrent.futures
import subprocess


#内网使用ping检测存活
def scan_ip(ip):
    try:
        #防止命令注入
        result = subprocess.run(
            ["ping", "-n", "1", ip, "-w", "100"],
            capture_output=True,
            text=True,
            timeout=2,
            shell=False
        )
        if "TTL" in result.stdout:
            print(f"[+] {ip} 存活")
    except:
        pass

#多线程扫描
def scan_ip_run(hosts,threads):
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for ip in hosts:
            executor.submit(scan_ip, ip)




