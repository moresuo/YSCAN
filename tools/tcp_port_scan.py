#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : tcp_port_scan.py
@Author : moresuo
@Time : 2026/6/27 23:23
@脚本说明 :
"""
import socket

from tools.SchedulerTools import run_batch


#端口扫描
def scan_tcp_port(ip, port):
    tcp_socket = None
    try:
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.settimeout(1)
        result = tcp_socket.connect_ex((ip, port))
        if result == 0:
            print(f"[+] {ip}:{port} 端口开放")
    except:
        pass
    finally:
        if tcp_socket:
            tcp_socket.close()


#线程池调度
def scan_tcp_port_run(host, ports, threads):
    tasks = ((host, port) for port in ports)
    run_batch(tasks, scan_tcp_port, threads)
