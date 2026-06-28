#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : tcp_port_scan.py
@Author : moresuo
@Time : 2026/6/27 23:23
@脚本说明 :
"""
import asyncio

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
    79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
    465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
    646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
    1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
    2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
    9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]


def get_top_ports(count=100):
    return TOP_100_PORTS[:count]


#异步端口扫描，开放返回端口，否则返回 None
async def scan_tcp_port(ip, port, timeout=1):
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        return port
    except:
        return None
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass


async def _scan_port_worker(queue, host, open_ports, timeout):
    while True:
        try:
            port = queue.get_nowait()
        except asyncio.QueueEmpty:
            return
        try:
            result = await scan_tcp_port(host, port, timeout)
            if result:
                open_ports.append(result)
        finally:
            queue.task_done()


async def scan_tcp_port_async_collect(host, ports, threads, timeout=1):
    queue = asyncio.Queue()
    open_ports = []

    for port in ports:
        await queue.put(port)

    worker_count = min(max(threads, 1), queue.qsize() or 1)
    workers = [asyncio.create_task(_scan_port_worker(queue, host, open_ports, timeout)) for _ in range(worker_count)]
    await queue.join()
    for worker_task in workers:
        worker_task.cancel()
    await asyncio.gather(*workers, return_exceptions=True)
    return sorted(open_ports)


#多主机并行端口扫描：把所有 (host, port) 放入统一队列，按 host 归集开放端口
async def scan_tcp_port_async_collect_hosts(hosts_ports, threads, timeout=1):
    queue = asyncio.Queue()
    open_map = {}

    for host, port in hosts_ports:
        await queue.put((host, port))

    async def worker():
        while True:
            try:
                host, port = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                result = await scan_tcp_port(host, port, timeout)
                if result:
                    open_map.setdefault(host, []).append(result)
            finally:
                queue.task_done()

    worker_count = min(max(threads, 1), queue.qsize() or 1)
    workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
    await queue.join()
    for worker_task in workers:
        worker_task.cancel()
    await asyncio.gather(*workers, return_exceptions=True)
    return {host: sorted(ports) for host, ports in open_map.items()}


#收集单主机开放端口
def scan_tcp_port_collect(host, ports, threads, timeout=1):
    return asyncio.run(scan_tcp_port_async_collect(host, ports, threads, timeout))


#收集多主机开放端口，返回 {host: [open_ports]}
def scan_tcp_port_collect_hosts(hosts, ports, threads, timeout=1):
    hosts_ports = ((host, port) for host in hosts for port in ports)
    return asyncio.run(scan_tcp_port_async_collect_hosts(hosts_ports, threads, timeout))


#端口扫描入口，保持原 CLI 打印行为
def scan_tcp_port_run(host, ports, threads):
    open_ports = scan_tcp_port_collect(host, ports, threads)
    for port in open_ports:
        print(f"[+] {host}:{port} 端口开放")
