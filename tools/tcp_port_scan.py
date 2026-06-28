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


#异步端口扫描
async def scan_tcp_port(ip, port, timeout=1):
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        print(f"[+] {ip}:{port} 端口开放")
    except:
        pass
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass


async def scan_tcp_port_async_run(host, ports, threads):
    semaphore = asyncio.Semaphore(threads)

    async def scan_with_limit(port):
        async with semaphore:
            await scan_tcp_port(host, port)

    tasks = [asyncio.create_task(scan_with_limit(port)) for port in ports]
    for task in asyncio.as_completed(tasks):
        await task


#端口扫描入口
def scan_tcp_port_run(host, ports, threads):
    asyncio.run(scan_tcp_port_async_run(host, ports, threads))
