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

# 常见端口 → 服务名映射
PORT_SERVICE = {
    7: "echo", 9: "discard", 13: "daytime", 21: "FTP", 22: "SSH",
    23: "Telnet", 25: "SMTP", 26: "RSFTP", 37: "time", 53: "DNS",
    79: "finger", 80: "HTTP", 81: "TorPark",
    88: "Kerberos", 106: "pop3pw", 110: "POP3", 111: "rpcbind",
    113: "ident", 119: "NNTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 144: "News",
    179: "BGP", 199: "smux", 389: "LDAP",
    427: "SLP", 443: "HTTPS", 444: "SNPP", 445: "SMB",
    465: "SMTPS", 513: "rlogin", 514: "shell", 515: "lpd",
    543: "klogin", 544: "kshell", 548: "AFP", 554: "RTSP",
    587: "SMTP", 631: "IPP",
    646: "LDP", 873: "rsync", 990: "FTPS", 993: "IMAPS",
    995: "POP3S", 1025: "NFS-or-IIS", 1026: "DCOM",
    1027: "IPv6", 1028: "DCOM", 1029: "DCOM",
    1110: "nfsd-status", 1433: "MSSQL", 1720: "H.323",
    1723: "PPTP", 1755: "MMS", 1900: "UPnP",
    2000: "Cisco-SCCP", 2001: "CAPTAN", 2049: "NFS",
    2121: "FTP-proxy",
    2717: "PN-REQ", 3000: "Grafana", 3128: "Squid",
    3306: "MySQL", 3389: "RDP",
    3986: "MAP-ws", 4899: "Radmin", 5000: "UPnP",
    5009: "Airport", 5051: "ITA-agent", 5060: "SIP",
    5101: "ESIntf", 5190: "AIM", 5357: "WSDAPI",
    5432: "PostgreSQL", 5631: "pcAnywhere",
    5666: "Nagios", 5800: "VNC-http", 5900: "VNC",
    6000: "X11", 6001: "X11",
    6646: "IRC-SSL", 7070: "RealServer",
    8000: "HTTP-Alt", 8008: "HTTP-Alt",
    8009: "AJP", 8080: "HTTP-Proxy", 8081: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9100: "JetDirect", 9999: "Abyss",
    10000: "Webmin", 32768: "filenet",
    49152: "WinRPC", 49153: "WinRPC", 49154: "WinRPC",
    49155: "WinRPC", 49156: "WinRPC", 49157: "WinRPC",
}

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
    79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
    465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
    646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
    1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
    2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
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


async def scan_tcp_port_async_collect(host, ports, threads, timeout=1, on_progress=None):
    queue = asyncio.Queue()
    open_ports = []

    for port in ports:
        await queue.put(port)

    total = queue.qsize()
    completed = [0]
    p_lock = asyncio.Lock()
    last_reported = [0]

    async def worker():
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
                async with p_lock:
                    completed[0] += 1
                    if on_progress and (completed[0] - last_reported[0] >= max(total // 100, 1) or completed[0] == total):
                        last_reported[0] = completed[0]
                        on_progress(completed[0], total)

    worker_count = min(max(threads, 1), queue.qsize() or 1)
    workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
    await queue.join()
    for worker_task in workers:
        worker_task.cancel()
    await asyncio.gather(*workers, return_exceptions=True)
    return sorted(open_ports)


#多主机并行端口扫描：把所有 (host, port) 放入统一队列，按 host 归集开放端口
#on_open(host, port) 回调在发现开放端口时立即调用，用于实时输出
#on_progress(completed, total) 每完成 1% 回调一次，用于进度显示
async def scan_tcp_port_async_collect_hosts(hosts_ports, threads, timeout=1, on_open=None, on_progress=None):
    queue = asyncio.Queue()
    open_map = {}

    for host, port in hosts_ports:
        await queue.put((host, port))

    total = queue.qsize()
    completed = [0]
    p_lock = asyncio.Lock()
    last_reported = [0]

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
                    if on_open:
                        on_open(host, result)
            finally:
                queue.task_done()
                async with p_lock:
                    completed[0] += 1
                    if on_progress and (completed[0] - last_reported[0] >= max(total // 100, 1) or completed[0] == total):
                        last_reported[0] = completed[0]
                        on_progress(completed[0], total)

    worker_count = min(max(threads, 1), queue.qsize() or 1)
    workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
    await queue.join()
    for worker_task in workers:
        worker_task.cancel()
    await asyncio.gather(*workers, return_exceptions=True)
    return {host: sorted(ports) for host, ports in open_map.items()}


#收集单主机开放端口
def scan_tcp_port_collect(host, ports, threads, timeout=1, on_progress=None):
    return asyncio.run(scan_tcp_port_async_collect(host, ports, threads, timeout, on_progress))


#收集多主机开放端口，返回 {host: [open_ports]}
def scan_tcp_port_collect_hosts(hosts, ports, threads, timeout=1, on_open=None, on_progress=None):
    hosts_ports = ((host, port) for host in hosts for port in ports)
    return asyncio.run(scan_tcp_port_async_collect_hosts(hosts_ports, threads, timeout, on_open, on_progress))


#端口扫描入口
def scan_tcp_port_run(host, ports, threads):
    from tools.color import console
    ports_list = list(ports)
    console.print(f"[host]{host}[/host] [dim]扫描 {len(ports_list)} 端口...[/dim]")
    open_ports = scan_tcp_port_collect(host, ports_list, threads)
    if not open_ports:
        console.print("  [dim]未发现开放端口[/dim]")
    for port in open_ports:
        svc = PORT_SERVICE.get(port, "?")
        console.print(f"  [success]●[/success] [port]{port:>5}/tcp[/port]  [service]{svc}[/service]")
