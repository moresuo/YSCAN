#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : ip_scan.py
@Author : moresuo
@Time : 2026/6/27 11:11
@脚本说明 : 内网 ARP 存活探测（scapy L2，主机禁 ICMP 仍可探测）

ARP 为二层协议，仅在同一广播域（同网段）内有效。发包时必须从与目标
同网段的网卡发出，因此探测前会按目标 IP 自动匹配本机同网段网卡。
"""
import ipaddress
import platform
import subprocess
import warnings

from scapy.interfaces import IFACES
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp

from tools.color import console

warnings.filterwarnings("ignore")

# 网卡列表懒加载缓存，避免每次探测重复 reload 开销
_ifaces_loaded = False


def _load_ifaces():
    """加载并缓存本机网卡列表。"""
    global _ifaces_loaded
    if not _ifaces_loaded:
        IFACES.reload()
        _ifaces_loaded = True
    return list(IFACES.values())


def pick_iface(target_ip):
    """根据目标 IP 网段自动选择同网段网卡（/24 前缀匹配）。

    ARP 不可跨路由，必须从与目标同网段的网卡发出才能收到响应。
    返回匹配的 NetworkInterface，无匹配返回 None。
    """
    try:
        prefix = ".".join(target_ip.split(".")[:3])
    except Exception:
        return None
    for dev in _load_ifaces():
        ip = getattr(dev, "ip", "") or ""
        if not ip or ip.startswith("127."):
            continue
        if ".".join(ip.split(".")[:3]) == prefix:
            return dev
    return None


def resolve_iface(iface, sample_ip):
    """解析网卡：iface 为 None 时按目标网段自动选择；否则按 名称/描述/IP 匹配。"""
    if iface is None:
        return pick_iface(sample_ip)
    for dev in _load_ifaces():
        if iface in (dev.name, dev.description, getattr(dev, "ip", "")):
            return dev
    return None


def _arp_sweep(ip_list, iface, timeout=2, batch=256):
    """srp 批量发送 ARP 广播，返回 [(ip, mac)] 列表。

    分批发送避免大网段一次性发包过多导致丢包或内存峰值。
    """
    results = []
    for i in range(0, len(ip_list), batch):
        chunk = ip_list[i:i + batch]
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=chunk),
                iface=iface,
                timeout=timeout,
                verbose=0,
            )
            for _s, r in ans:
                results.append((r.psrc, r.hwsrc))
        except Exception:
            # 宽泛吞异常，保持与项目其他扫描模块一致的容错风格
            pass
    return results


def _icmp_alive(ip):
    """跨平台 ICMP ping 兜底（跨网段场景 ARP 不可达时使用）。

    使用 subprocess.run 列表参数 + shell=False，杜绝命令注入。
    """
    system = platform.system().lower()
    if system == "windows":
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
        if system == "windows":
            return "TTL" in result.stdout
        return result.returncode == 0
    except Exception:
        return False


# 单主机 ARP 探测并打印存活
def scan_ip(ip, iface=None):
    dev = resolve_iface(iface, ip)
    if dev is None:
        console.print(f"  [fail]✗ {ip} 无可用网卡，跳过[/fail]")
        return
    res = _arp_sweep([ip], dev, timeout=1)
    if res:
        ip_, mac = res[0]
        console.print(f"  [success]●[/success] [host]{ip_}[/host] [dim]| {mac} 存活[/dim]")


# 存活检测：ARP 优先（同网段，禁 ICMP 主机仍可探测），跨网段回退 ICMP
# 被 tcp_port_scan 端口扫描前预检复用
def _ping_alive(ip, iface=None):
    dev = resolve_iface(iface, ip)
    if dev is not None:
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=dev,
                timeout=1,
                verbose=0,
            )
            if ans:
                return True
        except Exception:
            pass
    return _icmp_alive(ip)


# 多主机 ARP 批量扫描入口
def scan_ip_run(hosts, threads, iface=None):
    from rich.panel import Panel

    hosts_list = list(hosts)
    if not hosts_list:
        return

    dev = resolve_iface(iface, hosts_list[0])
    if dev is None:
        console.print(
            f"[fail]✗ 无法确定探测网卡[/fail] "
            f"[dim]（目标 {hosts_list[0]} 无同网段网卡，请用 -I/--iface 指定网卡名称/描述）[/dim]"
        )
        return

    console.print(Panel.fit(
        f"[accent]探测主机数[/accent]  [count]{len(hosts_list)}[/count]\n"
        f"[accent]网卡[/accent]        [highlight]{dev.description}[/highlight] [dim]({dev.ip})[/dim]",
        title="[header]ARP 存活探测[/header]",
        border_style="dim",
    ))

    # threads 控制单批发包上限，上限 512 避免一次性发包过多
    batch = min(512, max(64, threads))
    alive = _arp_sweep(hosts_list, dev, timeout=2, batch=batch)

    for ip, mac in sorted(alive, key=lambda x: ipaddress.ip_address(x[0])):
        console.print(f"  [success]●[/success] [host]{ip}[/host] [dim]| {mac} 存活[/dim]")

    console.print(f"[info]存活 {len(alive)} / {len(hosts_list)}[/info]")
