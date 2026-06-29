#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : yscan.py
@Author : moresuo
@Time : 2026/6/27 15:30
@脚本说明 :
"""
import argparse
import sys
from pathlib import Path

from rich.panel import Panel
from rich.text import Text

from tools.AddressTools import iter_segments
from tools.mysql_burte import scan_mysql_run, scan_mysql_run_file
from tools.redis_burte import scan_redis_run
from tools.ssh_burte import scan_ssh_run, scan_ssh_run_file
from tools.dir_scan import scan_dir_run
from tools.subdomain_scan import scan_subdomain_run
from tools.ip_scan import scan_ip_run
from tools.arp_attack import arp_attack_run
from tools.PortTools import iter_ports
from tools.tcp_port_scan import scan_tcp_port_run, get_top_ports
from tools.scan_run import scan_run
from tools.color import console, Colors
from tools.OutputTools import TeeWriter

BASE_DIR = Path(__file__).resolve().parent
DIR_PATH = BASE_DIR / "libs" / "passwords.txt"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# ── Banner ────────────────────────────────────────────────────

BANNER_LINES = [
    r" █████ █████  █████████    █████████    █████████   ██████   █████",
    r"▒▒███ ▒▒███  ███▒▒▒▒▒███  ███▒▒▒▒▒███  ███▒▒▒▒▒███ ▒▒██████ ▒▒███ ",
    r" ▒▒███ ███  ▒███    ▒▒▒  ███     ▒▒▒  ▒███    ▒███  ▒███▒███ ▒███ ",
    r"  ▒▒█████   ▒▒█████████ ▒███          ▒███████████  ▒███▒▒███▒███ ",
    r"   ▒▒███     ▒▒▒▒▒▒▒▒███▒███          ▒███▒▒▒▒▒███  ▒███ ▒▒██████ ",
    r"    ▒███     ███    ▒███▒▒███     ███ ▒███    ▒███  ▒███  ▒▒█████ ",
    r"    █████   ▒▒█████████  ▒▒█████████  █████   █████ █████  ▒▒█████",
    r"   ▒▒▒▒▒     ▒▒▒▒▒▒▒▒▒    ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒",
]

def _banner():
    text = Text()
    for i, line in enumerate(BANNER_LINES):
        style = "banner" if i < 2 else "dim"
        text.append(line + "\n", style=style)
    return Panel(text, border_style="dim")


# ── CLI ───────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="YSCAN")
subprocess = parser.add_subparsers(dest="subparser_name", help="请选择需要使用的功能")

parent_parser = argparse.ArgumentParser(add_help=False)
parent_parser.add_argument("-o", "--output", dest="output", type=str, default=None,
                           help="输出文件路径（.txt 或 .html）")

# MySQL
mysql_subparser = subprocess.add_parser("mysql", parents=[parent_parser], help="MySQL弱口令检测")
mysql_subparser.add_argument("-H", "--host", dest="host", type=str, required=True, help="MySQL主机地址/网段/范围")
mysql_subparser.add_argument("-P", "--port", dest="port", type=int, help="MySQL端口", default=3306)
mysql_subparser.add_argument("-U", "--username_file", dest="username_file", type=str, help="MySQL用户名文件路径")
mysql_subparser.add_argument("-u", "--username", dest="username", type=str, help="MySQL用户名", default="root")
mysql_subparser.add_argument("-p", "--password", dest="password", type=str, help="MySQL密码本路径", default=DIR_PATH)
mysql_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=500)

# Redis
redis_subparser = subprocess.add_parser("redis", parents=[parent_parser], help="Redis弱口令检测")
redis_subparser.add_argument("-H", "--host", dest="host", type=str, required=True, help="Redis主机地址/网段/范围")
redis_subparser.add_argument("-P", "--port", dest="port", type=int, help="Redis端口", default=6379)
redis_subparser.add_argument("-p", "--password", dest="password", type=str, help="redis密码本路径", default=DIR_PATH)
redis_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=500)
redis_subparser.add_argument("-pub", "--ssh_pub_key", dest="ssh_pub_key",
                             type=argparse.FileType(mode="r", encoding="utf-8"), help="ssh公钥")
redis_subparser.add_argument("-I", "--ip", dest="ip", type=str, help="反弹shell IP")
redis_subparser.add_argument("-L", "--listen_port", dest="listen_port", type=int, help="反弹shell端口", default=8888)

# SSH
ssh_subparser = subprocess.add_parser("ssh", parents=[parent_parser], help="SSH弱口令检测")
ssh_subparser.add_argument("-H", "--host", dest="host", type=str, required=True, help="ssh主机地址/网段/范围")
ssh_subparser.add_argument("-P", "--port", dest="port", type=int, help="ssh端口", default=22)
ssh_subparser.add_argument("-U", "--username_file", dest="username_file", type=str, help="ssh用户名文件路径")
ssh_subparser.add_argument("-u", "--username", dest="username", type=str, help="ssh用户名", default="root")
ssh_subparser.add_argument("-p", "--password", dest="password", type=str, help="ssh密码本路径", default=DIR_PATH)
ssh_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=500)

# 目录扫描
dir_subparser = subprocess.add_parser("dir", parents=[parent_parser], help="Web目录扫描")
dir_subparser.add_argument("-t", "--url", dest="url", type=str, required=True, help="待扫描的url")
dir_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=500)
dir_subparser.add_argument("--timeout", dest="timeout", type=float, default=3.0, help="单次请求超时秒数（默认3）")

# 子域名
subdomain_subparser = subprocess.add_parser("subdomain", parents=[parent_parser], help="子域名爆破")
subdomain_subparser.add_argument("-t", "--url", dest="url", type=str, required=True, help="待扫描的域名")
subdomain_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=500)

# IP 存活
ip_subparser = subprocess.add_parser("ip", parents=[parent_parser], help="内网IP存活探测")
ip_subparser.add_argument("-H", "--host", dest="host", type=str, required=True, help="ip地址/网段/范围")
ip_subparser.add_argument("-I", "--iface", dest="iface", type=str, default=None, help="指定发包网卡名称/描述（默认按目标网段自动选择）")
ip_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=500)

# 一键扫描
scan_subparser = subprocess.add_parser("scan", parents=[parent_parser], help="一键式快速扫描")
scan_subparser.add_argument("-H", "--host", dest="host", type=str, required=True, help="主机地址/网段/范围")
scan_subparser.add_argument("-u", "--username", dest="username", type=str, help="SSH/MySQL用户名", default="root")
scan_subparser.add_argument("-p", "--password", dest="password", type=str, help="密码本路径", default=DIR_PATH)
scan_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=500)
scan_subparser.add_argument("--top", dest="top", type=int, default=100, help="Top端口数量")

# ARP 欺骗攻击
arp_subparser = subprocess.add_parser("arp", parents=[parent_parser], help="ARP欺骗攻击（伪装网关）")
arp_subparser.add_argument("-H", "--host", dest="host", type=str, required=True, help="靶机IP地址")
arp_subparser.add_argument("-g", "--gateway", dest="gateway", type=str, default=None, help="伪装的网关IP（默认自动推断同网段.1）")
arp_subparser.add_argument("-I", "--iface", dest="iface", type=str, default=None, help="发包网卡名称/描述（默认按靶机网段自动选择）")
arp_subparser.add_argument("-n", "--num", dest="num", type=int, default=10000, help="发送ARP响应包数量（默认10000）")
arp_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=200)

# 端口扫描
port_subparser = subprocess.add_parser("port", parents=[parent_parser], help="端口扫描")
port_subparser.add_argument("-H", "--host", dest="host", type=str, required=True, help="ip地址")
port_subparser.add_argument("-p", "--ports", dest="ports", type=str, default=None, help="端口范围（如 1-1024、80,443、8080）")
port_subparser.add_argument("--top", dest="top", type=int, default=None, help="扫描Top常见端口数量，等价于常用端口快速扫描")
port_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=500)

# ── 执行 ───────────────────────────────────────────────────────

args = parser.parse_args()

_output_writer = None
if args.output:
    _output_writer = TeeWriter(args.output)
    sys.stdout = _output_writer

console.print(_banner())

if not args.subparser_name:
    parser.print_help()
    exit()

try:
    if args.subparser_name == "scan":
        hosts = iter_segments(args.host)
        scan_run(hosts, args.threads, args.password, args.username, args.top)
        console.print("[header]✓ 一键扫描完成[/header]")
    elif args.subparser_name == "mysql":
        hosts = iter_segments(args.host)
        if args.username_file:
            scan_mysql_run_file(hosts, args.username_file, args.password, args.port, args.threads)
        else:
            scan_mysql_run(hosts, args.username, args.password, args.port, args.threads)
        console.print("[header]✓ 漏扫完毕[/header]")
    elif args.subparser_name == "redis":
        hosts = iter_segments(args.host)
        ssh_pub_key = args.ssh_pub_key.read() if args.ssh_pub_key else None
        scan_redis_run(hosts, args.port, args.password, ssh_pub_key, args.ip, args.listen_port, args.threads)
        console.print("[header]✓ 漏扫完毕[/header]")
    elif args.subparser_name == "ssh":
        hosts = iter_segments(args.host)
        if args.username_file:
            scan_ssh_run_file(hosts, args.username_file, args.password, args.port, args.threads)
        else:
            scan_ssh_run(hosts, args.username, args.password, args.port, args.threads)
        console.print("[header]✓ 漏扫完毕[/header]")
    elif args.subparser_name == "dir":
        args.url = args.url.strip()
        if not args.url.endswith("/"):
            args.url += "/"
        scan_dir_run(args.url, args.threads, timeout=args.timeout)
        console.print("[header]✓ 目录扫描完成[/header]")
    elif args.subparser_name == "subdomain":
        scan_subdomain_run(args.url, args.threads)
        console.print("[header]✓ 子域名扫描完成[/header]")
    elif args.subparser_name == "ip":
        hosts = iter_segments(args.host)
        scan_ip_run(hosts, args.threads, args.iface)
        console.print("[header]✓ IP探测完成[/header]")
    elif args.subparser_name == "port":
        if args.top:
            top_ports = get_top_ports(args.top)
            console.print(Panel.fit(
                f"[accent]目标[/accent]  [host]{args.host}[/host]\n"
                f"[accent]端口[/accent]  [count]Top {len(top_ports)}[/count]",
                title="[header]端口扫描[/header]",
                border_style="dim",
            ))
            scan_tcp_port_run(args.host, top_ports, args.threads)
        elif args.ports:
            ports = iter_ports(args.ports)
            scan_tcp_port_run(args.host, ports, args.threads)
        else:
            top_ports = get_top_ports(100)
            console.print(Panel.fit(
                f"[accent]目标[/accent]  [host]{args.host}[/host]\n"
                f"[accent]端口[/accent]  [count]Top {len(top_ports)}[/count]",
                title="[header]端口扫描[/header]",
                border_style="dim",
            ))
            scan_tcp_port_run(args.host, top_ports, args.threads)
        console.print("[header]✓ 端口扫描完成[/header]")
    elif args.subparser_name == "arp":
        arp_attack_run(args.host, args.gateway, args.num, args.iface, args.threads)
        console.print("[header]✓ ARP攻击完成[/header]")
except KeyboardInterrupt:
    console.print("\n[warn]⏎ 用户中断，任务已取消[/warn]")
except Exception as e:
    console.print(f"\n[fail]✗ 运行异常: {e}[/fail]")
finally:
    if _output_writer:
        try:
            _output_writer.close()
            sys.stdout = sys.__stdout__
            console.print(f"[dim]结果已保存至:[/dim] [url]{args.output}[/url]")
        except Exception:
            pass
