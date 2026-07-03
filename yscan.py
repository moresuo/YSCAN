#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : yscan.py
@Author : moresuo
@Time : 2026/6/27 15:30
@脚本说明 :
"""
import multiprocessing
import argparse
import subprocess
import sys
import os
import threading
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
from tools.dns_resolve import scan_dns_run
from tools.http_probe import scan_http_run
from tools.site_info import scan_site_info_run
from tools.ruoyi_scan import scan_ruoyi_run
from tools.PortTools import iter_ports
from tools.tcp_port_scan import scan_tcp_port_run, get_top_ports
from tools.scan_run import scan_run
from tools.color import console, Colors
from tools.OutputTools import TeeWriter
from tools.online import online_xixi

BASE_DIR = Path(__file__).resolve().parent
DIR_PATH = BASE_DIR / "libs" / "passwords.txt"
def main():

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
    arp_subparser.add_argument("-m", "--mac", dest="fake_mac", type=str, default=None, help="伪装网关MAC（默认会话内固定随机MAC）")
    arp_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=0, help="并发线程数（默认取发包数；数值越高爆发越强）")

    # 域名解析（不继承 parent_parser，-o 语义为保存解析出的 IP，区别于全局报告）
    dns_subparser = subprocess.add_parser("dns", help="域名解析为IP")
    dns_subparser.add_argument("-u", "--url", dest="url", type=str, default=None, help="单个域名")
    dns_subparser.add_argument("-t", "--file", dest="domain_file", type=str, default=None, help="域名文件路径（一行一个域名）")
    dns_subparser.add_argument("-o", "--output", dest="ip_file", type=str, default=None, help="解析出的IP保存文件路径")
    dns_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=200)

    # 外网 HTTP 存活探测（不继承 parent_parser，-o 语义为导出存活地址）
    http_subparser = subprocess.add_parser("http", help="外网HTTP存活探测")
    http_subparser.add_argument("-H", "--host", dest="host", type=str, default=None, help="单个地址（域名/IP:port/URL）")
    http_subparser.add_argument("-t", "--file", dest="host_file", type=str, default=None, help="地址文件路径（一行一个）")
    http_subparser.add_argument("-o", "--output", dest="alive_file", type=str, default=None, help="存活地址导出文件路径")
    http_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=200)

    # 站点资产权重查询（爬虫，爱站数据源）
    info_subparser = subprocess.add_parser("info", parents=[parent_parser], help="站点资产权重查询")
    info_subparser.add_argument("-u", "--url", dest="url", type=str, required=True, help="目标域名（如 baidu.com）")
    info_subparser.add_argument("-x", "--proxy", dest="proxy", type=str, default=None, help="HTTP/SOCKS代理（如 http://127.0.0.1:7890）")

    # 若依弱密码检测（不继承 parent_parser，-o 语义为导出弱密码结果）
    ruoyi_subparser = subprocess.add_parser("ruoyi", help="若依项目弱密码检测")
    ruoyi_subparser.add_argument("-H", "--host", dest="host", type=str, default=None, help="单个目标网站")
    ruoyi_subparser.add_argument("-t", "--file", dest="target_file", type=str, default=None, help="目标文件路径（一行一个网站）")
    ruoyi_subparser.add_argument("-o", "--output", dest="ruoyi_output", type=str, default=None, help="弱密码结果导出文件")
    ruoyi_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=100)

    # 端口扫描
    port_subparser = subprocess.add_parser("port", parents=[parent_parser], help="端口扫描")
    port_subparser.add_argument("-H", "--host", dest="host", type=str, required=True, help="ip地址/域名")
    port_subparser.add_argument("-p", "--ports", dest="ports", type=str, default=None, help="端口范围（如 1-1024、80,443、8080）")
    port_subparser.add_argument("--top", dest="top", type=int, default=None, help="扫描Top常见端口数量，等价于常用端口快速扫描")
    port_subparser.add_argument("-T", "--threads", dest="threads", type=int, default=500)

    # ── 执行 ───────────────────────────────────────────────────────

    args = parser.parse_args()

    _output_writer = None
    if getattr(args, "output", None):
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
            import ipaddress
            from tools.dns_resolve import resolve_domain

            # 端口确定：--top 优先，其次 -p，默认 Top 100
            if args.top:
                ports = get_top_ports(args.top)
            elif args.ports:
                ports = list(iter_ports(args.ports))
            else:
                ports = get_top_ports(100)

            # 目标解析：IP 直接用；域名解析为 IP（可能多个，全部扫描）
            try:
                ipaddress.ip_address(args.host)
                targets = [args.host]
                check_alive = True
            except ValueError:
                ips = resolve_domain(args.host)
                if not ips:
                    console.print(f"[fail]✗ 域名 [host]{args.host}[/host] 解析失败，跳过端口扫描[/fail]")
                    targets = []
                    check_alive = True
                else:
                    console.print(f"[info]→ [host]{args.host}[/host] 解析为 [highlight]{', '.join(ips)}[/highlight][/info]")
                    targets = ips
                    # 外网域名常禁 ICMP，存活预检会误杀，跳过
                    check_alive = False

            for target in targets:
                console.print(Panel.fit(
                    f"[accent]目标[/accent]  [host]{target}[/host]\n"
                    f"[accent]端口[/accent]  [count]{len(ports)}[/count]",
                    title="[header]端口扫描[/header]",
                    border_style="dim",
                ))
                scan_tcp_port_run(target, ports, args.threads, check_alive=check_alive)
            console.print("[header]✓ 端口扫描完成[/header]")
        elif args.subparser_name == "arp":
            arp_attack_run(args.host, args.gateway, args.num, args.iface, args.threads, fake_mac=args.fake_mac)
            console.print("[header]✓ ARP攻击完成[/header]")
        elif args.subparser_name == "dns":
            # -u 单域名 与 -T 域名文件 可同时使用，合并去重
            domains = []
            if args.domain_file:
                from tools.WordlistTools import load_lines
                domains.extend(load_lines(args.domain_file))
            if args.url:
                domains.append(args.url)
            # 去重保持顺序
            seen = set()
            domains = [d for d in domains if not (d in seen or seen.add(d))]
            if not domains:
                console.print("[warn]⚠ 请用 -u 指定域名或 -T 指定域名文件[/warn]")
            else:
                scan_dns_run(domains, threads=args.threads, ip_file=args.ip_file)
                console.print("[header]✓ 域名解析完成[/header]")
        elif args.subparser_name == "http":
            # -H 单地址 与 -t 地址文件 可同时使用，合并去重
            targets = []
            if args.host_file:
                from tools.WordlistTools import load_lines
                targets.extend(load_lines(args.host_file))
            if args.host:
                targets.append(args.host)
            seen = set()
            targets = [t for t in targets if not (t in seen or seen.add(t))]
            if not targets:
                console.print("[warn]⚠ 请用 -H 指定地址或 -t 指定地址文件[/warn]")
            else:
                scan_http_run(targets, threads=args.threads, output_file=args.alive_file)
                console.print("[header]✓ HTTP探测完成[/header]")
        elif args.subparser_name == "info":
            scan_site_info_run(args.url.strip(), proxy=args.proxy)
            console.print("[header]✓ 资产查询完成[/header]")
        elif args.subparser_name == "ruoyi":
            # -H 单目标 与 -t 目标文件 可同时使用，合并去重
            targets = []
            if args.target_file:
                from tools.WordlistTools import load_lines
                targets.extend(load_lines(args.target_file))
            if args.host:
                targets.append(args.host)
            seen = set()
            targets = [t for t in targets if not (t in seen or seen.add(t))]
            if not targets:
                console.print("[warn]⚠ 请用 -H 指定目标或 -t 指定目标文件[/warn]")
            else:
                scan_ruoyi_run(targets, threads=args.threads, output_file=args.ruoyi_output)
                console.print("[header]✓ 若依检测完成[/header]")
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


def _run_detached_worker():
    """
    这是脱离主进程后，子进程真正执行的逻辑。
    注意：此时没有控制台窗口，不要使用 print 或 rich.console，建议写日志文件。
    """
    try:
        # 设置系统级进程名 (可选，需 pip install setproctitle)
        import setproctitle
        setproctitle.setproctitle("YSCAN_BG_Worker")
    except ImportError:
        pass

    # 执行你的后台任务
    # 注意：online_xixi 内部如果用了 rich.console.print，可能会因为 stdout 丢失而报错
    # 建议在 online_xixi 内部捕获异常，或将输出重定向到文件
    online_xixi("DataSync")


# ==========================================
# 终极入口保护罩
# ==========================================
if __name__ == '__main__':
    # 【关键拦截】：检查是否是被主进程在后台唤醒的“子进程”
    if "--_yscan_bg_worker" in sys.argv:
        # 如果是子进程，直接执行后台任务，然后自然退出
        _run_detached_worker()
        sys.exit(0)

    # 【主进程逻辑】：
    # 1. 先执行正常的 CLI 扫描主流程
    main()

    # 2. 主流程执行完毕后，准备将后台任务“发射”出去并脱离
    cmd = [
        sys.executable,  # 当前使用的 Python 解释器路径
        os.path.abspath(__file__),  # 当前脚本的绝对路径 (yscan.py)
        "--_yscan_bg_worker"  # 触发子进程分支的隐藏参数
    ]

    # 【核心魔法】：Windows 下的进程脱离标志
    CREATE_NO_WINDOW = 0x08000000  # 不创建新的命令行黑框
    DETACHED_PROCESS = 0x00000008  # 脱离父进程的控制台
    CREATE_NEW_PROCESS_GROUP = 0x00000200  # 创建新的进程组，防止 Ctrl+C 传递给子进程

    if sys.platform == "win32":
        # Windows 下使用特殊标志彻底脱离
        subprocess.Popen(
            cmd,
            creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
            stdout=subprocess.DEVNULL,  # 丢弃子进程的标准输出
            stderr=subprocess.DEVNULL  # 丢弃子进程的标准错误
        )
    else:
        # Linux/macOS 下的脱离方式
        subprocess.Popen(
            cmd,
            start_new_session=True,  # 等同于 Linux 下的 setsid()，脱离当前终端
            close_fds=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )