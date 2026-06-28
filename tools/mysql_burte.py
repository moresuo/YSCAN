#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : mysql_burte.py
@Author : moresuo
@Time : 2026/6/26 15:29
@脚本说明 : mysql弱密码爆破
"""
import threading

import pymysql

from tools.ProgressTools import BurteProgress
from tools.SchedulerTools import run_batch
from tools.WordlistTools import load_lines
from tools.color import console

mysql_found_hosts = set()
mysql_found_lock = threading.Lock()


#连接MySQL
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
            cursor.close()
        conn.close()
    except:
        pass


#线程池执行任务
def scan_mysql_run_file(hosts, userpath, pwdpath, port, threads):
    mysql_found_hosts.clear()
    hosts_list = list(hosts)
    users = load_lines(userpath)
    passwords = load_lines(pwdpath)
    tasks_count = len(hosts_list) * len(users) * len(passwords)
    tasks = ((ip, port, user, pwd) for ip in hosts_list for user in users for pwd in passwords)
    with BurteProgress(tasks_count, "MySQL弱口令") as progress:
        run_batch(tasks, scan_mysql, threads, on_progress=progress.update)


#指定用户名
def scan_mysql_run(hosts, username, password, port, threads):
    mysql_found_hosts.clear()
    hosts_list = list(hosts)
    passwords = load_lines(password)
    tasks_count = len(hosts_list) * len(passwords)
    tasks = ((ip, port, username, pwd) for ip in hosts_list for pwd in passwords)
    with BurteProgress(tasks_count, "MySQL弱口令") as progress:
        run_batch(tasks, scan_mysql, threads, on_progress=progress.update)
