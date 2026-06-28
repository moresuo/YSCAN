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

from tools.SchedulerTools import run_batch
from tools.WordlistTools import load_lines

mysql_found_hosts = set()
mysql_found_lock = threading.Lock()


#连接MySQL
def scan_mysql(ip="127.0.0.1", port=3306, user="root", password="", connect_timeout=5):
    with mysql_found_lock:
        if ip in mysql_found_hosts:
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
            print(f"[+] {ip}:{port}存在弱口令,弱口令:{user}/{password},版本:{cursor.connection.get_server_info()}")
            with mysql_found_lock:
                mysql_found_hosts.add(ip)
            cursor.close()
        conn.close()
    except:
        pass


#线程池执行任务
def scan_mysql_run_file(hosts, userpath, pwdpath, port, threads):
    mysql_found_hosts.clear()
    users = load_lines(userpath)
    passwords = load_lines(pwdpath)
    tasks = ((ip, port, user, pwd) for ip in hosts for user in users for pwd in passwords)
    run_batch(tasks, scan_mysql, threads)


#指定用户名
def scan_mysql_run(hosts, username, password, port, threads):
    mysql_found_hosts.clear()
    passwords = load_lines(password)
    tasks = ((ip, port, username, pwd) for ip in hosts for pwd in passwords)
    run_batch(tasks, scan_mysql, threads)
