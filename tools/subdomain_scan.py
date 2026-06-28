#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""  
@Project : python
@File : subdomain_scan.py
@Author : moresuo
@Time : 2026/6/27 11:56  
@脚本说明 : 子域名扫描
"""
import dns.resolver
import concurrent.futures
import warnings
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DIR_PATH = BASE_DIR / "libs" / "subdomain.txt"

warnings.filterwarnings("ignore")

#扫描子域名
def scan_subdomain(domain,subdomain):
    full_domain=f"{subdomain}.{domain}"
    result=set()
    try:
        #创建dns解析器
        dns_resolver=dns.resolver.Resolver()
        #设置dns服务器解析地址
        dns_resolver.nameservers=["223.5.5.5","180.76.76.76"]
        #设置dns查询超时时间
        dns_resolver.timeout=3
        #获取dns解析A结果
        dns_result=dns_resolver.resolve(full_domain,"A")
        #输出解析结果
        ips=[record.to_text() for record in dns_result]
        print(f"[+] {full_domain}存活，IP：{ips}")
    except:
        pass

#多线程执行
def scan_subdomain_run(domain,threads):
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        with open(file=DIR_PATH,mode="r",encoding="utf-8") as subdomains:
            for subdomain in subdomains:
                executor.submit(scan_subdomain,domain,subdomain.strip())

