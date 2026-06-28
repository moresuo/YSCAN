#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""  
@Project : python
@File : dir_scan.py
@Author : moresuo
@Time : 2026/6/27 11:24  
@脚本说明 : 目录扫描
"""
import concurrent.futures
import requests
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DIR_PATH = BASE_DIR / "libs" / "dirpath.txt"
#目录扫描
def scan_dir(url):
    headers={
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    try:
        response=requests.get(url,headers=headers,verify=False,timeout=3)
        if response.status_code in [200,301,302,401,403]:
            print(f"[+] 存在目录[{response.status_code}]：{url}")
    except:
        pass

#多线程执行
def scan_dir_run(base_url,threads):
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        with open(file=DIR_PATH,mode="r",encoding="utf-8") as dirpath:
            for path in dirpath:
                path=path.strip()
                #如果是空行直接跳过
                if not path:
                    continue
                executor.submit(scan_dir,base_url+path.strip())
