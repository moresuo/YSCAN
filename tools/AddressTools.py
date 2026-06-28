#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : AddressTools.py
@Author : moresuo
@Time : 2026/6/27 21:36
@脚本说明 :
"""
import ipaddress


#网段转化生成器
#边生成边扫描，避免大网段一次性展开成大列表
def iter_segments(segment):
    try:
        segment = segment.strip()
        if "/" in segment:
            for ip in ipaddress.ip_network(segment, strict=False).hosts():
                yield str(ip)
        elif "-" in segment:
            #清除多余空格
            ip_start, ip_end = segment.replace(" ", "").split("-")
            start = int(ipaddress.ip_address(ip_start))
            end = int(ipaddress.ip_address(ip_end))
            if start > end:
                raise Exception("请输入正确的IP范围")
            for ip in range(start, end + 1):
                yield str(ipaddress.ip_address(ip))
        else:
            yield segment
    except Exception as e:
        print(e)


#兼容旧接口：需要列表时再显式转换
#新扫描流程优先使用 iter_segments
def get_segments(segment):
    return list(iter_segments(segment))
