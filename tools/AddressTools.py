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


#网段转化
def get_segments(segment):
    try:
        if "/" in segment:
            hosts=[str(ip) for ip in ipaddress.ip_network(segment,strict=False).hosts()]
        elif "-" in segment:
            #清除多余空格
            ip_start,ip_end=segment.replace(" ","").split("-")
            start=int(ipaddress.ip_address(ip_start))
            end=int(ipaddress.ip_address(ip_end))
            hosts=[str(ipaddress.ip_address(ip)) for ip in range(start,end+1)]
        else:
            hosts=[segment]
        return hosts
    except Exception as e:
        print(e)