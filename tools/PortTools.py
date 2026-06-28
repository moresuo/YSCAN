#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : python
@File : PortTools.py
@Author : moresuo
@Time : 2026/6/27 23:38
@脚本说明 :
"""


def iter_ports(segment):
    try:
        segment = segment.strip()
        if "-" in segment:
            #清除多余空格，获取端口范围
            port_start, port_end = segment.replace(" ", "").split("-")
            port_start = int(port_start)
            port_end = int(port_end)
            if port_start <= 0 or port_end > 65535 or port_start > port_end:
                raise Exception("请输入正确的端口范围")
            for port in range(port_start, port_end + 1):
                yield port
        elif "," in segment:
            for port in segment.split(","):
                port = int(port.strip())
                if 0 < port <= 65535:
                    yield port
        else:
            port = int(segment)
            if port <= 0 or port > 65535:
                raise Exception("请输入正确的端口")
            yield port
    except Exception as e:
        print(e)


#兼容旧接口：需要列表时再显式转换
#新扫描流程优先使用 iter_ports
def get_ports(segment):
    return list(iter_ports(segment))
