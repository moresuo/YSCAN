#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""  
@Project : python
@File : PortTools.py
@Author : moresuo
@Time : 2026/6/27 23:38  
@脚本说明 : 
"""

def get_ports(segment):
    ports=[]
    try:
        if "-" in segment:
            #清除多余空格，获取端口范围
            port_start,port_end=segment.replace(" ","").split("-")
            if int(port_start)<=0 or int(port_end)>65535 or int(port_start)>int(port_end):
                raise Exception("请输入正确的端口范围")
            ports=[port for port in range(int(port_start),int(port_end)+1)]
        elif "," in segment:
            ports_tmp=[int(port) for port in segment.split(",")]
            ports=list(filter(lambda x: 0 < x <= 65535, ports_tmp))
        else:
            port=int(segment)
            if port<=0 or port>65535:
                raise Exception("请输入正确的端口")
            ports=[port]
        return ports
    except Exception as e:
        print(e)
        pass
