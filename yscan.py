#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""  
@Project : python
@File : yscan.py
@Author : moresuo
@Time : 2026/6/27 15:30  
@脚本说明 : 
"""
import argparse
import sys

from tools.AddressTools import iter_segments
from tools.mysql_burte import scan_mysql_run,scan_mysql_run_file
from tools.redis_burte import scan_redis_run
from tools.ssh_burte import scan_ssh_run,scan_ssh_run_file
from tools.dir_scan import scan_dir_run
from tools.subdomain_scan import scan_subdomain_run
from tools.ip_scan import scan_ip_run
from tools.PortTools import iter_ports
from tools.tcp_port_scan import scan_tcp_port_run
from tools.color import Colors
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DIR_PATH = BASE_DIR / "libs" / "passwords.txt"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

banner="""
 █████ █████  █████████    █████████    █████████   ██████   █████
▒▒███ ▒▒███  ███▒▒▒▒▒███  ███▒▒▒▒▒███  ███▒▒▒▒▒███ ▒▒██████ ▒▒███ 
 ▒▒███ ███  ▒███    ▒▒▒  ███     ▒▒▒  ▒███    ▒███  ▒███▒███ ▒███ 
  ▒▒█████   ▒▒█████████ ▒███          ▒███████████  ▒███▒▒███▒███ 
   ▒▒███     ▒▒▒▒▒▒▒▒███▒███          ▒███▒▒▒▒▒███  ▒███ ▒▒██████ 
    ▒███     ███    ▒███▒▒███     ███ ▒███    ▒███  ▒███  ▒▒█████ 
    █████   ▒▒█████████  ▒▒█████████  █████   █████ █████  ▒▒█████
   ▒▒▒▒▒     ▒▒▒▒▒▒▒▒▒    ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒ ▒▒▒▒▒    ▒▒▒▒▒                                                                                                                                                                                     
"""
print(f"{Colors.RED_BRIGHT}{Colors.BOLD}{banner}{Colors.RESET}")
#创建解析器对象
parser=argparse.ArgumentParser(description="YSCAN")
#创建子命令解析器
subprocess=parser.add_subparsers(dest="subparser_name",help="请选择需要使用的功能")

#分别创建子命令，以及需要的参数
#MySQl相关参数
mysql_subparser=subprocess.add_parser("mysql",help="MySQL相关漏扫")
mysql_subparser.add_argument("-H","--host",dest="host",type=str,required=True,help="MySQL主机地址/网段/范围")
mysql_subparser.add_argument("-P","--port",dest="port",type=int,help="MySQL端口",default=3306)
mysql_subparser.add_argument("-U","--username_file",dest="username_file",type=str,help="MySQL用户名文件路径")
mysql_subparser.add_argument("-u","--username",dest="username",type=str,help="MySQL用户名",default="root")
mysql_subparser.add_argument("-p","--password",dest="password",type=str,help="MySQL密码本路径",default=DIR_PATH)
mysql_subparser.add_argument("-T","--threads", dest="threads", type=int, default=500)
#Redis相关参数
redis_subparser=subprocess.add_parser("redis",help="Redis相关漏扫")
redis_subparser.add_argument("-H","--host",dest="host",type=str,required=True,help="Redis主机地址/网段/范围")
redis_subparser.add_argument("-P","--port",dest="port",type=int,help="Redis端口",default=6379)
redis_subparser.add_argument("-p","--password",dest="password",type=str,help="redis密码本路径",default=DIR_PATH)
redis_subparser.add_argument("-T","--threads", dest="threads", type=int, default=500)
#公私钥未授权输入公钥
redis_subparser.add_argument("-pub","--ssh_pub_key",dest="ssh_pub_key",type=argparse.FileType(mode="r",encoding="utf-8"),help="ssh公钥")
#反弹shell输入IP,端口
redis_subparser.add_argument("-I","--ip",dest="ip",type=str,help="反弹shellIP")
redis_subparser.add_argument("-L","--listen_port",dest="listen_port",type=int,help="反弹shell端口",default=8888)

#ssh相关参数
ssh_subparser=subprocess.add_parser("ssh",help="ssh相关漏扫")
ssh_subparser.add_argument("-H","--host",dest="host",type=str,required=True,help="ssh主机地址/网段/范围")
ssh_subparser.add_argument("-P","--port",dest="port",type=int,help="ssh端口",default=22)
ssh_subparser.add_argument("-U","--username_file",dest="username_file",type=str,help="ssh用户名文件路径")
ssh_subparser.add_argument("-u","--username",dest="username",type=str,help="ssh用户名",default="root")
ssh_subparser.add_argument("-p","--password",dest="password",type=str,help="ssh密码本路径",default=DIR_PATH)
ssh_subparser.add_argument("-T","--threads", dest="threads", type=int, default=500)

#目录扫描参数
dir_subparser=subprocess.add_parser("dir",help="目录扫描")
dir_subparser.add_argument("-t","--url",dest="url",type=str,required=True,help="待扫描的url")
dir_subparser.add_argument("-T","--threads", dest="threads", type=int, default=500)

#子域名扫描参数
subdomain_subparser=subprocess.add_parser("subdomain",help="子域名扫描")
subdomain_subparser.add_argument("-t","--url",dest="url",type=str,required=True,help="待扫描的url")
subdomain_subparser.add_argument("-T","--threads", dest="threads", type=int, default=500)

#ip扫描参数
ip_subparser=subprocess.add_parser("ip",help="内网ip扫描")
ip_subparser.add_argument("-H","--host",dest="host",type=str,required=True,help="ip地址/网段/范围")
ip_subparser.add_argument("-T","--threads", dest="threads", type=int, default=500)

#端口扫描参数
port_subparser=subprocess.add_parser("port",help="端口扫描")
port_subparser.add_argument("-H","--host",dest="host",type=str,required=True,help="ip地址")
port_subparser.add_argument("-p","--ports",dest="ports",type=str,help="端口范围",default="1-65535")
port_subparser.add_argument("-T","--threads", dest="threads", type=int, default=500)

#解析命令行参数
args=parser.parse_args()
if not args.subparser_name:
    parser.print_help()
    exit()
#根据子命令执行相应操作
if args.subparser_name=="mysql":
    hosts=iter_segments(args.host)
    if args.username_file:
        scan_mysql_run_file(hosts,args.username_file, args.password, args.port,args.threads)
    else:
        scan_mysql_run(hosts, args.username, args.password, args.port,args.threads)
    print("[*] 漏扫完毕")
elif args.subparser_name=="redis":
    hosts=iter_segments(args.host)
    #获取公钥文件内容
    ssh_pub_key=args.ssh_pub_key.read() if args.ssh_pub_key else None
    scan_redis_run(hosts,args.port,args.password,ssh_pub_key,args.ip,args.listen_port,args.threads)
    print("[*] 漏扫完毕")
elif args.subparser_name=="ssh":
    hosts=iter_segments(args.host)
    if args.username_file:
        scan_ssh_run_file(hosts,args.username_file,args.password,args.port,args.threads)
    else:
        scan_ssh_run(hosts,args.username,args.password,args.port,args.threads)
    print("[*] 漏扫完毕")
elif args.subparser_name=="dir":
    args.url = args.url.strip()
    if not args.url.endswith("/"):
        args.url+="/"
    scan_dir_run(args.url,args.threads)
    print("[*] 扫描完毕")
elif args.subparser_name=="subdomain":
    scan_subdomain_run(args.url,args.threads)
    print("[*] 扫描完毕")
elif args.subparser_name=="ip":
    hosts=iter_segments(args.host)
    scan_ip_run(hosts,args.threads)
    print("[*] 扫描完毕")
elif args.subparser_name=="port":
    ports=iter_ports(args.ports)
    scan_tcp_port_run(args.host,ports,args.threads)
    print("[*] 扫描完毕")