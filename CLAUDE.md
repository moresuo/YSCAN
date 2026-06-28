# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概览

YSCAN 是一个轻量级 Python 安全测试工具集合，面向授权内网探测、Web 目录/子域枚举、端口扫描和常见服务弱口令验证。当前仓库不是完整打包项目，没有 `pyproject.toml`、`requirements.txt`、README 或测试框架配置；主要以 `tools/` 下的函数模块供脚本或交互式调用。

## 常用命令

### 环境与依赖

当前仓库自带 `.venv/`，已观察到使用 Python 3.14，并依赖以下第三方库：`paramiko`、`redis`、`PyMySQL`、`requests`、`dnspython`。

```bash
# 查看 Python 版本
python --version

# 使用仓库现有虚拟环境执行 Python
.venv/Scripts/python.exe --version

# 如需重建依赖环境（仓库当前没有 requirements.txt）
python -m venv .venv
.venv/Scripts/python.exe -m pip install paramiko redis PyMySQL requests dnspython

# 查看当前虚拟环境依赖
.venv/Scripts/python.exe -m pip list
```

### 语法检查 / 基础验证

```bash
# 编译检查所有项目源码，不包含 .venv
.venv/Scripts/python.exe -m compileall tools

# 单文件语法检查
.venv/Scripts/python.exe -m py_compile tools/redis_burte.py
```

### 手动调用示例

仓库当前没有 CLI 入口；运行功能时通常通过 `python -c` 或新增入口脚本调用模块函数。字典文件路径是相对路径，建议从仓库根目录执行。

```bash
# IP 段解析：CIDR、起止范围、单 IP
.venv/Scripts/python.exe -c "from tools.AddressTools import get_segments; print(get_segments('192.168.1.0/30'))"
.venv/Scripts/python.exe -c "from tools.AddressTools import get_segments; print(get_segments('192.168.1.1-192.168.1.3'))"

# 端口解析：范围、逗号列表、单端口
.venv/Scripts/python.exe -c "from tools.PortTools import get_ports; print(get_ports('80,443,8080'))"
.venv/Scripts/python.exe -c "from tools.PortTools import get_ports; print(get_ports('1-1024'))"

# TCP 端口扫描示例
.venv/Scripts/python.exe -c "from tools.tcp_port_scan import scan_tcp_port_run; scan_tcp_port_run('127.0.0.1', [22,80,443])"

# 目录扫描示例：读取 libs/dirpath.txt
.venv/Scripts/python.exe -c "from tools.dir_scan import scan_dir_run; scan_dir_run('https://example.com')"

# 子域扫描示例：读取 libs/subdomain.txt
.venv/Scripts/python.exe -c "from tools.subdomain_scan import scan_subdomain_run; scan_subdomain_run('example.com')"
```

### 测试现状

当前仓库没有 `tests/`、pytest/unittest 配置或 CI 文件。若需要验证单个函数，优先用 `python -c` 构造最小输入输出检查；若新增测试，建议先补充独立 `tests/` 目录和依赖清单。

## 代码结构

```text
tools/
  AddressTools.py      # IP 输入规范化：CIDR、IP 范围、单 IP -> host 列表
  PortTools.py         # 端口输入规范化：范围、逗号列表、单端口 -> port 列表
  ip_scan.py           # Windows ping 存活探测
  tcp_port_scan.py     # TCP connect 端口扫描
  dir_scan.py          # 基于 requests + libs/dirpath.txt 的 Web 目录扫描
  subdomain_scan.py    # 基于 dnspython + libs/subdomain.txt 的 A 记录枚举
  ssh_burte.py         # Paramiko SSH 弱口令验证
  mysql_burte.py       # PyMySQL MySQL 弱口令验证
  redis_burte.py       # Redis 弱口令/未授权相关验证与写入尝试
libs/
  users.txt            # 用户名字典
  passwords.txt        # 密码字典
  dirpath.txt          # 目录扫描字典
  subdomain.txt        # 子域名字典
```

## 架构与数据流

- `AddressTools.get_segments()` 和 `PortTools.get_ports()` 是输入展开层，用于把用户输入的网段/端口表达式转换为扫描模块可消费的列表。
- 扫描模块普遍采用 `concurrent.futures.ThreadPoolExecutor` 并发调度，结果通过 `print()` 输出，没有统一结果对象、日志层或持久化层。
- `dir_scan.py`、`subdomain_scan.py`、弱口令模块直接读取 `libs/` 下的字典文件；这些路径依赖当前工作目录，通常必须从仓库根目录执行。
- 多数模块采用宽泛 `except: pass`，异常默认被吞掉。调试时应临时缩小异常捕获或打印异常，否则失败原因不可见。
- `ip_scan.py` 使用 Windows 命令 `ping -n 1 ... | findstr TTL`，对 Linux/macOS 不兼容。
- `redis_burte.py` 包含 Redis 未授权访问后的写入验证逻辑，包括 SSH `authorized_keys` 写入和 cron 反弹命令写入；修改该模块时应保持授权测试语境，并避免在非授权目标上执行破坏性写入。

## 开发注意事项

- 保持现有模块风格：单文件函数式工具、中文注释、直接打印结果。
- 文件名中已有 `burte` 拼写（如 `ssh_burte.py`、`mysql_burte.py`、`redis_burte.py`），引用时保持现状，除非明确进行重命名迁移。
- 新增依赖时同步创建或更新依赖清单；当前仓库缺少 `requirements.txt`，后续应优先补齐。
- 新增调用入口时，优先复用 `tools/` 中的函数，不要把扫描逻辑复制到入口脚本。
- 高并发参数当前较大（如 500、1000、5000 worker），修改扫描逻辑时注意资源消耗、超时设置和授权测试边界。
