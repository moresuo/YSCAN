#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
# YSCAN Linux 一键构建脚本
# 用法: ./build.sh [--reencrypt]
#
# 在 Linux 主机（WSL2/VM/裸机）上执行，生成 dist/yscan ELF 可执行文件。
# 默认复用已有的 tools/_encrypted/*.enc 加密模块，不修改任何源码。
# --reencrypt: 重新运行 build_encrypted.py 并同步盐到 _decrypt_loader.py。
#
set -euo pipefail

# ── 颜色 ────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*"; }
step()  { echo -e "\n${CYAN}${BOLD}==>${NC} ${CYAN}$*${NC}"; }

# ── 路径解析 ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

REENCrypt=false
if [[ "${1:-}" == "--reencrypt" ]]; then
    REENCrypt=true
fi

echo ""
echo -e "${CYAN}${BOLD}  YSCAN Linux Build${NC}"
echo -e "${CYAN}  ================${NC}"
echo ""

# ── 第 1 步：环境检测 ───────────────────────────────────────────
step "第 1 步：环境检测"

# 检查是否在 Linux 上
if [[ "$(uname -s)" != "Linux" ]]; then
    err "此脚本必须在 Linux 环境上运行（当前: $(uname -s)）"
    err "请在 WSL2 / 虚拟机 / Docker 中执行"
    exit 1
fi

# 检查 Python
PYTHON=""
for candidate in python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$major" -ge 3 && "$minor" -ge 9 ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    err "未找到 Python 3.9+，请先安装"
    err "  Ubuntu/Debian: sudo apt install python3 python3-pip python3-venv"
    err "  CentOS/RHEL:   sudo dnf install python3 python3-pip"
    exit 1
fi
info "Python: $($PYTHON --version)"

# 检查 pip
if ! "$PYTHON" -m pip --version &>/dev/null; then
    err "pip 不可用，请安装 python3-pip"
    exit 1
fi

# 检查系统级工具（非阻塞，仅提示）
MISSING_PKGS=""
command -v upx &>/dev/null || MISSING_PKGS="$MISSING_PKGS upx-ucl"
if ! ldconfig -p 2>/dev/null | grep -q libcurl; then
    MISSING_PKGS="$MISSING_PKGS libcurl4-openssl-dev"
fi

if [[ -n "$MISSING_PKGS" ]]; then
    warn "建议安装以下系统包以获得最佳构建结果:"
    warn "  sudo apt install$MISSING_PKGS"
    if ! command -v upx &>/dev/null; then
        warn "  (UPX 不可用，将自动将 spec 中 upx 改为 False)"
    fi
fi

# ── 第 2 步：创建虚拟环境 ───────────────────────────────────────
step "第 2 步：创建 Python 虚拟环境"

VENV_DIR="$PROJECT_DIR/.venv_linux"

if [[ -d "$VENV_DIR" ]]; then
    info "虚拟环境已存在，跳过创建: $VENV_DIR"
else
    "$PYTHON" -m venv "$VENV_DIR"
    info "虚拟环境已创建: $VENV_DIR"
fi

# 激活
source "$VENV_DIR/bin/activate"
info "已激活虚拟环境"

# 升级 pip
pip install --upgrade pip --quiet
info "pip 已升级"

# ── 第 3 步：安装依赖 ───────────────────────────────────────────
step "第 3 步：安装 Python 依赖"

pip install -r requirements.txt
pip install pyinstaller
info "依赖安装完成"

# ── 第 4 步：加密模块 ───────────────────────────────────────────
step "第 4 步：加密模块检查"

ENCRYPTED_DIR="$PROJECT_DIR/tools/_encrypted"
ENCRYPTED_COUNT=$(ls -1 "$ENCRYPTED_DIR"/*.enc 2>/dev/null | wc -l)

if [[ "$REEncrypt" == true ]]; then
    # ── 重新加密模式 ──
    info "重新生成加密模块..."

    python build_encrypted.py

    # 提取控制台输出的盐
    SALT_LINE=$(python build_encrypted.py 2>&1 | grep -oP '密钥盐 \(base64\): \K[A-Za-z0-9+/=]+' | tail -1)

    if [[ -z "$SALT_LINE" ]]; then
        err "无法从 build_encrypted.py 输出中提取盐值"
        exit 1
    fi
    info "新盐: $SALT_LINE"

    # 自动替换 _decrypt_loader.py 中的 _SALT 行
    python -c "
import re, sys
salt = '$SALT_LINE'
path = 'tools/_decrypt_loader.py'
with open(path, 'r') as f:
    content = f.read()
new_content = re.sub(
    r'_SALT = base64\.b64decode\(b\"[^\"]*\"\)',
    f'_SALT = base64.b64decode(b\"{salt}\")',
    content
)
if new_content == content:
    print('WARNING: _SALT 行未匹配，请手动检查 _decrypt_loader.py', file=sys.stderr)
    sys.exit(1)
with open(path, 'w') as f:
    f.write(new_content)
print('_SALT 已更新')
"
    info "加密模块已重新生成，_SALT 已同步"
else
    # ── 默认模式：复用已有 .enc ──
    if [[ "$ENCRYPTED_COUNT" -lt 20 ]]; then
        err "加密模块不足（找到 ${ENCRYPTED_COUNT} 个，预期 ≥20）"
        err "请先在 Windows 上运行 build_encrypted.py，或用 --reencrypt 选项"
        exit 1
    fi
    info "加密模块已就绪（${ENCRYPTED_COUNT} 个 .enc 文件），跳过重新加密"
fi

# ── 第 5 步：PyInstaller 打包 ────────────────────────────────────
step "第 5 步：PyInstaller 打包"

# UPX 检测：不可用时禁用
if ! command -v upx &>/dev/null; then
    warn "UPX 不可用，将 spec 中 upx 临时改为 False"
    cp yscan.spec yscan.spec.bak
    sed -i 's/upx=True/upx=False/' yscan.spec
fi

pyinstaller --clean yscan.spec

# 恢复 spec
if [[ -f yscan.spec.bak ]]; then
    mv yscan.spec.bak yscan.spec
fi

# ── 第 6 步：验证 ───────────────────────────────────────────────
step "第 6 步：验证"

EXECUTABLE="$PROJECT_DIR/dist/yscan"

if [[ ! -f "$EXECUTABLE" ]]; then
    err "构建失败：dist/yscan 未生成"
    exit 1
fi

chmod +x "$EXECUTABLE"

# file 命令查看类型
if command -v file &>/dev/null; then
    FILE_OUTPUT=$(file "$EXECUTABLE")
    info "文件类型: $FILE_OUTPUT"
    if ! echo "$FILE_OUTPUT" | grep -qi "ELF"; then
        warn "输出文件似乎不是 ELF 格式，请检查"
    fi
fi

# 文件大小
SIZE=$(du -h "$EXECUTABLE" | cut -f1)
info "文件大小: $SIZE"

# 冒烟测试
echo ""
info "冒烟测试: ./dist/yscan --help"
if "$EXECUTABLE" --help &>/dev/null; then
    info "冒烟测试通过 ✓"
else
    err "冒烟测试失败：yscan --help 返回非零退出码"
    exit 1
fi

# ── 完成 ─────────────────────────────────────────────────────────
step "构建完成"

echo ""
echo -e "  ${GREEN}✓${NC} 可执行文件: ${BOLD}dist/yscan${NC}"
echo -e "  ${GREEN}✓${NC} 文件大小:   ${BOLD}$SIZE${NC}"
echo ""
echo -e "  ${YELLOW}运行示例:${NC}"
echo -e "    ./dist/yscan --help"
echo -e "    ./dist/yscan port -H 127.0.0.1 --top 10"
echo -e "    sudo ./dist/yscan ip -H 192.168.1.0/24   ${YELLOW}# ARP 功能需 root${NC}"
echo ""

# ── 提醒：reencrypt 后恢复源码 ──
if [[ "$REEncrypt" == true ]]; then
    warn "=============================================="
    warn "  --reencrypt 模式已修改 tools/_decrypt_loader.py"
    warn "  构建完成后请执行以下命令恢复源码："
    warn ""
    warn "    git checkout tools/_decrypt_loader.py"
    warn "=============================================="
fi
