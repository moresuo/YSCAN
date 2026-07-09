# YSCAN Linux 构建容器
# 用法:
#   docker build -f build_linux/Dockerfile -o dist/ .
#   （产物 dist/yscan 直接输出到宿主机）
#
# 或:
#   docker build -f build_linux/Dockerfile -t yscan-builder .
#   docker run --rm -v $(pwd)/dist:/build/dist yscan-builder cp dist/yscan /build/dist/
#

FROM python:3.11-slim-bookworm AS builder

# ── 系统级依赖 ──
# libcurl4:     curl_cffi 所需
# libgl1/mesa等: ddddocr OpenCV 运行时
# libpcap:      scapy ARP 抓包
# upx:          二进制压缩（可选，减少产物体积）
# binutils:     file/strip 等工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    upx-ucl \
    libcurl4-openssl-dev \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# 先拷贝依赖文件，利用 Docker 层缓存
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt pyinstaller

# 拷贝整个项目（加密模块 tools/_encrypted/*.enc 随项目一起）
COPY . .

# PyInstaller 构建（复用已有 .enc，不重新加密）
RUN pyinstaller --clean yscan.spec \
    && chmod +x dist/yscan \
    && dist/yscan --help

# 产物在 /build/dist/yscan
# docker build -o 直接导出到宿主机 dist/ 目录
