# YSCAN Linux 构建指南

在 Linux 主机上构建 YSCAN ELF 可执行文件 `dist/yscan`。

## 前置条件

### 系统要求

| 项目 | 版本/说明 |
|------|----------|
| 操作系统 | Linux (WSL2 / 虚拟机 / 裸机 / Docker) |
| Python | 3.9 ~ 3.12 |
| pip | 随 Python 安装 |
| 磁盘空间 | ≥ 2 GB（构建中间产物 + 最终 ~100 MB） |

### 系统依赖（apt）

```bash
# 推荐安装以获得最佳构建结果
sudo apt install upx-ucl libcurl4-openssl-dev

# ddddocr OpenCV 运行时（通常已预装）
sudo apt install libgl1-mesa-glx libglib2.0-0 libsm6 libxext6 libxrender-dev libgomp1

# ARP 功能运行时依赖（非构建必需）
sudo apt install libpcap-dev
```

---

## 方式一：直接构建（推荐）

```bash
cd build_linux
chmod +x build.sh
./build.sh
```

产物在 `../dist/yscan`。

### 可选参数

```bash
# 重新加密模块（修改了 tools/*.py 源码时使用）
./build.sh --reencrypt

# ⚠️ --reencrypt 会修改 tools/_decrypt_loader.py
# 构建完成后请恢复: git checkout tools/_decrypt_loader.py
```

### 构建流程

```
环境检测 → 创建 venv → 安装依赖 → 复用 .enc → PyInstaller → 冒烟验证
```

---

## 方式二：Docker 构建

无需安装任何 Python 环境，Docker 容器内置全部依赖。

```bash
# 在项目根目录执行（注意：不是 build_linux/ 目录内）
cd ..

# 一键构建并导出产物到 dist/yscan
docker build -f build_linux/Dockerfile -o dist/ .
```

或者分两步：

```bash
# 1. 构建镜像
docker build -f build_linux/Dockerfile -t yscan-builder .

# 2. 提取产物到宿主机
docker run --rm -v $(pwd)/dist:/build/dist yscan-builder cp dist/yscan /build/dist/
```

---

## 验证

```bash
# 查看文件类型（应显示 ELF 64-bit）
file dist/yscan

# 查看所有子命令
./dist/yscan --help

# 快速功能测试（无网络依赖）
./dist/yscan port -H 127.0.0.1 --top 10

# 域名解析测试
./dist/yscan dns -u baidu.com

# ARP 存活探测（需 root）
sudo ./dist/yscan ip -H 192.168.1.0/24
```

---

## 注意事项

| 事项 | 说明 |
|------|------|
| **ARP 功能** | 需要 root 权限或 `CAP_NET_RAW`。推荐：`sudo setcap cap_net_raw+ep dist/yscan` |
| **WSL 环境** | 建议使用 WSL2，WSL1 网络栈差异可能导致部分扫描功能受限 |
| **加密模块** | 构建脚本默认复用仓库中已有的 `tools/_encrypted/*.enc`，不重新加密 |
| **ddddocr** | 首次运行 OCR 时会下载模型文件，速度较慢 |
| **构建时间** | 首次 3-10 分钟（取决于网络），后续 1-2 分钟 |

---

## 已知问题

### UPX 压缩失败

PyInstaller 报 `UPX is not available` 或压缩错误时：

```bash
# 方案 1：安装 UPX
sudo apt install upx-ucl

# 方案 2：编辑 yscan.spec，将 upx=True 改为 upx=False
```

### 构建时内存不足

PyInstaller 单文件模式打包 ~100 MB 产物时约需 1-2 GB 内存。机器内存不足时：

```bash
# 增加 swap
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
# 构建完成后
sudo swapoff /swapfile
sudo rm /swapfile
```

### curl_cffi 安装失败

```bash
# 确保 libcurl4 已安装
sudo apt install libcurl4-openssl-dev

# 如果仍失败，升级 pip 后重试
pip install --upgrade pip
```
