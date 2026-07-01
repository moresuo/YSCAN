#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : ruoyi_scan.py
@Author : moresuo
@Time : 2026/7/1
@脚本说明 : 若依(RuoYi)项目弱密码检测

融合自 weak_passwd_scanner.py，针对若依框架优化：
1. 少请求: 单目标先探测有效若依前缀, 只打真实 login API
2. 快失败: 短超时 + 命中/明确密码错误后立即停止当前分支
3. 高并发: ThreadPoolExecutor + 线程本地 Session + HTTP 连接池
4. 验证码: 若依 JSON/base64 验证码 OCR(需 ddddocr), 自动计算数学表达式
5. 低误报: 登录成功必须满足 token / 明确成功语义 / 后台跳转

检测链: 前缀探测 -> 若依JSON验证码 -> 表单/数学验证码 -> 通用JSON -> Basic Auth
默认只测若依常见弱口令 admin/admin123、admin/admin、admin/123456。
仅用于授权安全测试。
"""
from __future__ import annotations

import base64
import json
import re
import time
import warnings
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, local
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter

from tools.color import console

warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

DEFAULT_USER = "admin"
DEFAULT_PASSWORDS = "admin123,admin,123456"

JSON_CAPTCHA_PAIRS = [
    ("/dev-api/captchaImage", "/dev-api/login"),
    ("/prod-api/captchaImage", "/prod-api/login"),
    ("/stage-api/captchaImage", "/stage-api/login"),
    ("/api/captchaImage", "/api/login"),
    ("/admin-api/captchaImage", "/admin-api/login"),
    ("/captchaImage", "/login"),
]

JSON_LOGIN_APIS = [
    "/dev-api/login",
    "/prod-api/login",
    "/stage-api/login",
    "/api/login",
    "/admin-api/login",
    "/login",
]

FORM_LOGIN_APIS = ["/login", "/admin/login"]

FAIL_CAPTCHA = [
    "验证码错误", "验证码已失效", "验证码不正确", "验证码输入错误", "验证码不能为空",
    "captcha", "invalid verification", "verification code",
]

FAIL_CREDENTIAL = [
    "密码错误", "用户不存在", "用户名或密码", "账号不存在", "密码不正确", "登录失败",
    "用户密码错误", "用户名错误", "用户不存在/密码错误", "invalid password",
    "wrong password", "incorrect", "bad credentials", "authentication failed",
]

FAIL_OTHER = ["运行时异常", "cannot invoke", "exception", "error"]

# 默认配置（参数固化为合理默认，保持 ruoyi 子命令简洁）
DEFAULT_CONNECT_TIMEOUT = 3.0
DEFAULT_READ_TIMEOUT = 5.0
DEFAULT_POOL_SIZE = 100
DEFAULT_OCR_ROUNDS = 3

_tls = local()
_print_lock = Lock()
_write_lock = Lock()
_ocr_engine = None
_ocr_lock = Lock()


@dataclass(frozen=True)
class Config:
    username: str
    passwords: tuple
    threads: int
    connect_timeout: float
    read_timeout: float
    pool_size: int
    ocr_rounds: int
    no_ocr: bool
    no_basic: bool
    json_only: bool

    @property
    def timeout(self):
        return (self.connect_timeout, self.read_timeout)


def normalize_url(url):
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/") + "/"


def get_session(cfg):
    s = getattr(_tls, "session", None)
    if s is not None:
        return s

    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Connection": "keep-alive",
    })
    adapter = HTTPAdapter(
        pool_connections=cfg.pool_size,
        pool_maxsize=cfg.pool_size,
        max_retries=0,
        pool_block=False,
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    _tls.session = s
    return s


def init_ocr(cfg):
    """初始化 ddddocr，缺失时降级（跳过验证码分支，无验证码站点仍可检测）。"""
    global _ocr_engine
    if cfg.no_ocr:
        console.print("[warn]⚠ OCR 已禁用（带验证码站点将跳过）[/warn]")
        return
    try:
        import ddddocr
        _ocr_engine = ddddocr.DdddOcr(show_ad=False)
        console.print("[info]→ ddddocr 就绪[/info]")
    except Exception:
        _ocr_engine = None
        console.print("[warn]⚠ ddddocr 不可用，仅检测无验证码站点（安装: pip install ddddocr）[/warn]")


def ocr_classify(img):
    if not _ocr_engine or not img:
        return None
    try:
        # ddddocr 并发 classification 不稳定, 加锁牺牲少量吞吐换稳定性
        with _ocr_lock:
            return _ocr_engine.classification(img)
    except Exception:
        return None


def decode_captcha_image(img_b64):
    if not img_b64:
        return b""
    if "," in img_b64:
        img_b64 = img_b64.split(",", 1)[1]
    return base64.b64decode(img_b64)


def calc_math_expr(text):
    if not text:
        return None
    s = str(text)
    trans = {
        "×": "*", "x": "*", "X": "*",
        "÷": "/", "／": "/", "＋": "+", "—": "-", "－": "-",
        "l": "1", "I": "1", "O": "0", "o": "0",
    }
    for k, v in trans.items():
        s = s.replace(k, v)
    s = re.sub(r"[^0-9+\-*/=?]", "", s).replace("=", "").replace("?", "")
    m = re.search(r"(\d{1,3})\s*([+\-*/])\s*(\d{1,3})", s)
    if not m:
        return None

    a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
    if op == "+":
        result = a + b
    elif op == "-":
        result = a - b
    elif op == "*":
        result = a * b
    elif op == "/":
        result = a // b if b else 0
    else:
        return None
    return str(result) if -999 <= result <= 9999 else None


def normalize_captcha_code(raw):
    math_code = calc_math_expr(raw)
    if math_code is not None:
        return math_code
    code = re.sub(r"[^0-9A-Za-z]", "", str(raw or ""))
    return code if len(code) >= 2 else None


def response_kind(resp):
    """返回 success / captcha / credential / fail / unknown。

    成功判断尽量保守, 避免 code=200 但实际失败造成误报。
    """
    ct = resp.headers.get("Content-Type", "").lower()
    text = resp.text or ""
    low = text.lower()

    if "json" in ct:
        try:
            data = resp.json()
            raw = json.dumps(data, ensure_ascii=False).lower()
            msg = str(data.get("msg", "")).lower()
            code = data.get("code")

            if any(k.lower() in raw for k in FAIL_CAPTCHA):
                return "captcha"
            if any(k.lower() in raw for k in FAIL_CREDENTIAL):
                return "credential"
            if any(k.lower() in raw for k in FAIL_OTHER):
                return "fail"

            token = data.get("token") or data.get("access_token")
            if not token and isinstance(data.get("data"), dict):
                token = data["data"].get("token") or data["data"].get("access_token")
            if code in (200, 0, "200", "0") and token and len(str(token)) > 15:
                return "success"
            if code in (200, 0, "200", "0") and ("成功" in msg or "success" in msg):
                return "success"
            if data.get("success") is True and not any(x in raw for x in ["fail", "error", "错误", "失败"]):
                return "success"
        except Exception:
            pass

    for h in resp.history:
        loc = h.headers.get("Location", "").lower()
        if not loc:
            continue
        good = any(k in loc for k in ["dashboard", "admin", "index", "home", "main", "manage", "welcome"])
        bad = any(k in loc for k in ["login", "signin", "auth", "error", "fail", "denied", "locked"])
        if good and not bad:
            return "success"

    if any(k.lower() in low for k in FAIL_CAPTCHA):
        return "captcha"
    if any(k.lower() in low for k in FAIL_CREDENTIAL):
        return "credential"
    if any(k in low for k in ["dashboard", "logout", "退出", "后台管理", "控制台", "登录成功", "欢迎回来", "当前用户"]):
        return "success"

    return "unknown"


def request_get(s, url, cfg):
    try:
        return s.get(url, timeout=cfg.timeout, allow_redirects=True, verify=False)
    except requests.RequestException:
        return None


def post_json(s, url, body, cfg):
    try:
        return s.post(url, json=body, timeout=cfg.timeout, allow_redirects=True, verify=False)
    except requests.RequestException:
        return None


def post_form(s, url, data, cfg):
    try:
        return s.post(url, data=data, timeout=cfg.timeout, allow_redirects=True, verify=False)
    except requests.RequestException:
        return None


def probe_json_captcha(s, base, cfg):
    """探测若依 JSON 验证码前缀, 命中后只使用该前缀登录, 避免扫全路径。"""
    for captcha_api, login_api in JSON_CAPTCHA_PAIRS:
        r = request_get(s, urljoin(base, captcha_api), cfg)
        if not r or r.status_code != 200:
            continue
        if "json" not in r.headers.get("Content-Type", "").lower():
            continue
        try:
            data = r.json()
        except Exception:
            continue
        if not any(k in data for k in ["captchaEnabled", "uuid", "img"]):
            continue
        return {
            "captcha_api": captcha_api,
            "login_api": login_api,
            "captcha_enabled": data.get("captchaEnabled") is not False,
        }
    return None


def solve_json_captcha(s, base, captcha_api, cfg):
    """获取一次 JSON 验证码并 OCR, 返回 (code, uuid, raw_ocr)。"""
    if not _ocr_engine:
        return None, None, None

    r = request_get(s, urljoin(base, captcha_api), cfg)
    if not r or r.status_code != 200:
        return None, None, None
    try:
        data = r.json()
    except Exception:
        return None, None, None

    if data.get("captchaEnabled") is False:
        return "", "", "disabled"

    uuid = str(data.get("uuid", ""))
    img_b64 = data.get("img", "")
    if not img_b64:
        return None, None, None

    try:
        img = decode_captcha_image(img_b64)
    except Exception:
        return None, None, None

    raw = ocr_classify(img)
    code = normalize_captcha_code(raw)
    if not code:
        return None, None, raw or ""
    return code, uuid, raw or ""


def login_ruoyi_json(s, base, login_api, user, pwd, code, uuid, cfg):
    body = {
        "username": user,
        "password": pwd,
        "code": code,
        "uuid": uuid,
        "rememberMe": False,
    }
    r = post_json(s, urljoin(base, login_api), body, cfg)
    if not r:
        return "fail"
    return response_kind(r)


def try_ruoyi_json(s, base, cfg):
    probe = probe_json_captcha(s, base, cfg)
    if not probe:
        return None

    login_api = probe["login_api"]
    captcha_api = probe["captcha_api"]

    # 验证码关闭: 每个密码只发 1 个登录请求。
    if not probe["captcha_enabled"]:
        for pwd in cfg.passwords:
            kind = login_ruoyi_json(s, base, login_api, cfg.username, pwd, "", "", cfg)
            if kind == "success":
                return f"user={cfg.username} pwd={pwd} api={login_api} captcha=disabled"
            if kind == "credential":
                continue
        return None

    # 验证码开启: 每次登录必须重新取 code + uuid。
    if not _ocr_engine:
        return None

    for pwd in cfg.passwords:
        for _ in range(cfg.ocr_rounds):
            code, uuid, raw = solve_json_captcha(s, base, captcha_api, cfg)
            if code is None:
                continue
            kind = login_ruoyi_json(s, base, login_api, cfg.username, pwd, code, uuid, cfg)
            if kind == "success":
                return f"user={cfg.username} pwd={pwd} api={login_api} captcha={code} raw={raw}"
            # 验证码正确后才会进入密码判断, 此密码明确错误则不用继续消耗验证码。
            if kind == "credential":
                break
            # captcha/unknown 多数是 OCR 错, 继续同一密码下一轮。
    return None


def solve_form_math_captcha(s, base, cfg):
    if not _ocr_engine:
        return None
    for cap in ["/captcha/captchaImage?type=math", "/captchaImage?type=math"]:
        r = request_get(s, urljoin(base, cap), cfg)
        if not r or r.status_code != 200 or len(r.content) < 80:
            continue
        raw = ocr_classify(r.content)
        code = normalize_captcha_code(raw)
        if code:
            return code
    return None


def try_form_login(s, base, cfg):
    if cfg.json_only:
        return None

    for pwd in cfg.passwords:
        # 先尝试一次无验证码表单, 对无验证码站点最快。
        for api in FORM_LOGIN_APIS:
            data = {"username": cfg.username, "password": pwd, "rememberMe": "false"}
            r = post_form(s, urljoin(base, api), data, cfg)
            if r and response_kind(r) == "success":
                return f"user={cfg.username} pwd={pwd} api={api} form=no-captcha"

        # 再尝试传统若依数学验证码。
        for _ in range(cfg.ocr_rounds if _ocr_engine else 0):
            code = solve_form_math_captcha(s, base, cfg)
            if not code:
                continue
            for api in FORM_LOGIN_APIS:
                data = {
                    "username": cfg.username,
                    "password": pwd,
                    "rememberMe": "false",
                    "validateCode": code,
                }
                r = post_form(s, urljoin(base, api), data, cfg)
                if not r:
                    continue
                kind = response_kind(r)
                if kind == "success":
                    return f"user={cfg.username} pwd={pwd} api={api} form=math captcha={code}"
                if kind == "credential":
                    break
    return None


def try_generic_json(s, base, cfg):
    """只在未发现若依验证码前缀时做轻量 JSON 登录探测。"""
    for api in JSON_LOGIN_APIS:
        for pwd in cfg.passwords:
            body = {"username": cfg.username, "password": pwd, "code": "", "uuid": ""}
            r = post_json(s, urljoin(base, api), body, cfg)
            if not r:
                continue
            kind = response_kind(r)
            if kind == "success":
                return f"user={cfg.username} pwd={pwd} api={api} json=no-captcha"
            if kind == "captcha":
                # 该 API 需要验证码, 不在通用分支继续消耗时间。
                break
    return None


def try_basic_auth(base, cfg):
    if cfg.no_basic:
        return None
    s = get_session(cfg)
    try:
        r = s.get(base, timeout=cfg.timeout, verify=False, allow_redirects=False)
        if r.status_code != 401 or "WWW-Authenticate" not in r.headers:
            return None
        for pwd in cfg.passwords:
            r2 = s.get(base, auth=(cfg.username, pwd), timeout=cfg.timeout, verify=False, allow_redirects=False)
            if r2.status_code == 200:
                return f"user={cfg.username} pwd={pwd} basic-auth"
    except requests.RequestException:
        return None
    return None


def scan_one(base, cfg):
    """扫描单个目标，返回 (base, info_or_None)。"""
    s = get_session(cfg)

    # 可达性快速探测: 对 nginx 405/403 也视为可达。
    r = request_get(s, base, cfg)
    if not r:
        return base, None

    result = try_ruoyi_json(s, base, cfg)
    if not result:
        result = try_form_login(s, base, cfg)
    if not result:
        result = try_generic_json(s, base, cfg)
    if not result:
        result = try_basic_auth(base, cfg)

    return base, result


def scan_ruoyi_run(targets, threads=100, output_file=None, username=DEFAULT_USER,
                   passwords=None, no_ocr=False, no_basic=False, json_only=False):
    """若依弱密码检测入口（Rich + alive_bar 风格）。

    Args:
        targets:      目标 URL 迭代器
        threads:      并发线程数（默认 100）
        output_file:  结果导出文件（弱密码目标写入）
        username:     用户名（默认 admin）
        passwords:    密码元组（默认 admin123,admin,123456）
        no_ocr:       禁用验证码 OCR
        no_basic:     禁用 Basic Auth 检测
        json_only:    只检测 JSON API
    """
    import sys
    from pathlib import Path
    from alive_progress import alive_bar
    from rich.panel import Panel

    # 规整化 + 去重
    seen = set()
    urls = []
    for raw in targets:
        u = normalize_url(raw)
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    if not urls:
        console.print("[warn]⚠ 没有可扫描目标[/warn]")
        return

    if passwords is None:
        passwords = tuple(DEFAULT_PASSWORDS.split(","))
    else:
        passwords = tuple(passwords)

    cfg = Config(
        username=username,
        passwords=passwords,
        threads=max(1, threads),
        connect_timeout=DEFAULT_CONNECT_TIMEOUT,
        read_timeout=DEFAULT_READ_TIMEOUT,
        pool_size=DEFAULT_POOL_SIZE,
        ocr_rounds=DEFAULT_OCR_ROUNDS,
        no_ocr=no_ocr,
        no_basic=no_basic,
        json_only=json_only,
    )

    # OCR 初始化（ddddocr 缺失降级）
    init_ocr(cfg)

    console.print(Panel.fit(
        f"[accent]目标数[/accent]    [count]{len(urls)}[/count]\n"
        f"[accent]用户名[/accent]    [highlight]{cfg.username}[/highlight]\n"
        f"[accent]密码[/accent]      [highlight]{', '.join(cfg.passwords)}[/highlight]\n"
        f"[accent]并发[/accent]      [count]{cfg.threads}[/count]",
        title="[header]若依弱密码检测[/header]",
        border_style="dim",
    ))

    found = 0
    found_list = []  # [(url, info)]
    completed = [0]
    total = len(urls)
    started = time.perf_counter()

    # 进度条与端口扫描一致，输出到 stderr
    with alive_bar(
        total,
        title="若依检测",
        bar="smooth",
        spinner="dots_waves2",
        enrich_print=False,
        file=sys.__stderr__,
        receipt=True,
        receipt_text="若依检测完成",
    ) as _bar:
        with ThreadPoolExecutor(max_workers=cfg.threads) as pool:
            futures = {pool.submit(scan_one, t, cfg): t for t in urls}
            for fut in as_completed(futures):
                url = futures[fut]
                completed[0] += 1
                _bar()
                try:
                    target, info = fut.result()
                except Exception:
                    continue
                if info:
                    found += 1
                    found_list.append((target, info))
                    console.print(f"  [success]●[/success] [host]{target}[/host] [dim]弱密码![/dim] [highlight]{info}[/highlight]")

    cost = time.perf_counter() - started

    # 导出弱密码结果
    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as fh:
            for url, info in found_list:
                fh.write(f"{url}  {info}\n")
        console.print(f"[info]→ 已保存 {found} 个弱密码目标至 [url]{output_file}[/url]")

    console.print(f"[info]扫描 {total} | 弱密码 {found} | 耗时 {cost:.1f}s[/info]")
