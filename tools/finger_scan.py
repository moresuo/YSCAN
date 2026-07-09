#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : finger_scan.py
@Author : moresuo
@Time : 2026/7/9
@脚本说明 : Web 指纹识别（基于 libs/finger.yaml 表达式规则库）

规则语法（FingerprintHub / fofa 表达式）：
  字段: body / title / header / banner / cert / icon_hash / protocol / status
  操作符: =(包含) ==(精确) ~(正则) !=(非)
  逻辑: &&(与) ||(或) ()(分组嵌套)

流程: HTTP 存活探测 -> 提取字段(body/title/header/status/icon_hash) -> 规则匹配
icon_hash 采用 fofa favicon hash 算法（mmh3），mmh3 缺失时自动降级跳过。
仅用于授权安全测试。
"""
import re
import sys
import threading
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import yaml
from alive_progress import alive_bar

from tools.color import console

warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

BASE_DIR = Path(__file__).resolve().parent.parent
FINGER_PATH = BASE_DIR / "libs" / "finger.yaml"

DEFAULT_THREADS = 100
TIMEOUT = 8
# body 截断长度，避免超大响应体拖慢全量规则匹配
BODY_MAX_LEN = 200_000

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}


# ════════════════════════════════════════════════════════════════
# 表达式解析器（递归下降：or -> and -> atom）
# ════════════════════════════════════════════════════════════════

def tokenize(expr):
    """词法分析：拆出 FIELD / OP / STR / PAREN。"""
    tokens = []
    i, n = 0, len(expr)
    while i < n:
        c = expr[i]
        if c.isspace():
            i += 1
            continue
        # 字符串（双引号或单引号，支持转义）
        if c == '"' or c == "'":
            quote = c
            j = i + 1
            buf = []
            while j < n:
                if expr[j] == "\\" and j + 1 < n:
                    buf.append(expr[j + 1])
                    j += 2
                elif expr[j] == quote:
                    break
                else:
                    buf.append(expr[j])
                    j += 1
            tokens.append(("STR", "".join(buf)))
            i = j + 1
            continue
        # 两字符操作符（==, ~=, !=, &&, ||）
        two = expr[i:i + 2]
        if two in ("==", "~=", "!=", "&&", "||"):
            tokens.append(("OP", two))
            i += 2
            continue
        # 括号
        if c in "()":
            tokens.append(("PAREN", c))
            i += 1
            continue
        # 单字符 = （包含）
        if c == "=":
            tokens.append(("OP", "="))
            i += 1
            continue
        # 字段名
        if c.isalpha() or c == "_":
            j = i
            while j < n and (expr[j].isalnum() or expr[j] == "_"):
                j += 1
            tokens.append(("FIELD", expr[i:j]))
            i = j
            continue
        # 未知字符跳过
        i += 1
    return tokens


class _Parser:
    """递归下降解析器，生成 AST 元组。"""

    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else (None, None)

    def _next(self):
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self):
        if not self.tokens:
            return ("false",)
        return self._parse_or()

    def _parse_or(self):
        left = self._parse_and()
        while self._peek() == ("OP", "||"):
            self._next()
            right = self._parse_and()
            left = ("or", left, right)
        return left

    def _parse_and(self):
        left = self._parse_atom()
        while self._peek() == ("OP", "&&"):
            self._next()
            right = self._parse_atom()
            left = ("and", left, right)
        return left

    def _parse_atom(self):
        ttype, tval = self._peek()
        if ttype == "PAREN" and tval == "(":
            self._next()
            expr = self._parse_or()
            if self._peek() == ("PAREN", ")"):
                self._next()
            return expr
        if ttype == "FIELD":
            return self._parse_cmp()
        # 容错：跳过非法 token
        self._next()
        return ("false",)

    def _parse_cmp(self):
        field = self._next()[1]
        op_type, op_val = self._peek()
        if op_type != "OP":
            return ("false",)
        self._next()
        str_type, str_val = self._peek()
        if str_type != "STR":
            return ("false",)
        self._next()
        return ("cmp", field.lower(), op_val, str_val)


def parse_rule(rule):
    """解析单条规则为 AST，失败返回 None。"""
    try:
        return _Parser(tokenize(rule)).parse()
    except Exception:
        return None


# ════════════════════════════════════════════════════════════════
# 求值器（精确命中词）
# ════════════════════════════════════════════════════════════════

def _eval(ast, ctx):
    """基础求值（保留兼容）。"""
    typ = ast[0]
    if typ == "or":
        return _eval(ast[1], ctx) or _eval(ast[2], ctx)
    if typ == "and":
        return _eval(ast[1], ctx) and _eval(ast[2], ctx)
    if typ == "cmp":
        return _eval_cmp(ast[1], ast[2], ast[3], ctx)
    return False


def _eval_cmp(field, op, value, ctx):
    text = _get_field(field, ctx)
    if text is None:
        return False
    text = str(text)
    if field in ("icon_hash", "status") and op == "=":
        return text == value
    if op == "=":
        return value in text
    if op == "==":
        return text == value
    if op == "~=":
        try:
            return re.search(value, text) is not None
        except re.error:
            return False
    if op == "!=":
        return value not in text
    return False


def _eval_hit_words(ast, ctx):
    """返回 (bool, [(field, kw)])。
    关键：OR 节点只返回**实际命中分支**的命中词，
    AND 节点累积所有分支的命中词。
    这样 body="OAapp" || body="window.location" 在若依页面
    只返回 (True, [("body","window.location")])，通用词会被后续过滤掉。
    """
    if ast is None:
        return False, []
    typ = ast[0]
    if typ == "or":
        ok1, kw1 = _eval_hit_words(ast[1], ctx)
        if ok1:
            return True, kw1  # 左真→只返回左分支的关键词
        ok2, kw2 = _eval_hit_words(ast[2], ctx)
        return ok2, kw2  # 左假右真→只返回右分支
    if typ == "and":
        ok1, kw1 = _eval_hit_words(ast[1], ctx)
        if not ok1:
            return False, []
        ok2, kw2 = _eval_hit_words(ast[2], ctx)
        if not ok2:
            return False, []
        return True, kw1 + kw2  # AND→累积两分支
    if typ == "cmp":
        field, op, val = ast[1], ast[2], ast[3]
        if _eval_cmp(field, op, val, ctx):
            return True, [(field, val)]
        return False, []
    return False, []


# ── 关键词特异性规则 ──
# 规则形如 body="login" || body="特异词" 的通用分支不应导致命中
_LOW_SPEC_KWS = frozenset({
    "login", "password", "language", "user", "admin", "home", "main",
    "index", "search", "register", "submit", "success", "error", "send",
    "360", "Powered by", ".php?", "h3c.com", "login.php",
    "shortcut icon", "web", "page", "src", "href", "cache/", "download",
    "default", "true", "false", "null", "undefined", "upload",
    "url", "data", "type", "name", "id", "class", "value",
    "info", "api", "www", "http", "net", "com", "org",
    "file", "path", "root", "temp", "public", "static",
    "window.location", "/js/app", "/static/img/title.ico",
})


def _is_specific_hit(field, kw):
    """关键词是否足够特异（排除通用/低质命中）。"""
    if field in ("icon_hash", "status"):
        return True
    kw_clean = kw.strip()
    if kw_clean.lower() in _LOW_SPEC_KWS:
        return False
    if field == "header":
        return len(kw_clean) >= 8
    if field in ("body", "title"):
        return len(kw_clean) >= 6
    return len(kw_clean) >= 5


def _get_field(field, ctx):
    if field == "body":
        return ctx.body
    if field == "title":
        return ctx.title
    if field == "header":
        return ctx.header
    if field == "status":
        return ctx.status
    if field == "icon_hash":
        return ctx.icon_hash
    # banner / cert / protocol 在纯 HTTP 指纹识别中不提取
    return None


# ════════════════════════════════════════════════════════════════
# 匹配上下文（icon_hash 懒加载，避免无谓下载 favicon）
# ════════════════════════════════════════════════════════════════

class MatchContext:
    __slots__ = ("body", "title", "header", "status", "_url", "_session",
                 "_timeout", "_icon_hash", "_icon_loaded")

    def __init__(self, body, title, header, status, url, session, timeout):
        self.body = body or ""
        self.title = title or ""
        self.header = header or ""
        self.status = status or ""
        self._url = url
        self._session = session
        self._timeout = timeout
        self._icon_hash = None
        self._icon_loaded = False

    @property
    def icon_hash(self):
        # 仅当规则访问 icon_hash 时才下载 favicon（懒加载）
        if not self._icon_loaded:
            self._icon_loaded = True
            self._icon_hash = compute_icon_hash(self._url, self._session, self._timeout)
        return self._icon_hash


# ════════════════════════════════════════════════════════════════
# 字段提取
# ════════════════════════════════════════════════════════════════

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_title(body):
    if not body:
        return ""
    m = _TITLE_RE.search(body)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()


def compute_icon_hash(url, session, timeout):
    """fofa favicon hash: mmh3(base64(favicon 字节))。mmh3 缺失返回 None。"""
    try:
        import mmh3
        import base64
    except ImportError:
        return None
    try:
        favicon_url = urljoin(url, "/favicon.ico")
        resp = session.get(favicon_url, verify=False, timeout=timeout, allow_redirects=True)
        if resp.status_code != 200 or not resp.content:
            return None
        # fofa 算法：base64 编码（带换行）后 mmh3.hash
        b64 = base64.encodebytes(resp.content).decode("utf-8")
        return str(mmh3.hash(b64))
    except Exception:
        return None


def normalize_url(raw):
    """URL 规整化：补全 http:// 协议，兼容 IP:port / 域名 / 完整 URL。"""
    s = raw.strip().rstrip("/")
    if not s:
        return None
    if s.startswith("http://") or s.startswith("https://"):
        return s
    return "http://" + s


# ════════════════════════════════════════════════════════════════
# 指纹库加载（模块级缓存，线程安全单例）
# ════════════════════════════════════════════════════════════════

_fingerprints = None  # [(产品名, [AST,...])]
_finger_lock = threading.Lock()
_finger_stats = {"products": 0, "rules": 0, "failed": 0}


def _locate_finger_path():
    """定位 libs/finger.yaml，兼容 PyInstaller frozen 环境。"""
    import sys as _sys
    if getattr(_sys, "frozen", False):
        base = Path(_sys._MEIPASS)
    else:
        base = BASE_DIR
    return base / "libs" / "finger.yaml"


def load_fingerprints():
    """加载并解析指纹库，返回 [(产品名, [AST 列表])]。模块级缓存。"""
    global _fingerprints
    if _fingerprints is not None:
        return _fingerprints
    with _finger_lock:
        if _fingerprints is not None:
            return _fingerprints
        path = _locate_finger_path()
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            console.print(f"[fail]✗ 指纹库加载失败: {e}[/fail]")
            _fingerprints = []
            return _fingerprints

        if not isinstance(data, dict):
            _fingerprints = []
            return _fingerprints

        fps = []
        total_rules = 0
        failed = 0
        for product, rules in data.items():
            if not isinstance(rules, list):
                continue
            asts = []
            for rule in rules:
                if not isinstance(rule, str):
                    continue
                ast = parse_rule(rule)
                if ast is not None and ast[0] != "false":
                    asts.append(ast)
                    total_rules += 1
                else:
                    failed += 1
            if asts:
                fps.append((product, asts))
        _fingerprints = fps
        _finger_stats["products"] = len(fps)
        _finger_stats["rules"] = total_rules
        _finger_stats["failed"] = failed
        return _fingerprints


# ════════════════════════════════════════════════════════════════
# 单 URL 识别
# ════════════════════════════════════════════════════════════════

thread_local = threading.local()


def _get_session():
    session = getattr(thread_local, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update(_HEADERS)
        session.verify = False
        thread_local.session = session
    return session


def identify_url(url, fingerprints=None, timeout=TIMEOUT, session=None):
    """识别单个 URL，返回 (url, matched_list_or_None)。

    返回值:
      (url, None)      - 目标不存活（HTTP 不可达）
      (url, [])        - 存活但未识别出指纹
      (url, [产品名])  - 识别成功
    """
    if fingerprints is None:
        fingerprints = load_fingerprints()
    if session is None:
        session = _get_session()

    # 存活探测：HTTP GET 不可达视为不存活
    try:
        resp = session.get(url, verify=False, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return url, None
    except Exception:
        return url, None

    body = resp.text or ""
    if len(body) > BODY_MAX_LEN:
        body = body[:BODY_MAX_LEN]
    title = extract_title(body)
    header = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    status = str(resp.status_code)

    ctx = MatchContext(body, title, header, status, url, session, timeout)

    matched = []
    for product, asts in fingerprints:
        for ast in asts:
            if ast is None:
                continue
            ok, hit_words = _eval_hit_words(ast, ctx)
            if not ok:
                continue
            # 只保留高特异性命中词，过滤 OR 分支里的通用词（如 window.location）
            specific = [(f, kw) for f, kw in hit_words if _is_specific_hit(f, kw)]
            if specific:
                kws = [kw for _, kw in specific[:3]]
                matched.append((product, kws))
            break  # 每产品命中一条即够
    return url, matched


# ════════════════════════════════════════════════════════════════
# 主入口（finger 子命令）
# ════════════════════════════════════════════════════════════════

def scan_finger_run(targets, threads=DEFAULT_THREADS, timeout=TIMEOUT, output_file=None):
    """指纹识别入口（Rich + alive_bar 风格，对齐现有模块）。

    Args:
        targets:     目标 URL 迭代器
        threads:     并发线程数（默认 100）
        timeout:     单请求超时秒数（默认 8）
        output_file: 预留（实际通过 yscan.py TeeWriter 拦截 -o 输出）
    """
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
        return []

    # 加载指纹库
    fingerprints = load_fingerprints()
    stats = _finger_stats

    console.print(Panel.fit(
        f"[accent]目标数[/accent]    [count]{len(urls)}[/count]\n"
        f"[accent]指纹库[/accent]    [count]{stats['products']}[/count] 产品 / [count]{stats['rules']}[/count] 规则\n"
        f"[accent]并发[/accent]      [count]{threads}[/count]",
        title="[header]Web 指纹识别[/header]",
        border_style="dim",
    ))

    if stats["failed"]:
        console.print(f"[dim]解析失败规则 {stats['failed']} 条已跳过[/dim]")

    # mmh3 降级提示
    try:
        import mmh3  # noqa: F401
    except ImportError:
        console.print("[warn]⚠ mmh3 不可用，icon_hash 规则将跳过（安装: pip install mmh3）[/warn]")

    results = []  # [(url, [products])]
    results_lock = threading.Lock()

    with alive_bar(
        len(urls),
        title="指纹识别",
        bar="smooth",
        spinner="dots_waves2",
        enrich_print=False,
        file=sys.__stderr__,
        receipt=True,
        receipt_text="指纹识别完成",
    ) as _bar:
        workers = min(threads, max(1, len(urls)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(identify_url, url, fingerprints, timeout): url for url in urls}
            for fut in as_completed(futures):
                _bar()
                url = futures[fut]
                try:
                    target, matched = fut.result()
                except Exception:
                    continue
                if matched is None:
                    console.print(f"  [fail]✗ {target} 不存活[/fail]")
                    continue
                if matched:
                    with results_lock:
                        results.append((target, matched))
                    console.print(f"  [success]●[/success] [url]{target}[/url]")
                    for prod, kws in matched:
                        kw_str = f" [dim]({' / '.join(kws)})[/dim]" if kws else ""
                        console.print(f"    [highlight]{prod}[/highlight]{kw_str}")
                else:
                    console.print(f"  [dim]○ {target} 未识别[/dim]")

    identified = len(results)
    console.print(f"[info]识别 {identified} / {len(urls)}[/info]")
    return results
