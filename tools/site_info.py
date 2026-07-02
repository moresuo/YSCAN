#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : site_info.py
@Author : moresuo
@Time : 2026/7/1
@脚本说明 : 站点资产权重查询（爬虫，爱站数据源）

从爱站网爬取域名的 SEO 权重、ICP 备案、站点标题等信息。多维度反爬：
curl_cffi Chrome 指纹 + 完整浏览器头 + 多 UA 轮换 + 随机延迟 +
Session Cookie 复用 + 指数退避重试 + 代理支持 + 风控页面检测。
仅用于授权安全研究的信息收集阶段。
"""
import random
import time
import warnings

from curl_cffi import requests
from bs4 import BeautifulSoup

from tools.color import console

warnings.filterwarnings("ignore")

# 请求失败重试次数（风控验证码重试无意义，控制在 3 次内快速失败）
MAX_RETRIES = 3
# 重试基础间隔（秒），指数退避：2, 4, 8（封顶 10s，避免用户久等）
RETRY_BASE_INTERVAL = 2
RETRY_MAX_INTERVAL = 10
# 重试前随机延迟范围（秒），打破固定请求节奏（首次请求不延迟）
REQ_DELAY_RANGE = (1.0, 2.0)
# 连通性预检超时（秒）——代理不可达时快速失败，不进重试
PROBE_TIMEOUT = 5

# 多 User-Agent 轮换池（均为 Chrome），避免单一 UA 被风控
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
]

# 风控/反爬页面特征关键词（精确短语，避免误伤正常页面）
# 注意：爱站正常页面会预加载 aliyunCaptcha.js，不能仅凭 "captcha" 判定
BLOCK_KEYWORDS = ["访问过于频繁", "请输入验证码", "人机验证", "安全验证", "请完成验证"]


def _build_headers(domain):
    """构造完整浏览器请求头，模拟真实 Chrome 流量。

    补全 Accept / Accept-Language / Referer / Sec-Fetch-* 等字段，
    单纯 UA 容易被指纹识别，完整头更像真实浏览器。
    """
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        # Referer 伪装从爱站首页进入，降低直链访问风控概率
        "Referer": f"https://www.aizhan.com/",
        "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }


def _is_blocked(html):
    """检测响应是否为风控/验证码页面。"""
    if not html:
        return False
    # 风控页通常很短（<1KB 验证码页），正常查询页远大于此
    if len(html) < 1000:
        return True
    lower = html.lower()
    return any(kw.lower() in lower for kw in BLOCK_KEYWORDS)


def _check_reachable(proxy=None):
    """连通性预检：快速探测爱站是否可达（含代理可用性）。

    代理不可用或爱站不可达时短超时快速失败，避免后续重试白白等待。
    返回 (reachable: bool, reason: str)。
    """
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        resp = requests.get(
            "https://www.aizhan.com/",
            headers=_build_headers(""),
            timeout=PROBE_TIMEOUT,
            impersonate="chrome120",
            proxies=proxies,
        )
        if resp.status_code >= 500:
            return False, f"爱站服务异常（HTTP {resp.status_code}）"
        return True, ""
    except Exception as e:
        msg = str(e)
        if proxy:
            return False, f"代理不可达：{msg[:80]}"
        return False, f"爱站不可达：{msg[:80]}"


def _fetch_html(domain, proxy=None):
    """带反爬策略地抓取爱站查询页，返回 HTML 文本或 None。

    速度优先策略：
      - 连通性预检：代理/网络不可达立即失败，不进重试
      - 首次请求不延迟，仅重试前随机延迟
      - 风控验证码页立即终止（重试无意义），不退避
      - 仅偶发连接重置才退避重试（3 次，封顶 10s）
    """
    url = f"https://www.aizhan.com/cha/{domain}/"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    # Session 复用 Cookie，模拟浏览器会话
    session = requests.Session()
    for attempt in range(MAX_RETRIES):
        # 首次请求不延迟，仅重试前随机延迟（避免高频，又不让用户白等）
        if attempt > 0:
            time.sleep(random.uniform(*REQ_DELAY_RANGE))
        try:
            resp = session.get(
                url,
                headers=_build_headers(domain),
                timeout=10,
                impersonate="chrome120",
                proxies=proxies,
            )
            if resp.status_code == 200:
                html = resp.text
                if _is_blocked(html):
                    # 风控验证码页：重试也过不了，立即终止
                    console.print(f"[warn]⚠ 触发风控/验证码，停止重试（请稍后再查或更换代理 -x）[/warn]")
                    return None
                return html
            elif resp.status_code in (403, 429):
                # 限流：重试一次可能恢复，继续退避
                console.print(f"[warn]⚠ 被限流（HTTP {resp.status_code}），退避重试...[/warn]")
        except Exception:
            # 偶发连接重置：退避重试可能恢复
            if attempt < MAX_RETRIES - 1:
                console.print(f"[warn]⚠ 连接异常，退避重试（第 {attempt + 1} 次）...[/warn]")
        # 指数退避：仅对可恢复异常重试（封顶 RETRY_MAX_INTERVAL）
        backoff = min(RETRY_BASE_INTERVAL * (2 ** attempt), RETRY_MAX_INTERVAL) + random.uniform(0, 1)
        time.sleep(backoff)
    return None


def _select_text(soup, selector, attr=None):
    """容错取值：选择器命中则返回文本/属性值，未命中返回 None。

    每个字段独立解析，避免单字段缺失导致整体失败。
    """
    try:
        els = soup.select(selector)
        if not els:
            return None
        if attr:
            return els[0].get(attr)
        return els[0].text.strip()
    except Exception:
        return None


def get_host_info(domain, proxy=None):
    """查询域名资产信息，返回 dict 或 None。

    返回结构：
      {
        "title": 站点标题,
        "weights": {baidu, mobile, sogou, x360, bing, toutiao, google},
        "icp": {icp_number, nature, name, audit_time}
      }
    """
    html = _fetch_html(domain, proxy=proxy)
    if not html:
        return None

    soup = BeautifulSoup(html, "html.parser")

    # 权重字段：img alt 属性表示权重值（0-10）
    weights = {
        "百度权重": _select_text(soup, "#baidurank_br > img", "alt"),
        "移动权重": _select_text(soup, "#baidurank_mbr > img", "alt"),
        "搜狗权重": _select_text(soup, "#sogou_pr > img", "alt"),
        # ID 以数字开头，select() 解析报错，改用属性选择器
        "360权重": _select_text(soup, '[id="360_pr"] > img', "alt"),
        "必应权重": _select_text(soup, "#bing_pr > img", "alt"),
        "头条权重": _select_text(soup, "#toutiao_pr > img", "alt"),
        "谷歌权重": _select_text(soup, "#google_pr > img", "alt"),
    }

    # ICP 备案信息
    icp = {
        "备案号": _select_text(soup, "#icp > li > a"),
        "备案地址": _select_text(soup, "#icp > li > a", "href"),
        "性质": _select_text(soup, "#icp_type"),
        "公司名称": _select_text(soup, "#icp_company"),
        "审核时间": _select_text(soup, "#icp_passtime"),
    }

    title = _select_text(soup, "#webpage_title")

    return {"title": title, "weights": weights, "icp": icp}


def scan_site_info_run(domain, proxy=None):
    """查询并展示域名资产信息（Rich 表格输出）。"""
    from rich.panel import Panel
    from rich.table import Table

    console.print(Panel.fit(
        f"[accent]目标域名[/accent]  [host]{domain}[/host]",
        title="[header]站点资产权重查询[/header]",
        border_style="dim",
    ))

    # ── 连通性预检：代理/网络不可达立即失败，不让用户等完整重试周期 ──
    reachable, reason = _check_reachable(proxy=proxy)
    if not reachable:
        console.print(f"[fail]✗ 无法爬取数据[/fail] [dim]（{reason}）[/dim]")
        return

    info = get_host_info(domain, proxy=proxy)
    if not info:
        console.print(f"[fail]✗ 查询失败[/fail] [dim]（页面抓取失败或被反爬拦截，请稍后重试或更换代理 -x）[/dim]")
        return

    # ── 基本信息 ──
    title = info["title"] or "-"
    console.print(f"[info]站点标题[/info]  [highlight]{title}[/highlight]")

    # ── SEO 权重表 ──
    w_table = Table(title="SEO 权重", border_style="dim", show_header=True, header_style="header")
    w_table.add_column("搜索引擎", style="accent")
    w_table.add_column("权重", justify="center", style="highlight")
    for engine, value in info["weights"].items():
        w_table.add_row(engine, value if value else "-")
    console.print(w_table)

    # ── ICP 备案表 ──
    icp_table = Table(title="ICP 备案信息", border_style="dim", show_header=True, header_style="header")
    icp_table.add_column("项目", style="accent")
    icp_table.add_column("内容", style="highlight")
    for key, value in info["icp"].items():
        icp_table.add_row(key, value if value else "-")
    console.print(icp_table)
