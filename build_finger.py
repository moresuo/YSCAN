#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
指纹库合并脚本：多源拉取 -> 统一格式 -> 去重 -> 更新 libs/finger.yaml

数据源（格式统一到 fofa 表达式语法 body="x" && title="y"）：
  1. FingerprintHub  web_fingerprint_v4.json  （3290 条 nuclei 模板）
     - 优先取 metadata.fofa-query（已是表达式）
     - 无 fofa-query 时从 http.matchers 转换（word/regex/status -> 表达式）
  2. EASY233/Finger  library/finger.json      （goby 格式，转换）
  3. 现有 libs/finger.yaml                    （保留合并）

任一源拉取失败不影响其他源。可重复运行：python build_finger.py
"""
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

import yaml

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROJECT_DIR = Path(__file__).resolve().parent
FINGER_YAML = PROJECT_DIR / "libs" / "finger.yaml"

# jsdelivr CDN 镜像（绕过 GitHub raw 429 限流）
FPHUB_V4_JSON = "https://cdn.jsdelivr.net/gh/0x727/FingerprintHub@main/web_fingerprint_v4.json"
EASY_FINGER_JSON = "https://cdn.jsdelivr.net/gh/EASY233/Finger@main/library/finger.json"

RAW_MAX_RETRIES = 3
RAW_RETRY_DELAY = 3


def info(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def ok(msg):
    print(f"[OK] {msg}")


def http_download(url, max_retries=RAW_MAX_RETRIES):
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "YSCAN-finger-merger/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read()
        except Exception as e:
            if attempt < max_retries - 1:
                wait = RAW_RETRY_DELAY * (attempt + 1)
                warn(f"下载失败({e}), {wait}s 后重试 ({attempt + 1}/{max_retries})")
                time.sleep(wait)
            else:
                raise


def add_rule(merged, product, rule):
    if not product or not rule:
        return
    # 清洗控制字符（换行等会导致 YAML key 跨行 / 规则 block 样式解析失败）
    product = re.sub(r"[\x00-\x1f\x7f]", " ", str(product)).strip()
    rule = re.sub(r"[\x00-\x1f\x7f]", " ", str(rule)).strip()
    if not product or not rule:
        return
    merged.setdefault(product, set()).add(rule)


# ── nuclei matcher -> fofa 表达式转换 ─────────────────────────────
# nuclei part 字段映射到 fofa 字段
NUCLEI_PART_MAP = {
    "body": "body",
    "header": "header",
    "all": "body",
    "title": "title",
    "server": "header",
    "banner": "banner",
    "cert": "cert",
}


def _esc_q(s):
    """转义 fofa 表达式值中的双引号。"""
    return str(s).replace('"', '\\"')


def matcher_to_expr(m):
    """单个 nuclei matcher 转 fofa 表达式片段，失败返回 None。"""
    mtype = m.get("type", "")
    part = m.get("part", "body")
    if isinstance(part, list):
        part = part[0] if part else "body"
    field = NUCLEI_PART_MAP.get(part, "body")
    negative = m.get("negative", False)
    op = "!=" if negative else "="

    if mtype == "word":
        words = m.get("words", [])
        cond = m.get("condition", "or")
        parts = [f'{field}{op}"{_esc_q(w)}"' for w in words if w]
        if not parts:
            return None
        joiner = " && " if cond == "and" else " || "
        expr = joiner.join(parts)
        return f"({expr})" if len(parts) > 1 else expr

    if mtype == "regex":
        regexs = m.get("regex", m.get("regexes", []))
        # regex 用 ~= ; negative regex 无直接对应，降级为不含
        rop = "~=" if not negative else "!="
        parts = [f'{field}{rop}"{_esc_q(r)}"' for r in regexs if r]
        if not parts:
            return None
        return " || ".join(parts) if len(parts) > 1 else parts[0]

    if mtype == "status":
        statuses = m.get("status", [])
        parts = [f'status="{s}"' for s in statuses if s]
        if not parts:
            return None
        return " || ".join(parts) if len(parts) > 1 else parts[0]

    return None


def http_entry_to_expr(http_entry):
    """单个 http 请求的 matchers 列表转表达式（多 matcher 默认 AND）。"""
    matchers = http_entry.get("matchers", [])
    exprs = []
    for m in matchers:
        e = matcher_to_expr(m)
        if e:
            exprs.append(e)
    if not exprs:
        return None
    return " && ".join(exprs) if len(exprs) > 1 else exprs[0]


# ── 源 1：FingerprintHub v4.json ─────────────────────────────────
def fetch_fphub_v4(merged):
    try:
        raw = http_download(FPHUB_V4_JSON)
        data = json.loads(raw)
    except Exception as e:
        warn(f"v4.json 拉取失败: {e}")
        return

    count_fofa = 0
    count_matcher = 0
    for item in data:
        info_obj = item.get("info", {})
        meta = info_obj.get("metadata", {})
        product = meta.get("product") or info_obj.get("name") or item.get("id")

        # 优先用 fofa-query（已是表达式，最准确）
        queries = meta.get("fofa-query")
        if queries:
            if isinstance(queries, str):
                queries = [queries]
            for q in queries:
                if any(op in q for op in ("=", "~=")):
                    add_rule(merged, product, q)
                    count_fofa += 1
            continue  # 有 fofa-query 则不再转换 matchers

        # 无 fofa-query 时从 http.matchers 转换
        http_entries = item.get("http", [])
        if not http_entries:
            continue
        # 取第一个 http entry 的表达式（多请求时合并较复杂，取首个避免噪声）
        expr = http_entry_to_expr(http_entries[0])
        if expr:
            add_rule(merged, product, expr)
            count_matcher += 1

    ok(f"FingerprintHub v4.json: fofa-query {count_fofa} 条 + matchers 转换 {count_matcher} 条")


# ── 源 2：EASY233/Finger goby 格式 ───────────────────────────────
GOPY_LOC_MAP = {
    "body": "body",
    "header": "header",
    "title": "title",
    "server": "header",
    "cert": "cert",
    "banner": "banner",
}


def goby_rule_to_expr(item):
    method = item.get("method", "")
    location = item.get("location", "")
    keywords = item.get("keyword", [])
    if not keywords:
        return None

    if method == "faviconhash" or location == "faviconhash":
        return f'icon_hash="{keywords[0]}"'

    field = GOPY_LOC_MAP.get(location)
    if not field:
        return None

    parts = []
    for kw in keywords:
        if not isinstance(kw, str) or not kw.strip():
            continue
        kw_esc = kw.replace('"', '\\"')
        parts.append(f'{field}="{kw_esc}"')
    if not parts:
        return None
    return " || ".join(parts)


def fetch_easy_finger(merged):
    try:
        raw = http_download(EASY_FINGER_JSON)
        data = json.loads(raw)
    except Exception as e:
        warn(f"EASY233/Finger 拉取失败: {e}")
        return

    entries = data.get("fingerprint", []) if isinstance(data, dict) else data
    count = 0
    for item in entries:
        product = item.get("cms") or item.get("name")
        expr = goby_rule_to_expr(item)
        if product and expr:
            add_rule(merged, product, expr)
            count += 1
    ok(f"EASY233/Finger: {count} 条规则")


# ── 源 0：保留现有 libs/finger.yaml ───────────────────────────────
def load_existing(merged):
    if not FINGER_YAML.exists():
        return
    try:
        with open(FINGER_YAML, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return
        count = 0
        for product, rules in data.items():
            if not isinstance(rules, list):
                continue
            for rule in rules:
                if isinstance(rule, str):
                    add_rule(merged, product, rule)
                    count += 1
        ok(f"现有 finger.yaml: {count} 条规则")
    except Exception as e:
        warn(f"读取现有 finger.yaml 失败: {e}")


# ── 输出：yaml.safe_dump 整体输出，自动正确转义所有标量 ─────────
def write_merged(merged):
    FINGER_YAML.parent.mkdir(parents=True, exist_ok=True)
    ordered = {}
    for product in sorted(merged.keys(), key=lambda s: s.lower()):
        ordered[product] = sorted(merged[product])

    # yaml.safe_dump 自动处理所有标量转义（引号/反斜杠/冒号/特殊字符）
    # width=99999 禁止长行折行（否则规则在 && 处折行会导致 YAML 解析失败）
    content = yaml.safe_dump(
        ordered, allow_unicode=True, sort_keys=False,
        default_flow_style=False, indent=2, width=99999,
    )
    # PyYAML 序列项默认顶格，后处理为 2 空格缩进以对齐原始 finger.yaml 格式
    content = re.sub(r"(?m)^(- )", r"  \1", content)

    # 原子写入：先校验内容可解析，再写临时文件替换，避免破坏现有库
    try:
        yaml.safe_load(content)
    except yaml.YAMLError as e:
        warn(f"生成内容 YAML 校验失败，放弃写入: {e}")
        # 打印问题行附近辅助定位
        if hasattr(e, "problem_mark") and e.problem_mark:
            ln = e.problem_mark.line
            cl = content.splitlines()
            lo, hi = max(0, ln - 2), min(len(cl), ln + 3)
            for i in range(lo, hi):
                mark = ">>>" if i == ln else "   "
                print(f"  {mark} {i + 1}: {cl[i]}")
        return 0, 0

    tmp_path = str(FINGER_YAML) + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
    import os
    os.replace(tmp_path, str(FINGER_YAML))

    return len(ordered), sum(len(r) for r in ordered.values())


def main():
    print("=" * 60)
    print("YSCAN 指纹库合并")
    print("=" * 60)

    merged = {}

    info("加载现有 libs/finger.yaml ...")
    load_existing(merged)

    info("拉取 FingerprintHub v4.json ...")
    fetch_fphub_v4(merged)

    info("拉取 EASY233/Finger goby 指纹 ...")
    fetch_easy_finger(merged)

    info("合并去重并写入 libs/finger.yaml ...")
    product_count, rule_count = write_merged(merged)

    # 验证写入后可被 yaml.safe_load 解析
    try:
        with open(FINGER_YAML, "r", encoding="utf-8") as f:
            yaml.safe_load(f)
    except Exception as e:
        warn(f"输出文件 YAML 校验失败: {e}")

    print()
    ok(f"合并完成: {product_count} 个产品, {rule_count} 条规则")
    ok(f"输出: {FINGER_YAML}")
    size_kb = FINGER_YAML.stat().st_size / 1024
    print(f"    文件大小: {size_kb:.1f} KB")


if __name__ == "__main__":
    main()
