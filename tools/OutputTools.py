#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : OutputTools.py
@Author : moresuo
@Time : 2026/6/28
@脚本说明 : 输出管理器，支持 txt/html 格式持久化扫描结果
"""
import re
import sys
import threading
from datetime import datetime
from pathlib import Path


class TeeWriter:
    """拦截 sys.stdout，同时输出到控制台和文件。

    通过替换 sys.stdout 实现无侵入拦截，所有模块的 print() / console.print() 自动捕获。
    支持两种输出格式：
      - txt:  纯文本，自动去除 ANSI 颜色码（含 Rich 输出）
      - html: 带 GitHub 风格暗色主题的 HTML 报告
    """

    def __init__(self, filepath, file_format=None):
        self._stdout = sys.stdout
        self._lock = threading.Lock()
        self._filepath = filepath
        self._start_time = datetime.now()

        if file_format is None:
            ext = Path(filepath).suffix.lower()
            file_format = 'html' if ext in ('.html', '.htm') else 'txt'
        self._format = file_format

        Path(filepath).parent.mkdir(parents=True, exist_ok=True)

        if self._format == 'html':
            self._buffer = []
        else:
            self._fh = open(filepath, 'w', encoding='utf-8')
            self._write_file(f"YSCAN Scan Report\n"
                             f"Started: {self._start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                             f"{'=' * 60}\n\n")

    # ── stdout 协议 ──────────────────────────────────────────

    def write(self, text):
        with self._lock:
            self._stdout.write(text)
            if self._format == 'txt':
                clean = _strip_ansi(text)
                self._fh.write(clean)
            elif self._format == 'html':
                self._buffer.append(text)

    def flush(self):
        self._stdout.flush()
        if self._format == 'txt' and hasattr(self, '_fh') and self._fh:
            self._fh.flush()

    def reconfigure(self, **kwargs):
        pass

    def fileno(self):
        return self._stdout.fileno()

    def close(self):
        with self._lock:
            if self._format == 'html':
                self._build_html()
            else:
                end_time = datetime.now()
                elapsed = (end_time - self._start_time).total_seconds()
                self._write_file(f"\n{'=' * 60}\n"
                                 f"Finished: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                                 f"Duration: {elapsed:.1f}s\n")
                self._fh.close()

    # ── 内部方法 ────────────────────────────────────────────

    def _write_file(self, text):
        if hasattr(self, '_fh') and self._fh:
            self._fh.write(text)

    def _build_html(self):
        end_time = datetime.now()
        elapsed = (end_time - self._start_time).total_seconds()

        all_text = ''.join(self._buffer)
        lines = all_text.split('\n')

        html_parts = []
        for line in lines:
            clean = _strip_ansi(line)
            if not clean.strip():
                continue

            escaped = _escape_html(clean)
            cls = _classify_line(clean)

            if _is_banner(clean):
                html_parts.append(f'<pre class="{cls}">{escaped}</pre>')
            elif escaped.strip():
                html_parts.append(f'<div class="{cls}">{escaped}</div>')

        html = _HTML_TEMPLATE.format(
            gen_time=end_time.strftime('%Y-%m-%d %H:%M:%S'),
            duration=f'{elapsed:.1f}',
            filepath=_escape_html(self._filepath),
            body='\n'.join(html_parts),
        )

        with open(self._filepath, 'w', encoding='utf-8') as f:
            f.write(html)


# ── 辅助函数 ──────────────────────────────────────────────────

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def _strip_ansi(text):
    return _ANSI_RE.sub('', text)


def _escape_html(text):
    return (text.replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;'))


def _is_banner(text):
    if '%' in text and '(' in text:
        return False
    return '█' in text or '▒' in text or '▓' in text


def _classify_line(line):
    """根据内容关键词返回 CSS 类名。"""
    stripped = line.strip()

    if _is_banner(stripped):
        return 'banner'
    if stripped.startswith('==='):
        return 'divider'

    # 新格式标记：● ✔ ✗ → ✓ ← ─
    # 成功
    if any(kw in line for kw in ('✔', '● ', '写入成功', '反弹成功', '连接成功')):
        return 'success'
    if '存在弱口令' in line:
        return 'success'
    # 失败 / 错误
    if any(kw in line for kw in ('✗',)):
        return 'error'
    if ('未发现' in line and '存活' not in line):
        return 'error'
    if stripped.startswith('[-]'):
        return 'error'
    # 警告 [!]
    if stripped.startswith('[!]') or '未发现任何存活' in line:
        return 'warning'
    # 信息 / 触发
    if any(kw in line for kw in ('→', '▸', '触发', '扫描', '开启', '探测', '目标')):
        return 'info'
    if stripped.startswith('[*]'):
        return 'info'
    # 标题
    if any(kw in line for kw in ('一键扫描', '扫描完成', '扫描完毕', '漏扫完毕',
                                   '端口扫描', '目录扫描', '子域名', '弱口令',
                                   '存活', '扫描汇总')):
        return 'header'
    # 成功 [+]（旧格式兼容）
    if stripped.startswith('[+]'):
        return 'success'
    return 'text'


# ── HTML 模板 ─────────────────────────────────────────────────

_HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>YSCAN Scan Report</title>
<style>
  *, *::before, *::after {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: #0d1117;
    color: #c9d1d9;
    font-family: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', Consolas, monospace;
    font-size: 14px;
    line-height: 1.7;
    padding: 28px 36px;
    max-width: 1300px;
    margin: 0 auto;
  }}
  h1 {{
    color: #f778ba;
    font-size: 26px;
    margin-bottom: 6px;
    border-bottom: 2px solid #30363d;
    padding-bottom: 14px;
  }}
  .meta {{
    color: #8b949e;
    font-size: 13px;
    margin: 10px 0 22px 0;
  }}
  .meta span {{ color: #c9d1d9; }}
  pre.banner {{
    white-space: pre;
    font-family: inherit;
    line-height: 1.15;
    color: #f778ba;
    margin-bottom: 12px;
  }}
  div {{ padding: 1px 0; }}
  .banner {{ color: #f778ba; font-weight: bold; }}
  .success {{ color: #3fb950; }}
  .error  {{ color: #f85149; }}
  .warning {{ color: #d2991d; }}
  .info   {{ color: #58a6ff; }}
  .header {{ color: #f778ba; font-weight: bold; margin-top: 10px; }}
  .text   {{ color: #c9d1d9; }}
  .divider {{
    color: #484f58;
    border-top: 1px solid #21262d;
    margin: 10px 0;
    padding-top: 10px;
  }}
  .footer {{
    margin-top: 28px;
    padding-top: 16px;
    border-top: 2px solid #30363d;
    color: #8b949e;
    font-size: 13px;
  }}
</style>
</head>
<body>

<h1>YSCAN Scan Report</h1>
<div class="meta">
  Generated: <span>{gen_time}</span><br>
  Duration:  <span>{duration}s</span><br>
  File:      <span>{filepath}</span>
</div>

<div class="divider"></div>
{body}
<div class="footer">YSCAN — Report generated at {gen_time}</div>
</body>
</html>'''
