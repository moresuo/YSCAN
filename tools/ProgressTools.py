#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : ProgressTools.py
@Author : moresuo
@Time : 2026/6/28
@脚本说明 : 进度条工具
"""
import sys
import threading

from alive_progress import alive_bar


#弱口令爆破进度条
class BurteProgress:
    def __init__(self, total, title="弱口令爆破"):
        self.total = total
        self.title = title
        self._bar = None
        self._lock = threading.Lock()

    def __enter__(self):
        self._context = alive_bar(
            self.total,
            title=self.title,
            bar="smooth",
            spinner="dots_waves2",
            enrich_print=False,
            file=sys.__stderr__,
            receipt=True,
            receipt_text=f"{self.title}完成",
        )
        self._bar = self._context.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._context.__exit__(exc_type, exc, tb)

    def update(self):
        if self._bar:
            with self._lock:
                self._bar()
