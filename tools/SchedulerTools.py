#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Project : YSCAN
@File : SchedulerTools.py
@Author : moresuo
@Time : 2026/6/28
@脚本说明 : 任务调度工具
"""
import concurrent.futures


#分批提交任务，避免大目标一次性创建大量 Future
#默认 batch_size 取 threads * 8，减少批次等待开销，同时限制队列峰值
def run_batch(tasks, worker, threads=500, batch_size=None, on_progress=None):
    if batch_size is None:
        batch_size = max(threads * 8, 1)

    def done_callback(_future):
        if on_progress:
            on_progress()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for task in tasks:
            future = executor.submit(worker, *task)
            future.add_done_callback(done_callback)
            futures.append(future)
            if len(futures) >= batch_size:
                concurrent.futures.wait(futures)
                futures.clear()

        if futures:
            concurrent.futures.wait(futures)
