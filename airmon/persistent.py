"""QQT 持久化监控模式 — 客户端常驻 + 定期内存扫描

适用场景: 部署到监控机上, qqt.exe 一直开着(手动登录一次),
定时任务只做内存扫描提取节点, 不启动/不关闭客户端。

优势:
  - 只需手动登录一次, 之后客户端自己维护会话(心跳/token刷新)
  - 完全避开"自动登录"问题(不需要UI自动化)
  - 完全避开签名算法(只需要读内存)
  - 客户端断线自动重连, 不需要人工干预

用法:
  首次部署(手动, 一次性):
    1. 安装QQT客户端
    2. 启动 qqt.exe, 手动登录
    3. 确认连接成功(有节点可选)

  之后(自动化):
    python run.py scan-persistent --airport quqiuquan
    (加入定时任务, 每3小时跑一次)

  或者直接用现有的 all 命令(已集成):
    python run.py all
"""
from __future__ import annotations

import subprocess
import time
import os

from .models import Node, Snapshot
from . import store
from .memsan import find_pids, scan_process_memory, extract_nodes


def find_qqt_pid() -> int | None:
    """查找正在运行的qqt.exe进程, 返回PID。"""
    pids = find_pids(["QQT"])
    for name, pid in pids:
        if name.lower() == "qqt.exe":
            return pid
    return None


def is_qqt_logged_in(pid: int) -> bool:
    """检查qqt.exe是否已登录(内存中有真实节点而非只有backendapi域名)。"""
    result = scan_process_memory(pid)
    if "error" in result:
        return False
    items = result.get("found_items", [])
    # 未登录时只有4个backendapi域名(约13个items)
    # 登录后节点+伪装域名大量出现(2000+ items)
    return len(items) > 100


def scan_persistent(slug: str = "quqiuquan", detector=None) -> Snapshot | None:
    """持久化扫描: 假设客户端已运行且已登录, 直接扫内存提取节点。

    不启动/不关闭客户端。
    返回Snapshot或None(如果客户端未运行或未登录)。
    """
    pid = find_qqt_pid()
    if not pid:
        print("  [persistent] qqt.exe 未运行 — 请手动启动并登录")
        return None

    # 快速检查是否已登录
    if not is_qqt_logged_in(pid):
        print("  [persistent] qqt.exe 在运行但似乎未登录(内存条目过少)")
        print("  [persistent] 请手动在QQT客户端中登录一次")
        return None

    print(f"  [persistent] qqt.exe PID={pid}, 已登录, 开始扫描...")
    result = scan_process_memory(pid)
    if "error" in result:
        print(f"  [persistent] 扫描失败: {result['error']}")
        return None

    items = result.get("found_items", [])
    nodes = extract_nodes(items)

    # 去重
    seen = {}
    for n in nodes:
        key = n.key()
        if key not in seen:
            seen[key] = n
    nodes = list(seen.values())

    if not nodes:
        print("  [persistent] 内存中未提取到节点(可能未连接)")
        return None

    snap = Snapshot(
        airport=slug,
        ts=store.now_iso(),
        source=f"persistent_scan:pid{pid}",
        nodes=nodes,
        meta={"pid": pid, "items": len(items),
              "process": "qqt.exe",
              "mode": "persistent"},
    )

    if detector and nodes:
        from .collect import _enrich_and_detect
        snap.findings = _enrich_and_detect(slug, nodes, detector)

    print(f"  [persistent] ✓ {len(nodes)}节点提取成功")
    return snap
