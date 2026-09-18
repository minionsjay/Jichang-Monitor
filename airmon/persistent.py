"""持久化监控模式 — 客户端常驻 + 定期内存扫描(通用版)

适用场景: 部署到监控机上, 客户端一直开着(手动登录/连接一次),
定时任务只做内存扫描提取节点, 不启动/不关闭客户端。

支持任意客户端: QQT / LetsVPN / 未来的其他客户端。
进程名从 YAML 的 client.core_process 读取。

优势:
  - 只需手动操作一次, 之后客户端自己维护会话
  - 完全避开"自动登录"问题
  - 客户端断线自动重连, 不需要人工干预

用法(已集成到 run.py all):
  YAML配置:
    client:
      core_process: QQT          # 进程名(必填)
      persistent: true            # 启用持久化模式(必填)
      keep_alive: true            # 扫完不关闭(推荐)
"""
from __future__ import annotations

from .models import Node, Snapshot
from . import store
from .memsan import find_pids, scan_process_memory, extract_nodes


def find_process_pid(process_name: str) -> int | None:
    """按进程名查找PID。"""
    pids = find_pids([process_name])
    for name, pid in pids:
        if name.lower() == f"{process_name}.exe".lower():
            return pid
    return None


def is_connected(pid: int) -> bool:
    """检查进程是否已连接VPN(内存条目多=有真实流量)。"""
    result = scan_process_memory(pid)
    if "error" in result:
        return False
    items = result.get("found_items", [])
    # 未连接时只有少量API/DNS条目(<50)
    # 连接后节点+流量数据大量出现(500+)
    return len(items) > 100


def scan_persistent(slug: str, detector=None,
                    process_name: str = "QQT") -> Snapshot | None:
    """持久化扫描: 客户端已运行且已连接, 直接扫内存提取节点。

    不启动/不关闭客户端。
    返回Snapshot或None。
    """
    pid = find_process_pid(process_name)
    if not pid:
        print(f"  [persistent] {process_name}.exe 未运行 — 请手动启动")
        return None

    print(f"  [persistent] {process_name}.exe PID={pid}, 开始扫描...")
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
        print(f"  [persistent] 内存中未提取到节点(可能未连接VPN)")
        return None

    snap = Snapshot(
        airport=slug,
        ts=store.now_iso(),
        source=f"persistent_scan:{process_name}:pid{pid}",
        nodes=nodes,
        meta={"pid": pid, "items": len(items),
              "process": f"{process_name}.exe",
              "mode": "persistent"},
    )

    if detector and nodes:
        from .collect import _enrich_and_detect
        snap.findings = _enrich_and_detect(slug, nodes, detector)

    print(f"  [persistent] ✓ {len(nodes)}节点提取成功")
    return snap
