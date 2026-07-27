"""对已抓到的快照重新富化 + 重跑华为检测（离线，不用再登录）。

用途：批量 pull 时 RDAP 被限流，很多落地 IP 停在 n/a。rescan 温和地（低并发+退避）
把这些没分类的 IP 补查出来，重算华为命中，写一份新快照。
"""
from __future__ import annotations

import glob
import time

from . import store
from .detect import Detector
from .enrich import resolve, rdap
from .models import Node, Snapshot


def _needs_rdap(info) -> bool:
    return (not info) or (info[0] or "").startswith("n/a") or info[0] == ""


def rescan_airport(slug: str, detector: Detector, gentle: float = 0.3) -> Snapshot | None:
    """读该机场最新快照 → 补解析/补 RDAP 未分类 IP → 重跑检测 → 存新快照。"""
    snaps = store.list_snapshots(slug)
    if not snaps:
        return None
    prev = store.load(snaps[-1])
    nodes = [Node(**{k: n[k] for k in ("name", "protocol", "server", "port", "raw")})
             for n in prev["nodes"]]

    # 汇总需要（重新）RDAP 的 IP
    todo = set()
    for n in nodes:
        ips = n.raw.get("_resolved_ips")
        if not ips:                       # 之前没解析到，补解析一次
            ips = resolve(n.server)
            n.raw["_resolved_ips"] = ips
        rd = n.raw.get("_rdap") or {}
        for ip in ips:
            if _needs_rdap(rd.get(ip)):
                todo.add(ip)

    # 低并发 + 间隔，逐个补查（rdap 内部已带 429 退避；成功会进缓存）
    fixed = {}
    for ip in sorted(todo):
        info = rdap(ip)
        fixed[ip] = info
        if not (info[0] or "").startswith("n/a"):
            pass
        time.sleep(gentle)

    # 回填 + 重跑检测
    rdap_map = {}
    for n in nodes:
        rd = dict(n.raw.get("_rdap") or {})
        for ip in n.raw.get("_resolved_ips", []):
            if ip in fixed:
                rd[ip] = fixed[ip]
            if rd.get(ip):
                rdap_map[ip] = rd[ip]
        n.raw["_rdap"] = rd

    findings = detector.scan_nodes(slug, nodes, rdap_map)
    snap = Snapshot(airport=slug, ts=store.now_iso(),
                    source=prev.get("source", "") + " (rescan)",
                    nodes=nodes, findings=findings, meta=prev.get("meta", {}))
    return snap


def unresolved_stats(slug: str) -> tuple[int, int, int]:
    """返回该机场最新快照 (节点数, 有IP的节点数, 仍未分类IP数)。"""
    snaps = store.list_snapshots(slug)
    if not snaps:
        return (0, 0, 0)
    s = store.load(snaps[-1])
    have = unclassified = 0
    for n in s["nodes"]:
        ips = n["raw"].get("_resolved_ips") or []
        if ips:
            have += 1
        rd = n["raw"].get("_rdap") or {}
        for ip in ips:
            if _needs_rdap(rd.get(ip)):
                unclassified += 1
    return (len(s["nodes"]), have, unclassified)
