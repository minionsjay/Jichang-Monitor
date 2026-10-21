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
    nodes_data = prev.get("nodes", [])
    if not nodes_data:
        return None  # 0节点快照，不需要rescan
    nodes = [Node(**{k: n[k] for k in ("name", "protocol", "server", "port", "raw")})
             for n in nodes_data]

    # 汇总需要（重新）RDAP 的 IP
    # 同时记录"这一轮到底有没有真的补到东西"，没有就不写新快照（见文件末尾说明）
    todo = set()
    newly_resolved = 0
    for n in nodes:
        ips = n.raw.get("_resolved_ips")
        if not ips:                       # 之前没解析到，补解析一次
            ips = resolve(n.server)
            n.raw["_resolved_ips"] = ips
            if ips:
                newly_resolved += 1
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
    newly_fixed = 0
    for n in nodes:
        rd = dict(n.raw.get("_rdap") or {})
        for ip in n.raw.get("_resolved_ips", []):
            if ip in fixed:
                rd[ip] = fixed[ip]
            if rd.get(ip):
                rdap_map[ip] = rd[ip]
        n.raw["_rdap"] = rd
    for ip, info in fixed.items():
        if info and not _needs_rdap(info):
            newly_fixed += 1

    findings = detector.scan_nodes(slug, nodes, rdap_map)

    # ---- 有实际进展才写新快照 ----
    # 历史行为：不管有没有补到东西，每轮都 save 一份 ts=now 的新快照。
    # 后果：本轮拉取失败的机场，rescan 用旧数据"重写"了一份带当前时间戳的快照，
    # 使"最新快照很新鲜"这个陈旧度判据把它们判成健康（false green），
    # 同时每轮白增 40 份重复快照（data/ 已 2.2GB）。
    # 现在：只有真的补解析到 IP / 真的补到 RDAP 归属 / 检测结果变了，才落盘。
    prev_findings = prev.get("findings", [])
    if not (newly_resolved or newly_fixed) and findings == prev_findings:
        return None

    meta = dict(prev.get("meta", {}))
    meta["rescanned_at"] = store.now_iso()
    # 关键：rescan 是"给同一份采集结果补 RDAP"，不是一次新的采集。
    # 因此沿用原始快照的 ts（文件按 ts 命名 → 原地覆盖），不把采集时间刷成现在。
    # 否则陈旧度判据会把好几天前抓的数据当成"刚更新"。
    src = str(prev.get("source", "")).replace(" (rescan)", "").strip()
    snap = Snapshot(airport=slug, ts=prev.get("ts") or store.now_iso(),
                    source=(src + " (rescan)").strip(),
                    nodes=nodes, findings=findings, meta=meta)
    return snap


def unresolved_stats(slug: str) -> tuple[int, int, int]:
    """返回该机场最新快照 (节点数, 有IP的节点数, 仍未分类IP数)。"""
    snaps = store.list_snapshots(slug)
    if not snaps:
        return (0, 0, 0)
    s = store.load(snaps[-1])
    nodes = s.get("nodes", [])
    if not nodes:
        return (0, 0, 0)
    have = unclassified = 0
    for n in nodes:
        ips = n["raw"].get("_resolved_ips") or []
        if ips:
            have += 1
        rd = n["raw"].get("_rdap") or {}
        for ip in ips:
            if _needs_rdap(rd.get(ip)):
                unclassified += 1
    return (len(s["nodes"]), have, unclassified)
