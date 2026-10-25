"""告警输出。阶段1：控制台 + 追加到 data/alerts.log。TG/邮件后续接。"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from .models import Finding
from .store import DATA_DIR, list_snapshots, _ts_of

ALERT_LOG = os.path.join(DATA_DIR, "alerts.log")


def emit(airport: str, findings: list[Finding], changes: dict | None = None):
    """把华为命中 + 变更打到控制台并落盘。

    判空严格化（P0 修复）：findings 为空且 changes 无实际增删时**不写任何块**。
    此前 diff_latest 恒返回 dict，这里 `not changes` 永假，
    导致 alerts.log 里 83.9% 都是只有头行的空块。"""
    from .detect import HW_DIMS

    hw = [f for f in findings if f.dimension in HW_DIMS]
    fr = [f for f in findings if f.dimension == "fronting"]
    has_changes = bool(changes and (changes.get("added") or changes.get("removed")))
    if not hw and not fr and not has_changes:
        return
    os.makedirs(DATA_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [f"===== {ts} | {airport} ====="]
    if hw:
        lines.append(f"华为关联命中 {len(hw)} 条：")
        lines += ["  " + f.line() for f in hw]
    if fr:
        lines.append(f"大厂域前置 {len(fr)} 条（不算华为云，单列）：")
        lines += ["  " + f.line() for f in fr]
    if has_changes:
        if changes.get("added"):
            lines.append(f"新增节点 {len(changes['added'])} 个")
        if changes.get("removed"):
            lines.append(f"消失节点 {len(changes['removed'])} 个")
    block = "\n".join(lines)
    print(block)
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(block + "\n")


def stale_report(max_hours: float = 6.0, airports: list[str] | None = None) -> list[str]:
    """陈旧度巡检：data/<airport>/ 最新快照超 max_hours 的机场列表。

    在 cmd_all 收尾调用一次（告警侧与仪表盘 status=stale 同口径 6h）。
    只在确有陈旧机场时写一块告警，避免新的空块。返回陈旧 slug 列表。"""
    import glob as _glob
    stale = []
    if airports is None:
        root = os.path.join(DATA_DIR, "*")
        airports = sorted(p for p in _glob.glob(root) if os.path.isdir(p))
    now = datetime.now(timezone.utc).timestamp()
    for slug in airports:
        snaps = list_snapshots(slug)
        ts = _ts_of(snaps[-1]) if snaps else None
        if ts is None:
            continue  # 没有合法快照的目录不误报（如 quota/sitewatch 等数据目录）
        if (now - ts) / 3600 > max_hours:
            stale.append(f"{slug} 最近快照 {(now - ts) / 3600:.1f}h 前")
    if stale:
        ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines = [f"===== {ts_str} | 陈旧度告警 ====="]
        lines.append(f"以下 {len(stale)} 个机场超过 {max_hours:.0f}h 无新快照：")
        lines += ["  " + s for s in stale]
        block = "\n".join(lines)
        print(block)
        with open(ALERT_LOG, "a", encoding="utf-8") as f:
            f.write(block + "\n")
    return stale
