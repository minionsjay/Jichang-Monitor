"""告警输出。阶段1：控制台 + 追加到 data/alerts.log。TG/邮件后续接。"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from .models import Finding
from .store import DATA_DIR

ALERT_LOG = os.path.join(DATA_DIR, "alerts.log")


def emit(airport: str, findings: list[Finding], changes: dict | None = None):
    """把华为命中 + 变更打到控制台并落盘。"""
    if not findings and not changes:
        return
    os.makedirs(DATA_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [f"===== {ts} | {airport} ====="]
    if findings:
        lines.append(f"华为关联命中 {len(findings)} 条：")
        lines += ["  " + f.line() for f in findings]
    if changes:
        if changes.get("added"):
            lines.append(f"新增节点 {len(changes['added'])} 个")
        if changes.get("removed"):
            lines.append(f"消失节点 {len(changes['removed'])} 个")
    block = "\n".join(lines)
    print(block)
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(block + "\n")
