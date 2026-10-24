"""快照存储 + 历史 diff。每次采集落一份 JSON 到 data/<airport>/<ts>.json。"""
from __future__ import annotations

import glob
import json
import os
from datetime import datetime, timezone

from . import snapnames
from .models import Snapshot, Node

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(_HERE, "data")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def save(snap: Snapshot) -> str:
    """原子写：先写 .tmp 再 os.replace，避免写一半崩溃/并发读到半份 JSON。"""
    d = os.path.join(DATA_DIR, snap.airport)
    os.makedirs(d, exist_ok=True)
    # 文件名用**本地时间** 20261024-212028.json（见 airmon/snapnames.py）：
    # 以前是 UTC 的 20261024T132028Z.json，肉眼看像随机串，其实是 8 小时前的 UTC。
    try:
        _when = datetime.fromisoformat(snap.ts.replace("Z", "+00:00"))
    except ValueError:
        _when = datetime.now()
    path = os.path.join(d, f"{snapnames.fmt(_when)}.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(snap.to_dict(), f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return path


def list_snapshots(airport: str) -> list[str]:
    if not airport:
        return []
    d = os.path.join(DATA_DIR, airport)
    # 新旧两种命名混存（20261024T132028Z.json / 20261024-212028.json），
    # 纯字符串排序会把新格式整体排到旧格式后面 —— 必须按解析出的时间排。
    return snapnames.paths(d, reverse=False)


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _ts_of(path: str) -> float | None:
    """从快照文件名解析 epoch（兼容 UTC 旧名与本地时间新名）；非法名返回 None。"""
    e = snapnames.epoch(os.path.basename(path))
    return None if e == float("-inf") else e


def diff_latest(airport: str, min_gap_hours: float = 2.0) -> dict | None:
    """对比最近两次**跨轮**快照，返回 {added, removed, prev, cur}。

    修复两个历史问题：
    1. 同轮 pull+rescan 双写会让「最近两份」是同一轮的两份数据（假 diff）——
       现在只和间隔 ≥min_gap_hours（默认 2h，轮询周期 3h）的最近一份比较；
    2. 无变化时返回 None（此前恒返回 dict，配合 alert 判空不严产生了海量空告警块）。"""
    snaps = list_snapshots(airport)
    if len(snaps) < 2:
        return None
    cur_path = snaps[-1]
    cur_ts = _ts_of(cur_path)
    if cur_ts is None:
        return None
    prev_path = None
    for p in reversed(snaps[:-1]):
        pts = _ts_of(p)
        if pts is not None and cur_ts - pts >= min_gap_hours * 3600:
            prev_path = p
            break
    if prev_path is None:
        return None
    try:
        prev, cur = load(prev_path), load(cur_path)
    except Exception:
        return None
    pk = {_key(n): n for n in prev["nodes"]}
    ck = {_key(n): n for n in cur["nodes"]}
    added = [ck[k] for k in ck.keys() - pk.keys()]
    removed = [pk[k] for k in pk.keys() - ck.keys()]
    if not added and not removed:
        return None
    return {"prev": prev_path, "cur": cur_path,
            "added": added, "removed": removed,
            "prev_findings": prev.get("findings", []),
            "cur_findings": cur.get("findings", [])}


def _key(n: dict) -> str:
    return f"{n.get('protocol')}://{n.get('server')}:{n.get('port')}"
