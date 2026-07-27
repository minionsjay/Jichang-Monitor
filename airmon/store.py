"""快照存储 + 历史 diff。每次采集落一份 JSON 到 data/<airport>/<ts>.json。"""
from __future__ import annotations

import glob
import json
import os
from datetime import datetime, timezone

from .models import Snapshot, Node

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(_HERE, "data")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def save(snap: Snapshot) -> str:
    d = os.path.join(DATA_DIR, snap.airport)
    os.makedirs(d, exist_ok=True)
    ts = snap.ts.replace(":", "").replace("-", "")
    path = os.path.join(d, f"{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snap.to_dict(), f, ensure_ascii=False, indent=2)
    return path


def list_snapshots(airport: str) -> list[str]:
    d = os.path.join(DATA_DIR, airport)
    return sorted(glob.glob(os.path.join(d, "*.json")))


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def diff_latest(airport: str) -> dict | None:
    """对比最近两次快照，返回 {added, removed, changed}（按 node key）。"""
    snaps = list_snapshots(airport)
    if len(snaps) < 2:
        return None
    prev, cur = load(snaps[-2]), load(snaps[-1])
    pk = {_key(n): n for n in prev["nodes"]}
    ck = {_key(n): n for n in cur["nodes"]}
    added = [ck[k] for k in ck.keys() - pk.keys()]
    removed = [pk[k] for k in pk.keys() - ck.keys()]
    return {"prev": snaps[-2], "cur": snaps[-1],
            "added": added, "removed": removed,
            "prev_findings": prev.get("findings", []),
            "cur_findings": cur.get("findings", [])}


def _key(n: dict) -> str:
    return f"{n.get('protocol')}://{n.get('server')}:{n.get('port')}"
