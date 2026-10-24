"""从磁盘快照 + run.log 还原历史轮次，生成/补齐 data/runs.json。

背景：runs.json 是 2026-10-24 才加上的，之前的轮次没有台账。
但每轮开始时会把各家快照写到 data/<slug>/<UTC ts>.json，所以「快照时间聚类」
就能还原出每轮的时间窗与节点数；run.log 里每轮有一行
`运行台账 → data\\last_run.json（成功27/失败18，陈旧15）`，按顺序配对即可补上成功/失败数。

还原出来的是近似值（derived=true）：没有 exit code、没有精确的开始时间，
只用于「运行记录」页展示趋势，不作为健康判据。

用法：
    python -X utf8 tools/backfill_runs.py [--days 7] [--dry]
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
RUNS = os.path.join(DATA, "runs.json")

SNAP_RE = re.compile(r"^(\d{8}T\d{6})Z\.json$")
GAP_MIN = 30          # 快照间隔 >30 分钟视为新一轮（一轮正常 40 分钟、轮间隔 3~6 小时）
LEDGER_RE = re.compile(r"运行台账.*?成功\s*(\d+)\s*/\s*失败\s*(\d+).*?陈旧\s*(\d+)")


def _utc(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y%m%dT%H%M%S").replace(tzinfo=dt.timezone.utc)


def collect_snaps(days: int) -> dict[str, list[tuple[dt.datetime, int]]]:
    """slug → [(ts, nodes)]，只取最近 days 天。"""
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    out: dict[str, list[tuple[dt.datetime, int]]] = {}
    try:
        entries = [e for e in os.scandir(DATA) if e.is_dir()]
    except OSError:
        return out
    for e in entries:
        if e.name.startswith("_") or e.name in ("backup", "subraw", "trash"):
            continue
        rows = []
        for fp in glob.glob(os.path.join(e.path, "*Z.json")):
            m = SNAP_RE.match(os.path.basename(fp))
            if not m:
                continue
            try:
                ts = _utc(m.group(1))
            except ValueError:
                continue
            if ts < cutoff:
                continue
            try:
                with io.open(fp, encoding="utf-8") as f:
                    j = json.load(f)
                n = len(j.get("nodes") or [])
            except (OSError, ValueError):
                continue
            rows.append((ts, n))
        if rows:
            out[e.name] = sorted(rows)
    return out


def cluster(snaps: dict[str, list[tuple[dt.datetime, int]]]) -> list[dict]:
    """把全部机场的快照时间点按间隔聚类成轮次。"""
    pts: list[tuple[dt.datetime, str, int]] = []
    for slug, rows in snaps.items():
        for ts, n in rows:
            pts.append((ts, slug, n))
    pts.sort()
    rounds: list[list[tuple[dt.datetime, str, int]]] = []
    for p in pts:
        if not rounds or (p[0] - rounds[-1][-1][0]).total_seconds() > GAP_MIN * 60:
            rounds.append([p])
        else:
            rounds[-1].append(p)
    out = []
    for grp in rounds:
        start, end = grp[0][0], grp[-1][0]
        # 每机场取该轮内最后一份（同机场可能被 pull+rescan 写两次）
        best: dict[str, tuple[dt.datetime, int]] = {}
        for ts, slug, n in grp:
            if slug not in best or ts >= best[slug][0]:
                best[slug] = (ts, n)
        out.append({
            "start": start,
            "end": end,
            "airports": len(best),
            "nodes": sum(v[1] for v in best.values()),
        })
    return out


def ledger_rows() -> list[tuple[int, int, int]]:
    """run.log 里每轮的成功/失败/陈旧行（按出现顺序）。"""
    rows = []
    for name in ("run.log", "run_manual.log"):
        p = os.path.join(ROOT, name)
        if not os.path.exists(p):
            continue
        try:
            txt = io.open(p, "rb").read().decode("utf-8", "replace")
        except OSError:
            continue
        for m in LEDGER_RE.finditer(txt):
            rows.append((int(m.group(1)), int(m.group(2)), int(m.group(3))))
    return rows


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--dry", action="store_true")
    a = ap.parse_args(argv)

    snaps = collect_snaps(a.days)
    rounds = cluster(snaps)
    led = ledger_rows()
    print(f"快照：{len(snaps)} 个机场 / 聚类出 {len(rounds)} 轮；run.log 台账 {len(led)} 行")

    # 从最后一轮往前配台账（台账行数可能少于聚类轮数）
    items = []
    for i, r in enumerate(rounds):
        from_end = len(rounds) - 1 - i
        ok = fail = stale = None
        if from_end < len(led):
            ok, fail, stale = led[len(led) - 1 - from_end]
        # 快照时间窗两端各留 2 分钟余量（拿到首/末家之前还有网络等待）
        started = (r["start"] - dt.timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ended = (r["end"] + dt.timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        dur = round((r["end"] - r["start"]).total_seconds() + 240, 1)
        items.append({
            "started_at": started,
            "ended_at": ended,
            "duration_s": dur,
            "status": "derived",
            "pull_ok": ok,
            "pull_fail": fail,
            "client_scanned": None,
            "airports_active": r["airports"],
            "nodes_total": r["nodes"],
            "hw_findings": None,
            "stale_n": stale,
            "failed": [],
            "trigger": "scheduled",
            "derived": True,
            "note": "由快照时间聚类 + run.log 台账还原（无 exit code）",
        })

    for it in items[-12:]:
        print(f"  {it['started_at']}  {it['duration_s'] / 60:5.1f}min  "
              f"{it['airports_active']:2d}家 {it['nodes_total']:5d}节点  "
              f"ok={it['pull_ok']} fail={it['pull_fail']}")

    if a.dry:
        print("--dry：不落盘")
        return 0

    existing = []
    if os.path.exists(RUNS):
        try:
            existing = json.load(io.open(RUNS, encoding="utf-8")) or []
        except (OSError, ValueError):
            existing = []
    # 真实轮次优先：derived 只补真实轮次没覆盖到的时间段
    have = {e.get("started_at") for e in existing if not e.get("derived")}
    merged = list(existing)
    for it in items:
        if it["started_at"] in have:
            continue
        if any(abs((dt.datetime.strptime(e["started_at"], "%Y-%m-%dT%H:%M:%SZ") -
                    dt.datetime.strptime(it["started_at"], "%Y-%m-%dT%H:%M:%SZ")).total_seconds()) < 1800
               for e in merged if e.get("started_at")):
            continue
        merged.append(it)
    merged.sort(key=lambda e: e.get("started_at") or "")
    merged = merged[-60:]
    with io.open(RUNS, "w", encoding="utf-8") as f:
        json.dump(merged, f, ensure_ascii=False, indent=2)
    print(f"已写入 {RUNS}（共 {len(merged)} 轮，其中还原 {sum(1 for x in merged if x.get('derived'))} 轮）")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
