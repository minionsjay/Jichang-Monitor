"""机场分析预计算：生成 data/analysis.json（机场监控仪表盘「分析」页数据源）。

用法：
    python -m airmon.analyze            # 全量构建（带增量缓存，二次运行很快）
    python -m airmon.analyze --days 30  # 历史窗口天数（默认 30）

内容（全部为聚合值，无服务器/IP/URL/token）：
- timeseries：近 N 天节点数时序（每日取当天最后一份快照）+ 总量线
- zero_events / stability：0 节点轮次、有节点天数占比
- churn：窗口内 |Δ节点| 累计排行
- proto_global / geo_global：最新快照协议/地区分布
- rdap：各机场最新快照 RDAP 注册机构集中度（org 为公开注册信息）
- expiry：套餐到期分布（读 quota.json 派生值）

增量缓存：data/analysis_cache.json 记录每个快照文件的 (mtime,size,ts,n)，
只解析新增/变化文件；历史窗口外的缓存条目自动清理。
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from airmon import snapnames

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(_HERE, "data")
CACHE_PATH = os.path.join(DATA_DIR, "analysis_cache.json")
OUT_PATH = os.path.join(DATA_DIR, "analysis.json")
SNAP_RE = snapnames.SNAP_RE  # 新旧两种命名都认，见 airmon/snapnames.py
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")

DEFAULT_DAYS = 30


def _snap_ts(stem: str) -> datetime:
    """文件名 -> 带时区 datetime（旧格式按 UTC、新格式按本地时间）。"""
    got = snapnames.parse_stem(stem)
    return got or datetime.now(timezone.utc)


def _load_cache() -> dict:
    try:
        with io.open(CACHE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(cache: dict) -> None:
    tmp = CACHE_PATH + ".tmp"
    with io.open(tmp, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, CACHE_PATH)


def _scan_history(days: int) -> dict:
    """slug -> {points: [(iso_ts, n_nodes)], zero_n, churn}。带增量缓存。"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    cache = _load_cache()
    new_cache = {}
    out = {}
    if not os.path.isdir(DATA_DIR):
        return out
    for slug in sorted(os.listdir(DATA_DIR)):
        d = os.path.join(DATA_DIR, slug)
        if not SLUG_RE.match(slug) or not os.path.isdir(d):
            continue
        points = []
        for fn in os.listdir(d):
            m = SNAP_RE.match(fn)
            if not m:
                continue
            ts = _snap_ts(fn)
            if ts < cutoff:
                continue
            p = os.path.join(d, fn)
            try:
                st = os.stat(p)
            except OSError:
                continue
            key = f"{slug}/{fn}"
            sig = f"{st.st_mtime_ns}:{st.st_size}"
            ent = cache.get(key)
            if ent and ent.get("sig") == sig:
                n = ent["n"]
            else:
                try:
                    with io.open(p, encoding="utf-8") as f:
                        j = json.load(f)
                    n = len(j.get("nodes") or [])
                except Exception:
                    continue
                new_cache[key] = {"sig": sig, "n": n}
            points.append((fn, n))
        if not points:
            continue
        points.sort(key=lambda p: snapnames.epoch(p[0]))
        churn = sum(abs(b - a) for (_, a), (_, b) in zip(points, points[1:]))
        zero_n = sum(1 for _, n in points if n == 0)
        out[slug] = {"points": points, "zero_n": zero_n, "churn": churn}
    if new_cache:
        _save_cache({**cache, **new_cache})
    return out


def _daily_series(hist: dict, days: int) -> tuple[list, dict, dict]:
    """dates(本地日 MM-DD), totals[], by_slug{} —— 每日取最后一份快照值。"""
    today = datetime.now().date()
    dates = [(today - timedelta(days=i)).strftime("%m-%d") for i in range(days - 1, -1, -1)]
    day_key = lambda ts: snapnames.parse_stem(ts).astimezone().strftime("%m-%d")
    by_slug, totals = {}, {d: 0 for d in dates}
    zero_events = {}
    for slug, h in hist.items():
        last = {}
        for ts, n in h["points"]:
            last[day_key(ts)] = n  # 后写覆盖 = 当天最后一份
        series = [last.get(d) for d in dates]
        by_slug[slug] = series
        zero_events[slug] = h["zero_n"]
        for d, n in last.items():
            if d in totals and n:
                totals[d] = max(totals[d], n)
    return dates, totals, by_slug, zero_events


def _rdap_orgs() -> dict:
    """各机场最新快照的 RDAP 注册机构 Top（公开 org 名，聚合占比）。"""
    out = {}
    if not os.path.isdir(DATA_DIR):
        return out
    for slug in sorted(os.listdir(DATA_DIR)):
        d = os.path.join(DATA_DIR, slug)
        if not SLUG_RE.match(slug) or not os.path.isdir(d):
            continue
        snaps = snapnames.names(d, reverse=False)  # 新旧命名混存，按真实时间
        # 最新「非空」快照
        chosen = None
        for fn in reversed(snaps):
            try:
                with io.open(os.path.join(d, fn), encoding="utf-8") as f:
                    j = json.load(f)
                if j.get("nodes"):
                    chosen = j
                    break
            except Exception:
                continue
        if not chosen:
            continue
        orgs = Counter()
        for nd in chosen["nodes"]:
            raw = nd.get("raw") or {}
            r = raw.get("_rdap")
            org = ""
            if isinstance(r, dict):  # {ip: [key, org_name, ...]}
                for v in r.values():
                    if isinstance(v, (list, tuple)):
                        org = next((str(x).strip() for x in v
                                    if isinstance(x, str) and x.strip()), "")
                    elif isinstance(v, str):
                        org = v.strip()
                    if org:
                        break
            elif isinstance(r, (list, tuple)):
                org = next((str(x).strip() for x in r
                            if isinstance(x, str) and x.strip()), "")
            elif isinstance(r, str):
                org = r.strip()
            if org:
                orgs[org[:40]] += 1
        if not orgs:
            continue
        total = sum(orgs.values())
        top, topn = orgs.most_common(1)[0]
        out[slug] = {"top_org": top, "share": round(topn / total, 3),
                     "orgs_n": len(orgs), "nodes": total}
    return out


def _expiry_from_quota() -> list:
    qp = os.path.join(DATA_DIR, "quota.json")
    try:
        with io.open(qp, encoding="utf-8") as f:
            q = json.load(f)
    except Exception:
        return []
    rows = []
    for slug, v in (q.get("airports") or q).items():
        if not isinstance(v, dict):
            continue
        dl = v.get("days_left")
        if isinstance(dl, (int, float)):
            rows.append({"slug": slug, "days_left": int(dl)})
    rows.sort(key=lambda r: r["days_left"])
    return rows


def build(days: int = DEFAULT_DAYS) -> dict:
    from airmon.dashboard import build_data  # 复用最新快照聚合+quota+registry

    base = build_data(None, 120, 6.0, 2_000_000)
    hist = _scan_history(days)
    dates, totals, by_slug, zero_events = _daily_series(hist, days)
    churn = sorted(
        ({"slug": s, "churn": h["churn"], "latest": h["points"][-1][1]}
         for s, h in hist.items() if h["churn"] > 0),
        key=lambda x: -x["churn"])[:12]
    zero_rank = sorted(
        ({"slug": s, "zero_n": n} for s, n in zero_events.items() if n),
        key=lambda x: -x["zero_n"])[:12]
    stability = []
    for slug, series in by_slug.items():
        obs = sum(1 for n in series if n is not None)
        withn = sum(1 for n in series if n)
        if obs:
            stability.append({"slug": slug, "days": obs, "ok_days": withn,
                              "pct": round(withn / obs * 100)})
    stability.sort(key=lambda x: (x["pct"], -x["days"]))
    proto_c, geo_c = Counter(), Counter()
    for a in base.get("airports", []):
        for p, n in (a.get("proto_top") or []):
            proto_c[str(p)] += n
        for nd in (a.get("detail") or {}).get("nodes") or []:
            cc = str(nd.get("c") or "未知")
            geo_c[cc] += 1
    out = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "days": days,
        "base_local": base.get("base_local"),
        "timeseries": {"dates": dates, "totals": [totals[d] for d in dates],
                       "by_slug": by_slug},
        "zero_rank": zero_rank,
        "churn": churn,
        "stability": stability,
        "proto_global": proto_c.most_common(12),
        "geo_global": geo_c.most_common(12),
        "rdap": _rdap_orgs(),
        "expiry": _expiry_from_quota(),
    }
    # 负向自检：绝不落服务器/IP/URL/token
    blob = json.dumps(out, ensure_ascii=False)
    for bad in ("http://", "https://", "sub_url", "password", "aead", "auth_token", "eyJ"):
        if bad in blob:
            raise SystemExit(f"analyze: 负向自检命中 {bad!r}，中止写盘")
    tmp = OUT_PATH + ".tmp"
    with io.open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, OUT_PATH)
    return out


def main(argv: list[str]) -> int:
    days = DEFAULT_DAYS
    if "--days" in argv:
        i = argv.index("--days")
        try:
            days = max(3, min(90, int(argv[i + 1])))
        except (IndexError, ValueError):
            print("--days 需要一个 3-90 的整数")
            return 10
    out = build(days)
    print(f"分析完成：{len(out.get('timeseries', {}).get('by_slug', {}))} 机场 × {days} 天"
          f" → {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
