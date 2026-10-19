"""airmon.dashboard — 静态单文件仪表盘生成器（MVP）。

设计文档：docs\\05-仪表盘设计.md
用法：
    python -m airmon.dashboard                 # 全量生成 dashboard\\index.html
    python -m airmon.dashboard --airport muniu # 单机场视图
    python -m airmon.dashboard --out D:\\x.html --alert-limit 200 --stale-hours 6

数据来源（只读）：
    data\\<airport>\\<YYYYMMDDTHHMMSSZ>.json   快照（airmon.store.list_snapshots/load）
    data\\alerts.log                           告警块（airmon.alert.emit 写格式）
    run.log（项目根，尾部解析）                 最近完成一轮的运行健康信息
    data\quota.json（airmon.quota 生成）       套餐到期/流量（subscription-userinfo）
    airports.yaml + credentials.yaml           登记白名单字段（enabled/type/core/面板域名）

隐私红线（实现层白名单硬保证，生成后还有机器自检）：
    只输出聚合统计、节点别名、server:port、协议、国家/厂商、增删变化、时间戳；
    绝不输出订阅 URL/token、节点密码、velochron 密钥（aero_v2_edge_psk/aead_key 等）、
    账号邮箱、auth_id、app_signature 等任何凭据或指纹字段。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import store as _store
from .store import list_snapshots, load

SNAP_RE = re.compile(r"^\d{8}T\d{6}Z\.json$")
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(_store.DATA_DIR)
DEFAULT_OUT = PROJECT_ROOT / "dashboard" / "index.html"
RUN_LOG = PROJECT_ROOT / "run.log"
ALERT_LOG = DATA_DIR / "alerts.log"
QUOTA_FILE = DATA_DIR / "quota.json"
AIRPORTS_YAML = PROJECT_ROOT / "airports.yaml"
CREDENTIALS = PROJECT_ROOT / "credentials.yaml"

# 生成物自检：命中任意一条即中止写盘（只报规则与次数，不回显内容）
SANITIZE_RULES = [
    ("password", re.compile(r"(?i)password")),
    ("aead", re.compile(r"(?i)aead")),
    ("psk", re.compile(r"(?i)edge_?psk|\bpsk\b")),
    ("resume_ticket", re.compile(r"(?i)resume_ticket")),
    ("auth_token", re.compile(r"(?i)auth_?token")),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("subscribe-token-url", re.compile(r"(?i)subscribe\?token=|/api/v1/client/subscribe")),
    ("yaml-sub-url", re.compile(r"(?i)https?://\S+\.ya\s?ml")),
]

DETAIL_NODE_CAP = 200  # diff 明细单侧最多展示条数（计数仍为精确值）

# 节点别名常内嵌账号邮箱（订阅命名习惯），落页前统一打码
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _scrub(s: str) -> str:
    return _EMAIL_RE.sub("[email]", s)


# ---------------------------------------------------------------- 时间与文件名

def _fname_ts(path: Path) -> datetime | None:
    m = SNAP_RE.match(path.name)
    if not m:
        return None
    try:
        return datetime.strptime(path.stem, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _local(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone().strftime("%m-%d %H:%M")


def _ts_local(s: str) -> str:
    """alerts.log 块头时间戳 → 本地显示串；解析失败原样返回。"""
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return _local(dt) or s
    except ValueError:
        return s


def iter_airport_dirs() -> list[str]:
    """data\\ 下含快照命名 JSON 的目录才算机场（排除 *_analysis 与 .cache）。"""
    out = []
    if not DATA_DIR.exists():
        return out
    for d in sorted(DATA_DIR.iterdir()):
        if not d.is_dir():
            continue
        if d.name.startswith(".") or d.name.endswith("_analysis"):
            continue
        if any(SNAP_RE.match(f.name) for f in d.glob("*.json")):
            out.append(d.name)
    return out


def _snap_paths(slug: str) -> list[Path]:
    """list_snapshots 结果统一为 Path 并按快照命名过滤（store 返回类型防御）。"""
    return [Path(p) for p in list_snapshots(slug) if SNAP_RE.match(Path(p).name)]


def _load_valid(path: Path) -> dict | None:
    """容错读取：截断/损坏 JSON（快照非原子写）返回 None。"""
    try:
        data = load(path)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if not isinstance(data.get("nodes"), list):
        return None
    return data


# ---------------------------------------------------------------- 机场聚合

def _route_label(source: str) -> str:
    s = source or ""
    if s.startswith("memory_scan:"):
        client = s.split(":", 1)[1]
        return "内存扫描/" + client[:20] if client else "内存扫描"
    if s.startswith("velo_api"):
        return "velo-api"
    for kw in ("server-fetch", "v2board", "xlcc"):
        if kw in s:
            return kw
    if s.startswith("http"):
        return "sub-url"  # 永不透传 URL 本体
    head = s.split(":", 1)[0]
    return (head or "unknown")[:24]


def _parse_userinfo(meta: dict) -> dict:
    raw = meta.get("subscription-userinfo")
    if not isinstance(raw, str) or "=" not in raw:
        return {}
    kv = {}
    for part in raw.split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            try:
                kv[k] = float(v)
            except ValueError:
                pass
    out = {}
    total, used = kv.get("total", 0.0), kv.get("upload", 0.0) + kv.get("download", 0.0)
    if kv.get("expire"):
        out["expire"] = datetime.fromtimestamp(
            kv["expire"], tz=timezone.utc).astimezone().strftime("%Y-%m-%d")
    if total > 0:
        out["usage_pct"] = round(used / total * 100, 1)
    return out


def _node_row(n: dict) -> dict:
    raw = n.get("raw") if isinstance(n.get("raw"), dict) else {}
    country = None
    ips = raw.get("_resolved_ips") if isinstance(raw.get("_resolved_ips"), list) else []
    rdap = raw.get("_rdap") if isinstance(raw.get("_rdap"), dict) else {}
    if ips:
        info = rdap.get(str(ips[0]))
        if isinstance(info, (list, tuple)) and len(info) >= 3:
            country = (info[2] or "").strip() or None
    return {
        "n": _scrub(str(n.get("name") or ""))[:60],
        "p": str(n.get("protocol") or "unknown"),
        "s": str(n.get("server") or ""),
        "o": n.get("port"),
        "c": country,
        "r": (str(ips[0])[:45] if ips else None),  # 解析 IP（raw._resolved_ips 首个）
    }


def _node_key(n: dict) -> str:
    return f"{n.get('protocol')}://{n.get('server')}:{n.get('port')}"


def collect_airport(slug: str, base_dt: datetime, stale_hours: float) -> dict | None:
    snaps = _snap_paths(slug)
    if not snaps:
        return None

    fname_ts = [_fname_ts(p) for p in snaps]
    latest_file_ts = next((t for t in reversed(fname_ts) if t), None)

    latest = best = prev = None
    for i in range(len(snaps) - 1, -1, -1):
        s = _load_valid(snaps[i])
        if s is None:
            continue
        if latest is None:
            latest = s
        if s.get("nodes"):
            if best is None:
                best = s
            elif prev is None:
                prev = s
                break

    if latest is None and best is None:
        return None

    latest_ts = latest_file_ts or _fname_ts(snaps[-1])
    age_h = None
    if latest_ts is not None:
        age_h = max(0.0, round((base_dt - latest_ts).total_seconds() / 3600, 1))
    snap24 = sum(1 for t in fname_ts if t and t >= base_dt - timedelta(hours=24))

    # diff：最近两份非空快照（0 节点拉取快照不参与，避免 R-19 污染）
    added_rows: list[dict] = []
    removed_rows: list[dict] = []
    added_n = removed_n = 0
    if best is not None:
        bmap = {}
        for n in best["nodes"]:
            bmap.setdefault(_node_key(n), _node_row(n))
        pkeys = set()
        if prev is not None:
            for n in prev["nodes"]:
                pkeys.add(_node_key(n))
        for k, row in bmap.items():
            if k not in pkeys:
                added_n += 1
                if len(added_rows) < DETAIL_NODE_CAP:
                    added_rows.append(row)
        if prev is not None:
            pmap = {}
            for n in prev["nodes"]:
                pmap.setdefault(_node_key(n), _node_row(n))
            for k, row in pmap.items():
                if k not in bmap:
                    removed_n += 1
                    if len(removed_rows) < DETAIL_NODE_CAP:
                        removed_rows.append(row)

    # 当前命中取最新可解析快照的 findings（最近一次检测运行的口径）
    findings = []
    for f in (latest or {}).get("findings") or []:
        if isinstance(f, dict):
            findings.append({
                "d": str(f.get("dimension") or ""),
                "r": _scrub(str(f.get("rule") or "")),
                "e": _scrub(str(f.get("evidence") or ""))[:160],
                "x": _scrub(str(f.get("context") or ""))[:160],
                "c": str(f.get("confidence") or ""),
            })

    nodes = best["nodes"] if best is not None else []
    proto_top = [[p, c] for p, c in Counter(
        str(n.get("protocol") or "unknown") for n in nodes).most_common(3)]

    owners = Counter()
    for n in nodes:
        raw = n.get("raw") if isinstance(n.get("raw"), dict) else {}
        ips = raw.get("_resolved_ips") if isinstance(raw.get("_resolved_ips"), list) else []
        rdap = raw.get("_rdap") if isinstance(raw.get("_rdap"), dict) else {}
        if not ips:
            continue
        info = rdap.get(str(ips[0]))
        if isinstance(info, (list, tuple)) and info:
            owner = (info[1] or info[0] or "").replace(" administrator", "")[:34]
            if owner:
                owners[owner] += 1

    meta = {}
    for cand in (latest, best):
        if cand and isinstance(cand.get("meta"), dict) and cand["meta"]:
            meta = cand["meta"]
            if meta.get("subscription-userinfo"):
                break
    userinfo = _parse_userinfo(meta)

    route = _route_label(str((latest or best or {}).get("source") or ""))
    pull_zero = bool(latest is not None and not latest.get("nodes"))
    status = "stale" if (age_h is not None and age_h > stale_hours) else "ok"

    return {
        "slug": slug,
        "route": route,
        "status": status,
        "nodes": len(nodes),
        "pull_zero": pull_zero,
        "age_h": age_h,
        "latest_ts": latest_ts.strftime("%Y-%m-%dT%H:%M:%SZ") if latest_ts else None,
        "latest_local": _local(latest_ts),
        "snap24": snap24,
        "added_n": added_n,
        "removed_n": removed_n,
        "no_prev": prev is None,
        "hit_n": len(findings),
        "proto_top": proto_top,
        "expire": userinfo.get("expire"),
        "usage_pct": userinfo.get("usage_pct"),
        "detail": {
            "nodes": [_node_row(n) for n in nodes],
            "added": added_rows,
            "removed": removed_rows,
            "findings": findings[:20],
            "owners": [[o, c] for o, c in owners.most_common(5)],
        },
    }


# ---------------------------------------------------------------- alerts.log

_HW_RE = re.compile(
    r"\[华为命中\]\s*(\S+)\s*\|\s*([^=|]+?)=([^|]+?)\s*\|\s*证据=(.*?)\s*\|\s*(.*?)\s*\((\w+)\)\s*$",
    re.M,
)
_HEADER_RE = re.compile(r"^===== (.+?) \| (.+?) =====\s*$", re.M)


def parse_alerts(limit: int, airport: str | None = None) -> tuple[list, list]:
    if not ALERT_LOG.exists():
        return [], []
    text = ALERT_LOG.read_text(encoding="utf-8", errors="replace")
    heads = list(_HEADER_RE.finditer(text))
    blocks: list[dict] = []
    ledger: dict[tuple, dict] = {}
    for i, m in enumerate(heads):
        ts_raw, ap = m.group(1).strip(), m.group(2).strip()
        body = text[m.end(): heads[i + 1].start() if i + 1 < len(heads) else len(text)]
        if not re.search(r"华为|新增节点|消失节点", body):
            continue  # 空块过滤（t3：83.9% 空块无信息量）
        hw = []
        for hm in _HW_RE.finditer(body):
            row = {
                "airport": hm.group(1),
                "rule": _scrub(f"{hm.group(2).strip()}={hm.group(3).strip()}"),
                "evidence": _scrub(hm.group(4).strip())[:160],
                "context": _scrub(hm.group(5).strip())[:160],
                "confidence": hm.group(6),
            }
            hw.append(row)
            key = (row["airport"], row["rule"], row["evidence"])
            ent = ledger.setdefault(key, {**row, "count": 0, "last_ts": ts_raw})
            ent["count"] += 1
            if ts_raw > ent["last_ts"]:
                ent["last_ts"] = ts_raw
        added_n = sum(int(x) for x in re.findall(r"新增节点 (\d+) 个", body))
        removed_n = sum(int(x) for x in re.findall(r"消失节点 (\d+) 个", body))
        if hw or added_n or removed_n:
            blocks.append({
                "ts": ts_raw,
                "ts_local": _ts_local(ts_raw),
                "airport": ap,
                "hw_n": len(hw),
                "hw": hw[:8],
                "added_n": added_n,
                "removed_n": removed_n,
            })
    if airport:
        blocks = [b for b in blocks if b["airport"] == airport]
        ledger = {k: v for k, v in ledger.items() if k[0] == airport}
    blocks.sort(key=lambda b: b["ts"], reverse=True)
    led = sorted(ledger.values(), key=lambda v: v["last_ts"], reverse=True)
    return blocks[:limit], led


# ---------------------------------------------------------------- run.log

_BAT_TS = r"(\d{4}/\d{1,2}/\d{1,2})\D+?(\d{1,2}:\d{2}:\d{2})"
_START_RE = re.compile(r"===" + r"\s*" + _BAT_TS)
_DONE_RE = re.compile(r"Done\s+" + _BAT_TS)
_OK_RE = re.compile(r"\[成功\]\s+(\S+)\s+\(([^)]*)\):\s*(\d+)\s*节点")
_SKIP_RE = re.compile(r"\[跳过\]\s+(\S+):\s*超时")
_AUTH_RE = re.compile(r"\[(\S+)\]\s*✗\s*登录失败")
_PULL_RE = re.compile(r"正在拉取\s+(\S+)")
_FINAL_RE = re.compile(r"===== 完成：(\d+)\s*个机场，共\s*(\d+)\s*个节点")


def _bat_dt(m: re.Match) -> datetime | None:
    try:
        return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None


def parse_run_log(tail: int = 2_000_000) -> dict | None:
    if not RUN_LOG.exists():
        return None
    try:
        text = RUN_LOG.read_bytes()[-tail:].decode("utf-8", errors="replace")
    except OSError:
        return None
    starts = list(_START_RE.finditer(text))
    if not starts:
        return {"note": "尾部未找到轮次锚点（=== 日期 时间 ===）", "inflight": False}

    # 最近一轮 = 最近一个有完成标记（Done）的轮次；其后若还有新轮次开始则标记进行中
    window, start_m, done_m = None, None, None
    for i in range(len(starts) - 1, -1, -1):
        s = starts[i]
        d = next((x for x in _DONE_RE.finditer(text) if x.start() > s.start()), None)
        nxt = starts[i + 1].start() if i + 1 < len(starts) else len(text)
        if d and d.start() < nxt:
            window = text[s.start():d.start()]
            start_m, done_m = s, d
            break
    if start_m is None:
        s = starts[-1]
        return {
            "start_local": _local(_bat_dt(s)),
            "done_local": None,
            "inflight": True,
            "note": "检测到开始锚点但未见完成标记（进行中或被中断），以下为该轮片段",
            "window": text[s.start():],
        }
    inflight = any(x.start() > (done_m.start() if done_m else 0) for x in starts)

    def _scan(seg: str) -> dict:
        ok, skipped, zero, auth = [], [], [], []
        last_slug = None
        for line in seg.splitlines():
            pm = _PULL_RE.search(line)
            if pm:
                last_slug = pm.group(1).rstrip(".")
            om = _OK_RE.search(line)
            if om:
                ok.append({"slug": om.group(1), "kind": om.group(2), "n": int(om.group(3))})
                continue
            sm = _SKIP_RE.search(line)
            if sm:
                skipped.append(sm.group(1))
                continue
            am = _AUTH_RE.search(line)
            if am:
                auth.append(am.group(1))
                continue
            if "⚠ 0 节点" in line and last_slug:
                zero.append(last_slug)

        def dedup(seq):
            return list(dict.fromkeys(seq))

        return {
            "ok": ok,
            "skipped": dedup(skipped),
            "zero": dedup(zero),
            "auth": dedup(auth),
        }

    stats = _scan(window)
    seg = text[start_m.start(): done_m.end()] if done_m else window
    final = _FINAL_RE.search(seg)
    start_dt, done_dt = _bat_dt(start_m), _bat_dt(done_m) if done_m else None
    duration_min = None
    if start_dt and done_dt:
        duration_min = round((done_dt - start_dt).total_seconds() / 60, 1)
    out = {
        "start_local": _local(start_dt),
        "done_local": _local(done_dt),
        "duration_min": duration_min,
        "final_aps": int(final.group(1)) if final else None,
        "final_nodes": int(final.group(2)) if final else None,
        "ok_n": len(stats["ok"]),
        "ok_nodes": sum(x["n"] for x in stats["ok"]),
        "ok_top": sorted(stats["ok"], key=lambda x: -x["n"])[:60],
        "skipped": stats["skipped"][:30],
        "zero": stats["zero"][:30],
        "auth": stats["auth"][:30],
        "inflight": inflight,
    }
    if inflight:
        newer = [s for s in starts if s.start() > (done_m.start() if done_m else 0)]
        out["note"] = "此后检测到新一轮开始但无完成标记（进行中或被中断）：" + (
            _local(_bat_dt(newer[0])) or "?") if newer else ""
    return out


# ---------------------------------------------------------------- 套餐与登记（白名单字段）

_QUOTA_KEYS = ("expire_date", "days_left", "total_gb", "used_gb",
               "used_pct", "unlimited", "source", "at")


def _load_quota() -> tuple[str | None, dict[str, dict]]:
    """data/quota.json → (生成时间, slug→白名单套餐字段)。文件缺失/损坏时静默降级。"""
    if not QUOTA_FILE.exists():
        return None, {}
    try:
        raw = json.loads(QUOTA_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None, {}
    if not isinstance(raw, dict):
        return None, {}
    qmap: dict[str, dict] = {}
    for slug, e in (raw.get("airports") or {}).items():
        if isinstance(e, dict):
            qmap[slug] = {k: e.get(k) for k in _QUOTA_KEYS}
    gen = raw.get("generated_at")
    return (gen[:16].replace("T", " ") if isinstance(gen, str) else None), qmap


def _host_of(url) -> str | None:
    """面板登记值 → 纯域名（host），不带路径与参数。"""
    if not isinstance(url, str) or not url:
        return None
    s = url if url.startswith(("http://", "https://")) else "https://" + url
    return urlparse(s).netloc or None


def _load_registry() -> dict[str, dict]:
    """airports.yaml + credentials.yaml → slug→{enabled,ptype,core,panel}（仅白名单字段）。"""
    reg: dict[str, dict] = {}
    try:
        d = yaml.safe_load(AIRPORTS_YAML.read_text(encoding="utf-8")) or {}
        for a in d.get("airports") or []:
            if not isinstance(a, dict) or not a.get("name"):
                continue
            client = a.get("client") if isinstance(a.get("client"), dict) else {}
            reg.setdefault(str(a["name"]), {}).update(
                enabled=a.get("enabled"),
                ptype=a.get("type"),
                core=client.get("core_process"),
                panel=_host_of(a.get("panel")),
            )
    except Exception:
        pass
    try:
        c = yaml.safe_load(CREDENTIALS.read_text(encoding="utf-8")) or {}
        for name, acc in (c.get("accounts") or {}).items():
            if not isinstance(acc, dict):
                continue
            ent = reg.setdefault(str(name), {})
            if ent.get("panel") is None:
                ent["panel"] = _host_of(acc.get("panel"))
    except Exception:
        pass
    return reg


# ---------------------------------------------------------------- 组装与渲染

def build_data(airport: str | None, alert_limit: int, stale_hours: float,
               runlog_tail: int) -> dict:
    slugs = iter_airport_dirs()
    if airport and airport not in slugs:
        raise SystemExit(f"未知机场：{airport}（可用：{', '.join(slugs)}）")
    targets = [airport] if airport else slugs

    latest_ts_per = {}
    for slug in targets:
        snaps = _snap_paths(slug)
        ts = next((t for t in (_fname_ts(p) for p in reversed(snaps)) if t), None)
        if ts:
            latest_ts_per[slug] = ts
    base_dt = max(latest_ts_per.values()) if latest_ts_per else \
        datetime.now(timezone.utc)

    airports = []
    for slug in targets:
        card = collect_airport(slug, base_dt, stale_hours)
        if card:
            airports.append(card)

    # 套餐（quota.json）与登记（yaml 白名单字段）并入卡片
    reg = _load_registry()
    quota_at, qmap = _load_quota()
    for card in airports:
        info = reg.get(card["slug"]) or {}
        card["info"] = {k: info[k] for k in ("enabled", "ptype", "core", "panel")
                        if info.get(k) is not None}
        q = qmap.get(card["slug"])
        if q:
            card["quota"] = q
    expiring30 = sorted(a["slug"] for a in airports
                        if a.get("quota") and isinstance(a["quota"].get("days_left"), (int, float))
                        and 0 <= a["quota"]["days_left"] <= 30)
    expired = sorted(a["slug"] for a in airports
                     if a.get("quota") and isinstance(a["quota"].get("days_left"), (int, float))
                     and a["quota"]["days_left"] < 0)

    blocks, ledger = parse_alerts(alert_limit, airport)
    zero_pull = sorted(a["slug"] for a in airports if a["pull_zero"])
    stale = sorted(a["slug"] for a in airports if a["status"] == "stale")
    hw_current = [
        {"airport": a["slug"], **f}
        for a in airports for f in a["detail"]["findings"]
    ]

    return {
        "generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"),
        "base_local": _local(base_dt),
        "stale_hours": stale_hours,
        "single": airport,
        "totals": {
            "airports": len(airports),
            "dirs": len(slugs),
            "with_nodes": sum(1 for a in airports if a["nodes"] > 0),
            "nodes": sum(a["nodes"] for a in airports),
            "hits": sum(a["hit_n"] for a in airports),
            "zero_pull": zero_pull,
            "stale": stale,
            "expiring30": expiring30,
            "expired": expired,
        },
        "airports": airports,
        "alerts": blocks,
        "hw_ledger": [
            {"airport": v["airport"], "rule": v["rule"], "evidence": v["evidence"],
             "count": v["count"], "last_ts_local": _ts_local(v["last_ts"])}
            for v in ledger
        ],
        "hw_current": hw_current,
        "runlog": parse_run_log(runlog_tail),
        "quota_at": quota_at,
    }


TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>airmon 机场监控仪表盘</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--tx:#e6edf3;--mut:#8b949e;
--teal:#2dd4bf;--amber:#f0b429;--red:#f85149;--purple:#a371f7;--green:#3fb950;--blue:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);
font:14px/1.55 "Segoe UI","Microsoft YaHei",sans-serif}
a{color:var(--blue);text-decoration:none}
header{position:sticky;top:0;z-index:9;background:rgba(13,17,23,.94);backdrop-filter:blur(4px);
border-bottom:1px solid var(--border);padding:10px 18px}
h1{font-size:18px;margin:0 0 8px}
h2{font-size:16px;margin:26px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--border)}
main{padding:0 18px 40px;max-width:1500px}
.kpis{display:flex;flex-wrap:wrap;gap:8px}
.kpi{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:6px 12px}
.kpi b{font-size:16px;margin-right:4px}
.kpi.warn b{color:var(--amber)}.kpi.bad b{color:var(--red)}.kpi.good b{color:var(--teal)}
.chip{display:inline-block;border:1px solid var(--border);border-radius:10px;
padding:0 8px;font-size:12px;color:var(--mut);margin:1px 2px 1px 0}
.chip.amber{color:var(--amber);border-color:var(--amber)}
.chip.red{color:var(--red);border-color:var(--red)}
.chip.purple{color:var(--purple);border-color:var(--purple)}
.chip.teal{color:var(--teal);border-color:var(--teal)}
.red{color:var(--red)}.amber{color:var(--amber)}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
input,select{background:var(--panel);border:1px solid var(--border);color:var(--tx);
border-radius:6px;padding:5px 9px;font:inherit}
#cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--teal);
border-radius:8px;padding:10px 12px;cursor:pointer}
.card.st-stale{border-left-color:var(--red)}
.card:hover{border-color:var(--blue)}
.chead{display:flex;justify-content:space-between;align-items:baseline;gap:6px}
.chead b{font-size:15px}
.bignum{font-size:26px;font-weight:700;margin:4px 0}
.bignum small{font-size:12px;color:var(--mut);font-weight:400}
.delta .up{color:var(--green)}.delta .dn{color:var(--red)}
.meta{color:var(--mut);font-size:12px}
.detail{margin-top:8px;border-top:1px dashed var(--border);padding-top:8px;display:none}
.detail table,.dtable{width:100%;border-collapse:collapse;font-size:12px}
th,td{border:1px solid var(--border);padding:3px 6px;text-align:left;vertical-align:top}
th{background:#1c2129;position:sticky;top:0}
.scroll{max-height:320px;overflow:auto;margin:6px 0}
details.drow{background:var(--panel);border:1px solid var(--border);border-radius:8px;
padding:8px 12px;margin:8px 0}
details.drow summary{cursor:pointer;font-weight:600}
.al{background:var(--panel);border:1px solid var(--border);border-radius:8px;
padding:8px 12px;margin:8px 0}
.al .h{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.al .h b{color:var(--blue)}
.al .hw{color:var(--purple);font-size:12px;margin-top:4px;white-space:pre-wrap;word-break:break-all}
.muted{color:var(--mut)}.banner{background:#21262d;border:1px solid var(--border);
border-radius:8px;padding:8px 12px;margin:10px 0}
footer{color:var(--mut);font-size:12px;padding:14px 18px;border-top:1px solid var(--border)}
.twocol{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:800px){.twocol{grid-template-columns:1fr}}
</style>
</head>
<body>
<header>
  <h1>✈ airmon 机场监控仪表盘 <span class="muted" style="font-size:12px">静态快照视图 · 脱敏白名单生成</span></h1>
  <div class="kpis" id="kpi"></div>
</header>
<main>
  <div id="banner"></div>
  <section id="sec-cards"><h2>机场状态卡片矩阵</h2>
    <div class="toolbar">
      <input id="q" placeholder="搜索机场…" size="14">
      <select id="fst">
        <option value="all">全部状态</option><option value="ok">正常</option>
        <option value="stale">陈旧</option><option value="pull_zero">本轮拉取 0 节点</option>
        <option value="zero_pool">0 节点池</option><option value="hit">有华为命中</option>
        <option value="quota30">30天内到期/已过期</option>
      </select>
      <select id="fsort">
        <option value="nodes">按节点数↓</option><option value="delta">按变化↓</option>
        <option value="age">按陈旧度↓</option><option value="name">按名称</option>
      </select>
      <span class="muted" id="ccount"></span>
    </div>
    <div id="cards"></div>
  </section>
  <section id="sec-quota"><h2>套餐到期与流量总览</h2>
    <div class="muted">来源 subscription-userinfo 响应头（拉订阅时随快照写盘；&gt;7 天旧数据在生成套餐时在线刷新，失败机场以最近快照数据兜底并在 quota.json 记录原因）· 客户端路线无订阅故无此数据 · 红=已过期或≤7 天，黄=≤30 天。</div>
    <div id="quota"></div>
  </section>
  <section id="sec-diff"><h2>最近两次快照变化（新增 / 消失节点）</h2>
    <div class="muted">口径：最近两份<b>非空</b>快照之差（规避 0 节点拉取快照与同轮双写污染）；点击行展开明细。</div>
    <div id="diff"></div>
  </section>
  <section id="sec-alerts"><h2>告警流（有效块，已过滤空块）</h2><div id="alerts"></div></section>
  <section id="sec-hw"><h2>华为关联命中</h2><div id="hw"></div></section>
  <section id="sec-health"><h2>运行健康</h2><div id="health"></div></section>
</main>
<footer id="foot"></footer>
<script type="application/json" id="dashboard-data">__DATA_JSON__</script>
<script>
"use strict";
const D = JSON.parse(document.getElementById("dashboard-data").textContent);
function h(t,c,x){const e=document.createElement(t);if(c)e.className=c;
if(x!==undefined&&x!==null)e.textContent=x;return e;}
function chip(t,cls){return h("span","chip"+(cls?" "+cls:""),t);}
function thr(labels){const tr=document.createElement("tr");
labels.forEach(x=>tr.append(h("th",null,x)));return tr;}
function num(x){return (x===null||x===undefined)?"—":x;}

/* KPI */
(function(){
  const T=D.totals,k=document.getElementById("kpi");
  const put=(cls,label,val,title)=>{const e=h("div","kpi "+(cls||""),null);
    e.append(h("b",null,val),h("span","muted",label));
    if(title)e.title=title;k.append(e);};
  put("good","机场（有节点/总数）",T.with_nodes+"/"+T.airports);
  put("","节点总数",T.nodes);
  put(T.hits?"purple":"", "当前华为命中", T.hits);
  put(T.zero_pull.length?"warn":"","本轮拉取0节点",T.zero_pull.length,
      T.zero_pull.join(", ")||"无");
  put(T.stale.length?"bad":"","陈旧(>"+D.stale_hours+"h)",T.stale.length,
      T.stale.join(", ")||"无");
  put("","有效告警块",D.alerts.length);
  const expd=T.expired||[],expg=T.expiring30||[];
  put(expd.length?"bad":"","已过期",expd.length,expd.join("、")||"无");
  put(expg.length?"warn":"","30天内到期",expg.length,expg.join("、")||"无");
  put("","数据基准",D.base_local||"—");
})();

/* 卡片 */
const state={q:"",fst:"all",fsort:"nodes"};
function cardEl(a){
  const c=h("div","card st-"+a.status);
  const head=h("div","chead");head.append(h("b",null,a.slug));
  const badges=h("span",null,null);
  badges.append(chip(a.route,"teal"));
  if(a.pull_zero)badges.append(chip("拉取0节点","amber"));
  if(a.nodes===0)badges.append(chip("0节点池","red"));
  if(a.status==="stale")badges.append(chip("陈旧 "+a.age_h+"h","red"));
  if(a.hit_n)badges.append(chip("华为 "+a.hit_n,"purple"));
  head.append(badges);c.append(head);
  const big=h("div","bignum",null);
  big.append(document.createTextNode(a.nodes),h("small",null," 节点"));
  const delta=h("small","delta",null);
  if(a.added_n)delta.append(h("span","up"," +"+a.added_n));
  if(a.removed_n)delta.append(h("span","dn"," −"+a.removed_n));
  if(a.no_prev)delta.append(h("span","muted"," （仅一份非空快照）"));
  big.append(delta);c.append(big);
  c.append(h("div","meta","最近快照 "+num(a.latest_local)+
      (a.age_h!==null?"（"+a.age_h+"h 前）":"")+" · 24h快照 "+a.snap24));
  const inf=a.info||{},ib=[];
  if(inf.panel)ib.push("面板 "+inf.panel);
  if(inf.core)ib.push("内核 "+inf.core);
  if(inf.enabled===false)ib.push("已停用");
  if(ib.length)c.append(h("div","meta",ib.join(" · ")));
  const pc=h("div",null,null);
  a.proto_top.forEach(p=>pc.append(chip(p[0]+"×"+p[1])));
  const q=a.quota;
  if(q){
    if(q.expire_date){
      const dl=q.days_left;let cls="",txt="到期 "+q.expire_date;
      if(dl!==null&&dl!==undefined){
        if(dl<0){txt="已过期 "+q.expire_date;cls="red";}
        else{txt+="（剩 "+dl+" 天）";if(dl<=7)cls="red";else if(dl<=30)cls="amber";}
      }
      pc.append(chip(txt,cls));
    }else pc.append(chip("无到期日"));
    if(q.unlimited)pc.append(chip("流量不限","teal"));
    else if(q.total_gb!==null&&q.total_gb!==undefined){
      const rem=Math.max(0,(q.total_gb||0)-(q.used_gb||0)).toFixed(1);
      const pcls=(q.used_pct!==null&&q.used_pct!==undefined)?
        (q.used_pct>=90?"red":(q.used_pct>=75?"amber":"")):"";
      pc.append(chip("流量 "+(q.used_gb||0)+"/"+q.total_gb+"GB"+
        ((q.used_pct!==null&&q.used_pct!==undefined)?" · "+q.used_pct+"%":"")+
        "（剩 "+rem+"）",pcls));
    }else if(q.used_gb)pc.append(chip("已用 "+q.used_gb+"GB"));
  }else{
    if(a.expire)pc.append(chip("到期 "+a.expire));
    if(a.usage_pct!==null&&a.usage_pct!==undefined)pc.append(chip("已用 "+a.usage_pct+"%"));
  }
  c.append(pc);
  const det=h("div","detail");c.append(det);
  c.addEventListener("click",()=>toggleDetail(a,c,det));
  return c;
}
let expanded=new Set();
function toggleDetail(a,card,det){
  const open=det.style.display!=="block";
  det.style.display=open?"block":"none";
  if(open&&!expanded.has(a.slug)){buildDetail(a,det);expanded.add(a.slug);}
}
function nodeTable(rows){
  const wrap=h("div","scroll"),t=h("table","dtable");
  t.append(thr(["节点","协议","server:port","国家"]));
  rows.forEach(r=>{const tr=h("tr");
    tr.append(h("td",null,r.n),h("td",null,r.p),
      h("td",null,r.s+":"+r.o),h("td",null,r.c||""));t.append(tr);});
  wrap.append(t);return wrap;
}
function buildDetail(a,det){
  det.append(h("div",null,"落地厂商 Top："+(a.detail.owners.length?
    a.detail.owners.map(o=>o[0]+"×"+o[1]).join("，"):"（无 RDAP 信息）")));
  const dv=a.detail;
  if(dv.nodes.length){
    det.append(h("div",null,h("b",null,"节点明细（"+dv.nodes.length+"）")));
    det.append(nodeTable(dv.nodes));
  }else det.append(h("div","muted","当前非空快照无节点。"));
  if(dv.added.length||dv.removed.length||a.added_n||a.removed_n){
    const two=h("div","twocol");
    const mk=(title,rows,total,cap,cls)=>{
      const d=h("div");d.append(h("b",null,title+" "+total));
      if(total>cap)d.append(h("span","muted","（仅显示前 "+cap+" 条）"));
      const u=h("ul");rows.slice(0,cap).forEach(r=>u.append(h("li",cls,
        r.n+" — "+r.p+" "+r.s+":"+r.o+(r.c?" ("+r.c+")":""))));
      d.append(u);return d;};
    two.append(mk("新增",dv.added,a.added_n,200,"up"),mk("消失",dv.removed,a.removed_n,200,"dn"));
    det.append(two);
  }
  if(dv.findings.length){
    det.append(h("b",null,"华为命中 "+dv.findings.length));
    const t=h("table","dtable");
    dv.findings.forEach(f=>{const tr=h("tr");
      tr.append(h("td",null,f.d+"="+f.r),h("td",null,f.e),
        h("td",null,f.x),h("td",null,f.c));t.append(tr);});
    det.append(t);
  }
}
function renderCards(){
  const box=document.getElementById("cards");box.textContent="";
  let list=D.airports.filter(a=>{
    if(state.q&&!a.slug.toLowerCase().includes(state.q))return false;
    if(state.fst==="ok")return a.status==="ok"&&!a.pull_zero&&a.nodes>0&&!a.hit_n;
    if(state.fst==="stale")return a.status==="stale";
    if(state.fst==="pull_zero")return a.pull_zero;
    if(state.fst==="zero_pool")return a.nodes===0;
    if(state.fst==="hit")return a.hit_n>0;
    if(state.fst==="quota30")return !!(a.quota&&a.quota.days_left!==null&&
      a.quota.days_left!==undefined&&a.quota.days_left<=30);
    return true;});
  const key={nodes:a=>-a.nodes,delta:a=>-(a.added_n+a.removed_n),
    age:a=>-(a.age_h||0),name:a=>a.slug}[state.fsort];
  list=list.slice().sort((x,y)=>{const kx=key(x),ky=key(y);
    return kx<ky?-1:kx>ky?1:x.slug<y.slug?-1:1;});
  list.forEach(a=>box.append(cardEl(a)));
  document.getElementById("ccount").textContent="显示 "+list.length+" / "+D.airports.length+" 张卡片";
}
document.getElementById("q").addEventListener("input",e=>{state.q=e.target.value.toLowerCase();renderCards();});
document.getElementById("fst").addEventListener("change",e=>{state.fst=e.target.value;renderCards();});
document.getElementById("fsort").addEventListener("change",e=>{state.fsort=e.target.value;renderCards();});
renderCards();

/* 套餐到期与流量 */
(function(){
  const box=document.getElementById("quota");
  const rows=D.airports.filter(a=>a.quota)
    .sort((x,y)=>{
      const dx=x.quota.days_left,dy=y.quota.days_left;
      const nx=(dx===null||dx===undefined),ny=(dy===null||dy===undefined);
      if(nx&&ny)return x.slug<y.slug?-1:1;
      if(nx)return 1;if(ny)return -1;
      return dx-dy;});
  if(!rows.length){
    box.append(h("div","banner","暂无套餐数据：先运行 python -m airmon.quota 生成 data\\quota.json，再重新生成仪表盘。"));
    return;}
  const t=h("table","dtable");
  t.append(thr(["机场","到期日","剩余","已用/总量(GB)","剩余(GB)","用量","数据时点","来源"]));
  rows.forEach(a=>{const q=a.quota,tr=h("tr");
    const dl=q.days_left,cls=(dl===null||dl===undefined)?"":(dl<0?"red":(dl<=7?"red":(dl<=30?"amber":"")));
    const dls=(dl===null||dl===undefined)?"—":(dl<0?"已过期":dl+" 天");
    const flow=q.unlimited?"不限":(q.total_gb!==null&&q.total_gb!==undefined)?
      (q.used_gb||0)+" / "+q.total_gb:String(q.used_gb||0);
    const rem=q.unlimited?"—":(q.total_gb!==null&&q.total_gb!==undefined)?
      Math.max(0,(q.total_gb||0)-(q.used_gb||0)).toFixed(1):"—";
    const pct=(q.used_pct===null||q.used_pct===undefined)?"—":q.used_pct+"%";
    tr.append(h("td",null,a.slug),h("td",cls,q.expire_date||"无到期日"),h("td",cls,dls),
      h("td",null,flow),h("td",null,rem),h("td",null,pct),
      h("td","muted",q.at||"—"),h("td",null,q.source||"—"));
    t.append(tr);});
  box.append(t);
  const none=D.airports.filter(a=>!a.quota).map(a=>a.slug);
  if(none.length)box.append(h("div","muted","无套餐数据（"+none.length+
    " 机场，多为客户端路线无订阅）："+none.join("、")));
})();

/* diff 区 */
(function(){
  const box=document.getElementById("diff");
  const rows=D.airports.filter(a=>a.added_n||a.removed_n)
    .sort((x,y)=>(y.added_n+y.removed_n)-(x.added_n+x.removed_n));
  if(!rows.length){box.append(h("div","banner","所有机场相对上一份非空快照均无节点增删。"));return;}
  rows.forEach(a=>{
    const d=h("details","drow"),s=h("summary",null,null);
    s.append(document.createTextNode(a.slug+"  "));
    s.append(h("span","up","+"+a.added_n));s.append(document.createTextNode(" / "));
    s.append(h("span","dn","−"+a.removed_n));
    s.append(h("span","muted","　基准 "+num(a.latest_local)+(a.no_prev?"（无上一非空快照）":"")));
    d.append(s);
    const two=h("div","twocol");
    const col=(title,rows,total)=>{const w=h("div");
      w.append(h("b",null,title+" "+total));
      if(total>200)w.append(h("span","muted","（仅显示前 200 条）"));
      const u=h("ul");rows.forEach(r=>u.append(h("li",null,
        r.n+" — "+r.p+" "+r.s+":"+r.o+(r.c?" ("+r.c+")":""))));w.append(u);return w;};
    two.append(col("新增",a.detail.added,a.added_n),col("消失",a.detail.removed,a.removed_n));
    d.append(two);box.append(d);
  });
})();

/* 告警流 */
(function(){
  const box=document.getElementById("alerts");
  if(!D.alerts.length){box.append(h("div","banner","暂无有效告警块（alerts.log 中的空块已过滤）。"));return;}
  D.alerts.forEach(b=>{
    const d=h("div","al"),hd=h("div","h");
    hd.append(h("b",null,b.airport),h("span","muted",b.ts_local||b.ts));
    if(b.hw_n)hd.append(chip("华为 "+b.hw_n,"purple"));
    if(b.added_n)hd.append(chip("+"+b.added_n));
    if(b.removed_n)hd.append(chip("−"+b.removed_n));
    d.append(hd);
    b.hw.forEach(f=>d.append(h("div","hw","["+f.rule+"] "+f.evidence+" ｜ "+f.context+"（"+f.confidence+"）")));
    box.append(d);
  });
})();

/* 华为命中 */
(function(){
  const box=document.getElementById("hw");
  const t1=h("h3",null,"当前快照命中（"+D.hw_current.length+"）");
  box.append(t1);
  if(D.hw_current.length){
    const t=h("table","dtable");
    t.append(thr(["机场","维度=规则","证据","上下文","置信度"]));
    D.hw_current.forEach(f=>{const tr=h("tr");
      tr.append(h("td",null,f.airport),h("td",null,f.d+"="+f.r),h("td",null,f.e),
        h("td",null,f.x),h("td",null,f.c));t.append(tr);});
    box.append(t);
  }else box.append(h("div","muted","当前各机场最新快照无华为命中（服役华为 CDN=0 为常态）。"));
  box.append(h("h3",null,"历史台账（alerts.log 去重，"+D.hw_ledger.length+"）"));
  if(D.hw_ledger.length){
    const t=h("table","dtable");
    t.append(thr(["机场","规则","证据","累计","最近出现"]));
    D.hw_ledger.forEach(v=>{const r=h("tr");
      r.append(h("td",null,v.airport),h("td",null,v.rule),h("td",null,v.evidence),
        h("td",null,v.count),h("td",null,v.last_ts_local));t.append(r);});
    box.append(t);
  }else box.append(h("div","muted","alerts.log 中无历史命中记录。"));
})();

/* 运行健康 */
(function(){
  const box=document.getElementById("health");
  const t=h("table","dtable");
  t.append(thr(["机场","最近成功","陈旧h","24h快照","路线","节点数","本轮拉取","状态"]));
  D.airports.slice().sort((a,b)=>(b.age_h||0)-(a.age_h||0)).forEach(a=>{
    const r=h("tr");
    r.append(h("td",null,a.slug),h("td",null,num(a.latest_local)),
      h("td",null,num(a.age_h)),h("td",null,a.snap24),h("td",null,a.route),
      h("td",null,a.nodes),h("td",null,a.pull_zero?"0 节点":"✓"),
      h("td",null,a.status==="stale"?"陈旧":"正常"));
    t.append(r);});
  box.append(t);
  const rl=D.runlog,panel=h("div","banner");
  if(!rl){panel.append(h("b",null,"run.log 不可读或不存在。"));box.append(panel);return;}
  panel.append(h("b",null,"最近完成一轮（run.log 拉取阶段口径）"));
  panel.append(h("div",null,(rl.start_local||"?")+" → "+(rl.done_local||"未完成")+
    (rl.duration_min!==null&&rl.duration_min!==undefined?"（"+rl.duration_min+" 分钟）":"")+
    (rl.final_aps!==null&&rl.final_aps!==undefined?"　最终 "+rl.final_aps+" 机场 / "+rl.final_nodes+" 节点":"")));
  if(rl.note)panel.append(h("div","muted",rl.note));
  panel.append(h("div",null,"拉取成功 "+rl.ok_n+" 机场 / "+rl.ok_nodes+" 节点"));
  const lists=[["超时跳过",rl.skipped],["0 节点警告",rl.zero],["登录失败",rl.auth]];
  lists.forEach(p=>{if(p[1].length)panel.append(h("div",null,p[0]+"："+p[1].join("、")));});
  const okd=h("details");okd.append(h("summary",null,"本轮各机场拉取节点数"));
  const u=h("ul");(rl.ok_top||[]).forEach(x=>u.append(h("li",null,x.slug+"（"+x.kind+"）： "+x.n)));
  okd.append(u);panel.append(okd);
  box.append(panel);
})();

/* 单机场横幅与页脚 */
if(D.single)document.getElementById("banner").append(
  h("div","banner","单机场视图："+D.single+"（告警与台账已过滤到该机场；run.log 面板仍为全局）"));
document.getElementById("foot").append(
  h("div",null,"生成时间 "+D.generated_at+" · 数据基准 "+D.base_local+
    (D.quota_at?" · 套餐数据 "+D.quota_at:"")+
    " · 陈旧阈值 "+D.stale_hours+"h · 来源 data\\*.json + data\\quota.json + alerts.log + run.log + airports/credentials.yaml（只读）"),
  h("div",null,"脱敏白名单生成：不含订阅 token / 节点密码 / 邮箱 / 密钥字段。"));
</script>
</body>
</html>
"""


def _sanitize_check(html: str) -> list[str]:
    hits = []
    for name, rx in SANITIZE_RULES:
        n = len(rx.findall(html))
        if n:
            hits.append(f"{name}×{n}")
    return hits


def render_html(data: dict) -> str:
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    payload = payload.replace("</", "<\\/")  # 防 JSON 内出现 </script>
    return TEMPLATE.replace("__DATA_JSON__", payload)


def generate(out: str | Path | None = None, airport: str | None = None,
             alert_limit: int = 120, stale_hours: float = 6.0,
             runlog_tail: int = 2_000_000) -> str:
    data = build_data(airport, alert_limit, stale_hours, runlog_tail)
    html = render_html(data)
    hits = _sanitize_check(html)
    if hits:
        # 只报规则与次数，绝不回显命中内容
        raise RuntimeError("脱敏自检未通过，已中止写盘：" + ", ".join(hits))
    out_path = Path(out) if out else DEFAULT_OUT
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    t = data["totals"]
    print(f"机场 {t['airports']}/{t['dirs']}（有节点 {t['with_nodes']}）· "
          f"节点 {t['nodes']} · 华为命中 {t['hits']} · 有效告警块 {len(data['alerts'])}"
          f" · 基准 {data['base_local']}")
    return str(out_path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m airmon.dashboard",
        description="生成静态单文件监控仪表盘 dashboard/index.html（只读 data\\，脱敏白名单）")
    ap.add_argument("--airport", help="仅生成单机场视图")
    ap.add_argument("--out", help="输出路径（默认 dashboard\\index.html）")
    ap.add_argument("--alert-limit", type=int, default=120, help="告警块保留条数（默认 120）")
    ap.add_argument("--stale-hours", type=float, default=6.0,
                    help="陈旧阈值小时数（默认 6，即 2 个调度周期）")
    ap.add_argument("--runlog-tail", type=int, default=2_000_000,
                    help="run.log 尾部解析字节数（默认 2MB）")
    args = ap.parse_args(argv)
    path = generate(out=args.out, airport=args.airport, alert_limit=args.alert_limit,
                    stale_hours=args.stale_hours, runlog_tail=args.runlog_tail)
    print(f"仪表盘已生成 → {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
