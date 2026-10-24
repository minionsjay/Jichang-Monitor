# -*- coding: utf-8 -*-
"""生成面板预览用的静态数据包 docs/09-新界面-preview/app/data.js

只读 data/ 与 nodes/index.json，输出**派生数值**：
不含订阅 URL、token、密码、uuid、auth_token；节点只出 name/proto/server/port/可导出标记。

用法：python -X utf8 tools/gen_panel_data.py
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import time
from collections import Counter, OrderedDict
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from airmon.infra import classify as _infra_classify, label as _infra_label, is_edge as _infra_is_edge  # noqa: E402
OUT = os.path.join(ROOT, "docs", "09-新界面-preview", "app", "data.js")

EXPORTABLE = {"ss", "vmess", "vless", "trojan", "hysteria2", "anytls"}


def jload(path, default=None):
    try:
        with io.open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def load_sub_health():
    return jload(os.path.join(DATA, "sub_health.json"), {}) or {}


def load_quota():
    d = jload(os.path.join(DATA, "quota.json"), {}) or {}
    return d.get("airports") or {}


def load_index():
    return jload(os.path.join(ROOT, "nodes", "index.json"), {}) or {}


def load_analysis():
    return jload(os.path.join(DATA, "analysis.json"), {}) or {}


def load_airports_yaml():
    try:
        import yaml
        with io.open(os.path.join(ROOT, "airports.yaml"), encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def load_credentials_registry():
    """只取 slug -> panel 纯域名，绝不输出 token。"""
    out = {}
    try:
        import yaml
        with io.open(os.path.join(ROOT, "credentials.yaml"), encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
    except Exception:
        return out
    for slug, item in (doc.get("accounts") or {}).items():
        if not isinstance(item, dict):
            continue
        panel = item.get("panel") or ""
        m = re.match(r"^https?://([^/]+)", panel or "")
        if m:
            out[slug] = m.group(1)
    return out


def load_credentials_subs():
    """slug -> 是否有 sub_url（只出布尔，绝不输出链接本身）。"""
    out = {}
    try:
        import yaml
        with io.open(os.path.join(ROOT, "credentials.yaml"), encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
    except Exception:
        return out
    for slug, item in (doc.get("accounts") or {}).items():
        if isinstance(item, dict):
            out[slug] = bool(item.get("sub_url"))
    return out


def latest_ok_local(slug: str, limit: int = 8) -> str | None:
    """最近一次「真拿到节点」的时间（本地时区 YYYY-MM-DD HH:MM）。

    别用 sub_health.json 里那个 last_ok：它是诊断脚本 2026-10-21 的快照，
    后续每轮拉取成功都不会改它，界面上就会出现「今天刚拉到、却显示 2 天前」。
    """
    d = os.path.join(DATA, slug)
    try:
        files = sorted((f for f in os.listdir(d) if re.match(r"\d{8}T\d{6}Z", f)), reverse=True)
    except OSError:
        return None
    for name in files[:limit]:
        try:
            with io.open(os.path.join(d, name), encoding="utf-8") as fh:
                snap = json.load(fh)
        except Exception:
            continue
        if not (snap.get("nodes") or []):
            continue
        try:
            t = datetime.strptime(name[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        return t.astimezone().strftime("%Y-%m-%d %H:%M")
    return None


def latest_snap_info(slug: str, limit: int = 12) -> dict:
    """最近一份「有节点」快照的信息；全都为空则回落最近一份快照。

    返回 {"ts": 本地时间 str|None, "nodes": int, "age_h": float|None}。
    状态判定要用实测：sub_health.json 是诊断脚本某一刻的快照，
    机场后来恢复了它也不会改，界面就会一直挂着「订阅失效」。
    """
    d = os.path.join(DATA, slug)
    try:
        files = sorted((f for f in os.listdir(d) if re.match(r"\d{8}T\d{6}Z", f)), reverse=True)
    except OSError:
        return {"ts": None, "nodes": 0, "age_h": None}
    now = datetime.now(timezone.utc)
    newest = None
    for name in files[:limit]:
        try:
            with io.open(os.path.join(d, name), encoding="utf-8") as fh:
                snap = json.load(fh)
        except Exception:
            continue
        nodes = len(snap.get("nodes") or [])
        try:
            t = datetime.strptime(name[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        age = round((now - t).total_seconds() / 3600.0, 1)
        ts = t.astimezone().strftime("%Y-%m-%d %H:%M")
        if newest is None:
            newest = {"ts": ts, "nodes": 0, "age_h": age}
        if nodes:
            return {"ts": ts, "nodes": nodes, "age_h": age}
    return newest or {"ts": None, "nodes": 0, "age_h": None}


def load_runs(limit: int = 20):
    """最近若干轮次的运行记录（runs.json 由 run.py 5.7 每轮追加）。"""
    rows = jload(os.path.join(ROOT, "data", "runs.json"), []) or []
    if not isinstance(rows, list):
        return []
    out = []
    for r in rows[-limit:]:
        if not isinstance(r, dict):
            continue
        out.append({
            "started_at": r.get("started_at"),
            "ended_at": r.get("ended_at"),
            "duration_s": r.get("duration_s"),
            "status": r.get("status"),
            "pull_ok": r.get("pull_ok"),
            "pull_fail": r.get("pull_fail"),
            "client_scanned": r.get("client_scanned"),
            "airports_active": r.get("airports_active"),
            "nodes_total": r.get("nodes_total"),
            "hw_findings": r.get("hw_findings"),
            "stale_n": r.get("stale_n"),
            "failed": (r.get("failed") or [])[:60],
            "trigger": r.get("trigger") or "manual",
            "derived": bool(r.get("derived")),
        })
    return out


def load_subraw_index():
    """每家机场最近一份订阅原始响应的元信息（不含正文）。"""
    ix = jload(os.path.join(ROOT, "data", "subraw", "index.json"), {}) or {}
    out = {}
    if not isinstance(ix, dict):
        return out
    for slug, v in ix.items():
        if not isinstance(v, dict):
            continue
        out[slug] = {
            "at": v.get("at"),
            "ext": v.get("ext"),
            "bytes": v.get("bytes"),
            "via": v.get("via"),
        }
    return out


def _reach_kind(d, direct_key, proxy_key):
    """直连/代理两组探测结果 -> 分类词。p_ok 为 None 表示那一组没测（代理没开）。"""
    d_ok = (d.get(direct_key) or {}).get("ok")
    pk = d.get(proxy_key)
    p_ok = (pk or {}).get("ok") if isinstance(pk, dict) else None
    if d_ok and p_ok:
        return "both"
    if d_ok:
        return "direct"
    if p_ok:
        return "proxy"
    if d_ok is False and p_ok is None:
        return "direct_fail"
    if d_ok is False and p_ok is False:
        return "none"
    return None


def load_proxy_need():
    """data/proxy_need.json -> (slug -> {sub,panel}, 元信息)。只出分类词，不出 URL。"""
    j = jload(os.path.join(DATA, "proxy_need.json"), {}) or {}
    ap = j.get("airports") or {}
    cnt = ((j.get("summary") or {}).get("counts") or {})
    meta = {"at": j.get("generated_at") or "",
            "proxy_alive": bool(j.get("proxy_alive")),
            "counts": {k: cnt.get(k) for k in
                       ("direct_only", "need_proxy", "both", "unreachable")}}
    out = {}
    for slug, d in ap.items():
        if not isinstance(d, dict):
            continue
        out[slug] = {"sub": _reach_kind(d, "sub_direct", "sub_proxy"),
                     "panel": _reach_kind(d, "panel_direct", "panel_proxy")}
    return out, meta


def load_names():
    """slug -> {cn, src}：卡片显示的中文名（人工维护 data/airport_names.json）。"""
    return jload(os.path.join(DATA, "airport_names.json"), {}) or {}


def load_domains():
    """data/domains.json -> slug -> {n, alive, domains[]}（只含域名/状态码/标题）。"""
    d = jload(os.path.join(DATA, "domains.json"), {}) or {}
    return d.get("airports") or {}


def slug_of_name(name, slug, ascii_slugs):
    if slug in ascii_slugs:
        return slug
    return slug


def snap_age_hours(slug):
    """最近一份快照距今小时数；无目录/无文件返回 None。"""
    d = os.path.join(DATA, slug)
    try:
        names = [n for n in os.listdir(d) if n.endswith(".json")]
    except OSError:
        return None
    if not names:
        return None
    newest = max(names)
    path = os.path.join(d, newest)
    try:
        ts = os.path.getmtime(path)
    except OSError:
        return None
    return round((time.time() - ts) / 3600.0, 1)


def parse_alerts(path, limit=400):
    """alerts.log -> 结构化解块列表。只保留最近 limit 块。"""
    if not os.path.exists(path):
        return []
    with io.open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    blocks = []
    cur = None
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^=====\s*(\S+)\s*\|\s*(\S+)\s*=====$", s)
        if m:
            if cur:
                blocks.append(cur)
            cur = {"ts": m.group(1), "slug": m.group(2), "lines": []}
            continue
        if cur is None:
            continue
        if s:
            cur["lines"].append(s[:200])
    if cur:
        blocks.append(cur)

    out = []
    for b in blocks[-limit:]:
        lines = b["lines"]
        body = " / ".join(lines)
        if not lines:
            continue
        if "最近快照" in body:
            kind = "stale"
        elif "华为" in body:
            kind = "hw"
        elif "新增节点" in body or "消失节点" in body:
            kind = "churn"
        else:
            kind = "other"
        out.append({"ts": b["ts"], "slug": b["slug"], "kind": kind, "lines": lines[:6]})
    return out


def parse_run_log(path, want=60):
    """run.log 尾部（已脱敏：URL 全隐、token 类字段隐）。"""
    if not os.path.exists(path):
        return []
    with io.open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    tail = lines[-want:]
    out = []
    for ln in tail:
        s = ln.rstrip()
        s = re.sub(r"https?://\S+", "＜地址已隐＞", s)
        s = re.sub(r"(token|password|passwd|uuid|aead_key|auth_token|sub_url)=\S+", r"\1=＜已隐＞", s)
        s = s.strip()
        if s:
            out.append(s[:220])
    return out


def main():
    sub = load_sub_health()
    names = load_names()
    quota = load_quota()
    idx = load_index()
    an = load_analysis()
    yaml_doc = load_airports_yaml()
    cred_panel = load_credentials_registry()
    cred_sub = load_credentials_subs()
    dom_all = load_domains()
    last_run = jload(os.path.join(DATA, "last_run.json"), {}) or {}
    hw = jload(os.path.join(DATA, "huawei_findings.json"), {}) or {}
    probe = (jload(os.path.join(DATA, "probe.json"), {}) or {}).get("per_airport") or {}
    idc = (jload(os.path.join(DATA, "idc_profile.json"), {}) or {}).get("per_airport") or {}
    cv = (jload(os.path.join(DATA, "client_versions.json"), {}) or {}).get("airports") or {}
    kn = jload(os.path.join(DATA, "knowledge.json"), []) or []
    sites = jload(os.path.join(DATA, "sites_digest.json"), []) or []
    rdap_cache = jload(os.path.join(DATA, "rdap_cache.json"), {}) or {}

    # airports.yaml 注册表
    reg = {}
    for item in (yaml_doc.get("airports") or []):
        if not isinstance(item, dict):
            continue
        slug = item.get("name")
        if not slug:
            continue
        doms = item.get("domains") or []
        if isinstance(doms, str):
            doms = [doms]
        doms = [d for d in doms if isinstance(d, str)]
        reg[slug] = {
            "type": item.get("type") or "sub",
            "enabled": item.get("enabled", True),
            "panel": (item.get("panel") or "").split("/")[0] or "",
            "homepage": (item.get("homepage") or "").split("/")[0] or "",
            "domains": doms,
            "client": (item.get("client") or {}).get("name") if isinstance(item.get("client"), dict) else None,
        }

    an_rdap = an.get("rdap") or {}
    an_stab = {x["slug"]: x for x in (an.get("stability") or []) if isinstance(x, dict)}
    an_churn = {x["slug"]: x for x in (an.get("churn") or []) if isinstance(x, dict)}
    an_zero = {x["slug"]: x for x in (an.get("zero_rank") or []) if isinstance(x, dict)}
    an_expiry = {x["slug"]: x for x in (an.get("expiry") or []) if isinstance(x, dict)}
    idx_by = {a["slug"]: a for a in (idx.get("airports") or []) if isinstance(a, dict)}

    # 轮次台账
    round_info = {
        "status": last_run.get("status"),
        "step": last_run.get("step"),
        "started_at": last_run.get("started_at"),
        "ended_at": last_run.get("ended_at"),
        "duration_s": last_run.get("duration_s"),
        "pull_ok": len(last_run.get("pull_ok") or []) if isinstance(last_run.get("pull_ok"), list) else last_run.get("pull_ok"),
        "pull_fail": last_run.get("pull_fail") if not isinstance(last_run.get("pull_fail"), list) else len(last_run.get("pull_fail")),
        "airports_active": last_run.get("airports_active"),
        "nodes_total": last_run.get("nodes_total"),
        "hw_findings": last_run.get("hw_findings"),
        "stale": (last_run.get("stale_over_6h") or [])[:20] if isinstance(last_run.get("stale_over_6h"), list) else [],
    }

    # 每机场卡片
    slugs = sorted(set(list(sub.keys()) + [a["slug"] for a in (idx.get("airports") or [])] + list(reg.keys())))
    nodes_by = {}
    runs_hist = load_runs(20)
    subraw_ix = load_subraw_index()
    proxy_ix, proxy_meta = load_proxy_need()
    airports = []
    for slug in slugs:
        sh = sub.get(slug) or {}
        q = quota.get(slug) or {}
        ix = idx_by.get(slug) or {}
        r = reg.get(slug) or {}
        p = probe.get(slug) or {}
        idcp = idc.get(slug) or {}
        c = cv.get(slug) or {}
        # 状态以实测为准：最近一份有节点的快照才说明"现在还能不能拿到节点"
        snapinfo = latest_snap_info(slug)
        live_nodes = int(snapinfo.get("nodes") or 0)
        live_age = snapinfo.get("age_h")
        live_ts = snapinfo.get("ts") or ""
        live_fresh = live_nodes > 0 and isinstance(live_age, (int, float)) and live_age <= 6
        sh_state = sh.get("state")
        if live_nodes > 0 and live_fresh:
            state = "A"
        elif live_nodes > 0:
            # 有节点但不新鲜：保留诊断快照的分类语义（仅客户端/订阅失效/断流），
            # 只把"陈旧"这件事写进文案，别把 B/C/D 一律压成 B。
            state = sh_state if sh_state in ("A", "B", "C", "D") else "B"
            if sh_state == "A":
                state = "B"
        else:
            state = sh_state or ("A" if (ix.get("nodes") or 0) > 0 else "D")
        if ix:
            snap_n = int(ix.get("nodes") or 0)
            frag_ix = int((ix.get("snapshot_protos") or {}).get("unknown") or 0)
        else:
            snap_n, frag_ix = live_nodes, 0
        nodes = max(0, snap_n - frag_ix)   # 可用节点=有协议；unknown 碎片单列
        _frag_ix = frag_ix
        exported = int(ix.get("exported") or 0)
        days = q.get("days_left")
        if days is None:
            e = an_expiry.get(slug)
            days = e.get("days_left") if e else None
        stab = an_stab.get(slug) or {}
        churn = an_churn.get(slug) or {}
        zero = an_zero.get(slug) or {}
        rd = an_rdap.get(slug) or {}
        stale_h = live_age if live_nodes > 0 else snap_age_hours(slug)

        # 节点明细（只出必要字段）
        node_rows = []
        infra_cnt = {}
        frag_n = 0          # 无协议碎片：scan-memory 用「域名:端口」正则捞到的残片，导不出去
        try:
            best = None
            best_ts = ""
            if ix.get("source_snapshot"):
                cands = [ix["source_snapshot"]]
            else:
                cands = []
            for rel in cands:
                path = os.path.join(ROOT, rel.replace("/", os.sep))
                if not os.path.exists(path):
                    continue
                snap = jload(path, {}) or {}
                rows = snap.get("nodes") or []
                if rows and len(rows) >= 0:
                    best = rows
                    best_ts = os.path.basename(rel)
            if best:
                for nd in best:
                    proto = (nd.get("protocol") or "unknown").lower()
                    owner, ikey = "", ""
                    rd = (nd.get("raw") or {}).get("_rdap") or {}
                    for _ip, tup in rd.items():
                        if not tup:
                            continue
                        owner = str(tup[1] or tup[0] or "")[:40]
                        ikey = _infra_classify(tup[1] or "", tup[0] or "")
                        break
                    if ikey:
                        infra_cnt[ikey] = infra_cnt.get(ikey, 0) + 1
                    row = [
                        (nd.get("name") or "")[:48],
                        proto,
                        (nd.get("server") or "")[:60],
                        int(nd.get("port") or 0),
                        1 if proto in EXPORTABLE else 0,
                        owner,
                        _infra_label(ikey) if ikey else "",
                    ]
                    node_rows.append(row)
        except Exception:
            node_rows = []

        # 判定文案：恢复了就把诊断快照里的旧结论显式作废，别让人以为还是坏的
        reason, action = sh.get("reason") or "", sh.get("action") or ""
        if live_nodes > 0 and live_fresh:
            if sh_state and sh_state != "A":
                reason = ("已恢复：最新快照 %s 有 %d 个节点；诊断快照把这家记成 %s 类、原因为「%s」，"
                          "那条结论已过期" % (live_ts, live_nodes, sh_state, (sh.get("reason") or "—")[:36]))
            else:
                reason = "正常：最新快照 %s 有 %d 个节点" % (live_ts, live_nodes)
            action = "无需处理"
        elif live_nodes > 0:
            if sh_state and sh_state != "A":
                reason = ("%s｜注：最新一份有节点的快照是 %s（%s 小时前，%d 个节点）"
                          % ((sh.get("reason") or "尚未判定").rstrip("。"), live_ts, live_age, live_nodes))
                action = sh.get("action") or ""
            else:
                reason = ("诊断记 A 类，但最新一份有节点的快照是 %s（%s 小时前，%d 个节点），采集可能卡住"
                          % (live_ts, live_age, live_nodes))
                action = "看「运行」页与 run.log 是否报错"
        elif sh_state:
            reason = sh.get("reason") or ""
            action = sh.get("action") or ""

        # 快照有节点但全是无协议碎片（内存扫描只拿到域名+端口）→ 拿不到可用节点，不能算「可用」
        if nodes <= 0 and state in ("A", "B") and not (days is not None and days < 0):
            state = "B"
            reason = "快照有 %d 条记录，但全是无协议碎片，拿不到可导入的节点" % snap_n
            action = "打开该客户端后再用「从内核内存捞节点」重新提取"
        elif state == "A" and nodes > 0:
            reason = "正常：最新快照 %s 有 %d 个可用节点" % (live_ts, nodes)

        airports.append({
            "slug": slug,
            "name_cn": (names.get(slug) or {}).get("cn_short") or (names.get(slug) or {}).get("cn") or "",
            "state": state,
            "nodes": nodes,          # 可用节点（有协议、来自 index.json 合并结果）
            "snap_total": snap_n,    # 合并后的节点总数（含无协议碎片）
            "exported": exported,
            "frag": _frag_ix,        # 无协议碎片（内存扫描只拿到域名+端口）
            "protos": ix.get("protos") or {},
            "via": "内存扫描" if (ix.get("node_source") == "client_nodes") else ("快照" if ix else "无数据"),
            "days": days,
            "expire": q.get("expire_date"),
            "total_gb": q.get("total_gb"),
            "used_pct": q.get("used_pct"),
            "unlimited": bool(q.get("unlimited")),
            "reason": reason,
            "action": action,
            "last_ok": latest_ok_local(slug),
            "raw": subraw_ix.get(slug) or None,
            "proxy": proxy_ix.get(slug) or None,
            "stale_h": stale_h,
            "stability": stab.get("pct"),
            "churn": churn.get("churn") or 0,
            "zero_n": zero.get("zero_n") or 0,
            "rdap_org": rd.get("top_org") or idcp.get("rdap_top_org") or "",
            "rdap_share": rd.get("share") or idcp.get("rdap_share"),
            "idc_score": idcp.get("score"),
            "idc_level": idcp.get("level") or "",
            "probe_ok": p.get("ok"),
            "probe_fail": p.get("fail"),
            "client": c.get("client"),
            "client_local": c.get("local_ver"),
            "client_latest": c.get("latest_ver"),
            "client_status": c.get("status"),
            "type": r.get("type") or ("client" if c else "sub"),
            "has_sub": bool(cred_sub.get(slug)),
            "doms_all": (dom_all.get(slug) or {}).get("domains") or [],
            "doms_n": (dom_all.get(slug) or {}).get("n") or 0,
            "doms_alive": (dom_all.get(slug) or {}).get("alive") or 0,
            "panel": r.get("panel") or cred_panel.get(slug, ""),
            "homepage": r.get("homepage") or "",
            "domains": (r.get("domains") or [])[:8],
            "enabled": r.get("enabled", True),
            "infra": [[_infra_label(k), n, (1 if _infra_is_edge(k) else 0)]
                      for k, n in sorted(infra_cnt.items(), key=lambda kv: -kv[1])[:4]],
            "edge_n": sum(n for k, n in infra_cnt.items() if _infra_is_edge(k)),
            "hw_edge": infra_cnt.get("huawei", 0),
            "node_rows": node_rows,
        })
        nodes_by[slug] = node_rows

    # 统计
    def cnt(pred):
        return sum(1 for a in airports if pred(a))

    ok_states = ("A",)
    flap_states = ("B",)
    totals = {
        "airports": len(airports),
        "ok": cnt(lambda a: a["state"] == "A"),
        "b": cnt(lambda a: a["state"] == "B"),
        "c": cnt(lambda a: a["state"] == "C"),
        "d": cnt(lambda a: a["state"] == "D"),
        "nodes": sum(a["nodes"] for a in airports),
        "exported": sum(a["exported"] for a in airports),
        "frag": sum(a.get("frag") or 0 for a in airports),
        "snap_nodes": sum(a.get("snap_total") or 0 for a in airports),
        "with_nodes": cnt(lambda a: a["nodes"] > 0),
        "with_export": cnt(lambda a: a["exported"] > 0),
        "expired": cnt(lambda a: isinstance(a["days"], (int, float)) and a["days"] < 0),
        "expiring30": cnt(lambda a: isinstance(a["days"], (int, float)) and 0 <= a["days"] <= 30),
        "stale": cnt(lambda a: isinstance(a["stale_h"], (int, float)) and a["stale_h"] > 6),
        "hw": (hw.get("summary") or {}).get("entities_total") or 0,
    }

    # 需要人工
    actions = [a for a in airports if a["state"] in ("B", "C") or (a["state"] == "D" and a["action"])]
    actions.sort(key=lambda a: (a["state"], -(a["days"] or 0)))

    alerts = parse_alerts(os.path.join(DATA, "alerts.log"))
    alert_kinds = Counter(x["kind"] for x in alerts)

    # 时间序列（补零）
    ts = an.get("timeseries") or {}
    dates = ts.get("dates") or []
    values = ts.get("totals") or []

    # 知识库（截断正文）
    kn_out = []
    for k in kn:
        if not isinstance(k, dict):
            continue
        first_sec = ""
        secs = k.get("sections") or []
        if secs and isinstance(secs[0], (list, tuple)) and len(secs[0]) > 1:
            first_sec = str(secs[0][1])[:220]
        kn_out.append({
            "slug": k.get("slug"),
            "title": k.get("title"),
            "cat": k.get("cat"),
            "date": k.get("date"),
            "n": k.get("n_sections"),
            "doms": (k.get("doms") or [])[:5],
            "excerpt": re.sub(r"\s+", " ", first_sec).strip(),
        })

    # 推荐站档案：只留与 47 家相关 + 字段瘦身
    related_slugs = set(a["slug"] for a in airports)
    sites_out = []
    for s in sites:
        if not isinstance(s, dict):
            continue
        rel = s.get("related") or ""
        sites_out.append({
            "name": (s.get("name") or "")[:40],
            "cat": s.get("cat") or "",
            "dom": (s.get("dom0") or "")[:48],
            "date": s.get("date") or "",
            "free": (s.get("free") or "")[:40],
            "protos": (s.get("protos") or "")[:60],
            "rel": rel[:80] if rel else "",
        })

    payload = {
        "meta": {
            "built": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "round": round_info,
            "running": last_run.get("status") == "running",
            "base": an.get("base_local"),
            "days": an.get("days"),
            "analysis_at": an.get("generated_at"),
        },
        "totals": totals,
        "airports": airports,
        "alerts": alerts,
        "alertKinds": dict(alert_kinds),
        "hw": {
            "generated_at": hw.get("generated_at"),
            "judges": hw.get("judges"),
            "summary": hw.get("summary") or {},
            "lib": hw.get("airport_lib") or {},
            "entities": (hw.get("entities") or [])[:20],
            "scope": hw.get("scope"),
        },
        "series": {"dates": dates, "values": values},
        "protos": an.get("proto_global") or [],
        "geos": an.get("geo_global") or [],
        "churn": an.get("churn") or [],
        "zero": an.get("zero_rank") or [],
        "stability": an.get("stability") or [],
        "expiry": an.get("expiry") or [],
        "rdap": an_rdap,
        "knowledge": kn_out,
        "sites": sites_out,
        "clients": [dict(slug=slug, **{k: v for k, v in (c or {}).items() if k in ("client", "local_ver", "latest_ver", "status", "note", "node_pull")}) for slug, c in cv.items()],
        "logTail": parse_run_log(os.path.join(ROOT, "run.log")),
        "runs": runs_hist,
        "proxy_meta": proxy_meta,
        "actions": [{"slug": a["slug"], "state": a["state"], "reason": a["reason"], "action": a["action"], "days": a["days"]} for a in actions],
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    # 兜底脱敏：节点名里可能混入机场客服邮箱 / 完整链接
    body = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", "[邮箱已隐]", body)
    body = re.sub(r"https?://[^\s\"']+", "[链接已隐]", body)
    # 面板后端（preview server）读这份，避免抽屉与卡片口径不一致
    try:
        _st = {a["slug"]: {"state": a["state"], "nodes": a["nodes"], "exported": a["exported"],
                           "frag": a.get("frag") or 0, "snap_total": a.get("snap_total") or 0,
                           "reason": a.get("reason") or "", "action": a.get("action") or ""}
               for a in payload["airports"]}
        with io.open(os.path.join(DATA, "panel_state.json"), "w", encoding="utf-8") as fh:
            json.dump(_st, fh, ensure_ascii=False, separators=(",", ":"))
    except Exception as exc:
        print("warn: panel_state.json 写入失败 %s" % exc)

    with io.open(OUT, "w", encoding="utf-8") as f:
        f.write("window.AIRMON=")
        f.write(body)
        f.write(";\n")

    # 自检：绝不带凭据
    bad = 0
    for pat in ("password", "aead_key", "auth_token", "sub_url=", "eyJ", "subscribe?token", "@qq.com", "@gmail.com"):
        if pat in body:
            print("LEAK:", pat)
            bad += 1
    print("written %s | %.1f KB" % (OUT, len(body) / 1024.0))
    print("airports %d | nodes %d | exported %d | alerts %d (stale %d churn %d hw %d) | sites %d | knowledge %d | nodes_rows %d"
          % (len(airports), totals["nodes"], totals["exported"], len(alerts),
             alert_kinds.get("stale", 0), alert_kinds.get("churn", 0), alert_kinds.get("hw", 0),
             len(sites_out), len(kn_out), sum(len(v) for v in nodes_by.values())))
    print("LEAK-CHECK", "CLEAN" if bad == 0 else "FAILED")


if __name__ == "__main__":
    main()
