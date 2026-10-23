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
import time
from collections import Counter, OrderedDict
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
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
    airports = []
    for slug in slugs:
        sh = sub.get(slug) or {}
        q = quota.get(slug) or {}
        ix = idx_by.get(slug) or {}
        r = reg.get(slug) or {}
        p = probe.get(slug) or {}
        idcp = idc.get(slug) or {}
        c = cv.get(slug) or {}
        state = sh.get("state") or ("A" if (ix.get("nodes") or 0) > 0 else "D")
        nodes = int(ix.get("nodes") or sh.get("nodes") or 0)
        exported = int(ix.get("exported") or 0)
        days = q.get("days_left")
        if days is None:
            e = an_expiry.get(slug)
            days = e.get("days_left") if e else None
        stab = an_stab.get(slug) or {}
        churn = an_churn.get(slug) or {}
        zero = an_zero.get(slug) or {}
        rd = an_rdap.get(slug) or {}
        stale_h = None
        if isinstance(sh.get("stale_h"), (int, float)):
            stale_h = sh["stale_h"]
        else:
            stale_h = snap_age_hours(slug)

        # 节点明细（只出必要字段）
        node_rows = []
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
                    row = [
                        (nd.get("name") or "")[:48],
                        proto,
                        (nd.get("server") or "")[:60],
                        int(nd.get("port") or 0),
                        1 if proto in EXPORTABLE else 0,
                    ]
                    node_rows.append(row)
        except Exception:
            node_rows = []

        airports.append({
            "slug": slug,
            "name_cn": (names.get(slug) or {}).get("cn_short") or (names.get(slug) or {}).get("cn") or "",
            "state": state,
            "nodes": nodes,
            "exported": exported,
            "protos": ix.get("protos") or {},
            "via": "内存扫描" if (ix.get("node_source") == "client_nodes") else ("快照" if ix else "无数据"),
            "days": days,
            "expire": q.get("expire_date"),
            "total_gb": q.get("total_gb"),
            "used_pct": q.get("used_pct"),
            "unlimited": bool(q.get("unlimited")),
            "reason": sh.get("reason") or "",
            "action": sh.get("action") or "",
            "last_ok": sh.get("last_ok"),
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
        "actions": [{"slug": a["slug"], "state": a["state"], "reason": a["reason"], "action": a["action"], "days": a["days"]} for a in actions],
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    # 兜底脱敏：节点名里可能混入机场客服邮箱 / 完整链接
    body = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", "[邮箱已隐]", body)
    body = re.sub(r"https?://[^\s\"']+", "[链接已隐]", body)
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
