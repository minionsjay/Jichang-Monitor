"""机场基建画像（流量识别 MVP，docs/07 Phase A）——纯离线四指标。

只读 data/ 下最新快照，不发任何网络流量：
  1. 端口扇出：单个入口 IP 承载的节点端口数（机场特征=海量端口挤在少数 IP）
  2. 高位端口占比：10k-65535 且成连续整数段（自动生成端口池）
  3. 伪 TLD/高风险 TLD：.internal/.go/.local 等不可注册段 + .xyz/.top 等批量注册局
  4. RDAP 机构集中度：top org 覆盖率（复用快照 _rdap，不重查）

输出 data/idc_profile.json（零机密：只有 IP/端口/域名形态统计）。
用法：python -m airmon.idc_profile
"""
from __future__ import annotations

import glob
import ipaddress
import json
import os
import re
import time
from collections import Counter

from .store import DATA_DIR

OUT = os.path.join(DATA_DIR, "idc_profile.json")
_PSEUDO_TLD = {"internal", "go", "local", "home", "lan", "intranet", "corp", "test"}
_BULK_TLD = {"xyz", "top", "icu", "cc", "shop", "site", "online", "pw", "info", "club"}


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def _tld_of(server: str) -> str:
    parts = server.lower().rstrip(".").split(".")
    return parts[-1] if parts else ""


def profile_slug(slug: str) -> dict | None:
    snaps = sorted(f for f in glob.glob(os.path.join(DATA_DIR, slug, "*.json"))
                   if os.path.basename(f).endswith(".json"))
    if not snaps:
        return None
    try:
        with open(snaps[-1], encoding="utf-8") as f:
            s = json.load(f)
    except Exception:
        return None
    nodes = s.get("nodes") or []
    if not nodes:
        return {"n_nodes": 0}

    # 1) 端口扇出（按入口 IP 聚合；无 _resolved_ips 的回退 server 本身）
    by_entry: Counter = Counter()
    ports = []
    tld_counter: Counter = Counter()
    n_ip_direct = 0
    n_domain = 0
    for nd in nodes:
        raw = nd.get("raw") or {}
        ips = raw.get("_resolved_ips") or []
        entry = ips[0] if ips else (nd.get("server") or "")
        if entry:
            by_entry[entry] += 1
        port = int(nd.get("port") or 0)
        if port:
            ports.append(port)
        server = (nd.get("server") or "").lower()
        if _is_ip(server):
            n_ip_direct += 1
        elif server:
            n_domain += 1
            tld_counter[_tld_of(server)] += 1

    top_entry = by_entry.most_common(3)
    max_fanout = top_entry[0][1] if top_entry else 0

    # 2) 高位端口 + 最长连续段
    hi = [p for p in ports if 10000 <= p <= 65535]
    hi_pct = round(len(hi) / len(ports), 3) if ports else 0
    ps = sorted(set(ports))
    max_run = cur = 1
    for i in range(1, len(ps)):
        cur = cur + 1 if ps[i] - ps[i - 1] == 1 else 1
        max_run = max(max_run, cur)

    # 3) 域名形态
    n_pseudo = sum(c for t, c in tld_counter.items() if t in _PSEUDO_TLD)
    n_bulk = sum(c for t, c in tld_counter.items() if t in _BULK_TLD)
    odd_pct = round((n_pseudo + n_bulk) / n_domain, 3) if n_domain else 0

    # 4) RDAP 集中度（最新快照 _rdap）
    org_counter: Counter = Counter()
    for nd in nodes:
        raw = nd.get("raw") or {}
        r = raw.get("_rdap")
        if isinstance(r, dict):
            for v in r.values():
                if isinstance(v, (list, tuple)):
                    org = next((str(x).strip() for x in v
                                if isinstance(x, str) and x.strip()), "")
                    if org:
                        org_counter[org[:40]] += 1
                        break
    n_org_total = sum(org_counter.values())
    top_org, top_org_n = (org_counter.most_common(1)[0] if org_counter else ("", 0))
    rdap_share = round(top_org_n / n_org_total, 3) if n_org_total else 0

    # 综合分（0-100，越高越像机场基建）
    score = round(
        30 * min(1.0, max_fanout / 100)
        + 25 * hi_pct
        + 20 * odd_pct
        + 25 * rdap_share)
    level = ("机场基建特征强" if score >= 70 else
             "中性" if score >= 40 else "低特征")

    return {"n_nodes": len(nodes),
            "max_fanout": max_fanout,
            "fanout_top": [[ip, n] for ip, n in top_entry],
            "n_entries": len(by_entry),
            "hi_port_pct": hi_pct,
            "port_max_run": max_run,
            "ip_direct_pct": round(n_ip_direct / len(nodes), 3),
            "pseudo_tld_pct": round(n_pseudo / n_domain, 3) if n_domain else 0,
            "bulk_tld_pct": round(n_bulk / n_domain, 3) if n_domain else 0,
            "tld_top": [[t, c] for t, c in tld_counter.most_common(5)],
            "rdap_top_org": top_org,
            "rdap_share": rdap_share,
            "score": score,
            "level": level}


def build() -> dict:
    slugs = [os.path.basename(d) for d in sorted(glob.glob(os.path.join(DATA_DIR, "*")))
             if os.path.isdir(d) and not os.path.basename(d).startswith(("_", "."))]
    out = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "per_airport": {}}
    for slug in slugs:
        try:
            p = profile_slug(slug)
        except Exception:
            p = None
        if p and p.get("n_nodes", 0) > 0:
            out["per_airport"][slug] = p
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
    os.replace(tmp, OUT)
    return out


def main(argv=None):
    r = build()
    n = len(r["per_airport"])
    strong = [s for s, p in r["per_airport"].items() if p.get("level") == "机场基建特征强"]
    print(f"基建画像 → {OUT}（{n} 机场；特征强 {len(strong)}：{', '.join(strong[:8])}）")


if __name__ == "__main__":
    raise SystemExit(main())
