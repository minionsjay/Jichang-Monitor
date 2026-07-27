"""汇总所有机场最新快照 → 生成整理好的节点分析报告(Markdown)。

报告含:总览、按机场、按落地厂商、按地区/国家、华为关联、落地被隐藏的机场。
"""
from __future__ import annotations

import glob
import json
import os
from collections import Counter, defaultdict

from . import store


def _latest_snapshots() -> dict[str, dict]:
    out = {}
    for d in sorted(glob.glob(os.path.join(store.DATA_DIR, "*/"))):
        slug = os.path.basename(d.rstrip("/"))
        snaps = sorted(glob.glob(os.path.join(d, "*.json")))
        if snaps:
            out[slug] = json.load(open(snaps[-1], encoding="utf-8"))
    return out


def _owner(info) -> str:
    if not info:
        return ""
    o = (info[1] or info[0] or "").strip()
    for junk in (" administrator", " Administrator", " administrator administrator"):
        if o.endswith(junk):
            o = o[: -len(junk)]
    return o[:34]


def generate(out_path: str | None = None) -> str:
    snaps = _latest_snapshots()
    out_path = out_path or os.path.join(store.DATA_DIR, "report.md")

    total_nodes = 0
    total_hw = 0
    vendor_nodes = Counter()             # owner -> 节点数
    vendor_airports = defaultdict(set)   # owner -> {机场}
    country_nodes = Counter()
    per_airport = []                     # (slug, n, protos, resolved, top_vendors, hw, countries)
    all_findings = []
    hidden = []                          # 落地大量解析不到的机场

    for slug, s in snaps.items():
        nodes = s["nodes"]
        n = len(nodes)
        if n == 0:
            continue
        total_nodes += n
        total_hw += len(s["findings"])
        all_findings += [(slug, f) for f in s["findings"]]
        protos = Counter(nd["protocol"] for nd in nodes)
        resolved = 0
        vend = Counter()
        ctys = Counter()
        for nd in nodes:
            ips = nd["raw"].get("_resolved_ips") or []
            if ips:
                resolved += 1
            rd = nd["raw"].get("_rdap") or {}
            for ip in ips:
                o = _owner(rd.get(ip))
                if o and not o.startswith("n/a"):
                    vend[o] += 1
                    vendor_nodes[o] += 1
                    vendor_airports[o].add(slug)
                    c = (rd.get(ip) or ["", "", "", ""])[2]
                    if c:
                        ctys[c] += 1
                        country_nodes[c] += 1
        per_airport.append((slug, n, protos, resolved, vend.most_common(3),
                            len(s["findings"]), ctys.most_common(3)))
        if n and resolved / n < 0.5:      # 过半解析不到 → 落地被藏
            hidden.append((slug, resolved, n))

    lines = []
    a = lines.append
    a("# 机场节点分析报告\n")
    a(f"> 生成时间：{store.now_iso()} · 机场 {len(per_airport)} 个 · "
      f"节点 {total_nodes} 个 · 华为关联命中 {total_hw} 条\n")

    a("## 一、总览\n")
    a(f"- **机场数**：{len(per_airport)}")
    a(f"- **节点总数**：{total_nodes}")
    a(f"- **华为关联命中**：{total_hw}")
    a(f"- **落地被隐藏(GeoDNS)的机场**：{len(hidden)}\n")

    a("## 二、按机场\n")
    a("| 机场 | 节点 | 协议 | 落地厂商(Top) | 落地地区 | 华为 | 落地可见 |")
    a("|---|---|---|---|---|---|---|")
    for slug, n, protos, resolved, topv, hw, ctys in sorted(per_airport, key=lambda x: -x[1]):
        p = " ".join(f"{k}×{v}" for k, v in protos.most_common(3))
        v = "; ".join(f"{o}×{c}" for o, c in topv) or "—"
        cs = " ".join(f"{k}{v}" for k, v in ctys) or "—"
        vis = f"{resolved}/{n}"
        a(f"| {slug} | {n} | {p} | {v} | {cs} | {'⚠️'+str(hw) if hw else '0'} | {vis} |")
    a("")

    a("## 三、按落地厂商（节点归属整理）\n")
    a("| 厂商 / RDAP owner | 节点数 | 涉及机场 |")
    a("|---|---|---|")
    for o, c in vendor_nodes.most_common(30):
        aps = ", ".join(sorted(vendor_airports[o]))
        a(f"| {o} | {c} | {aps} |")
    a("")

    a("## 四、按地区 / 国家\n")
    a("| 国家/地区 | 节点数 |")
    a("|---|---|")
    for c, n in country_nodes.most_common():
        a(f"| {c} | {n} |")
    a("")

    a("## 五、华为关联命中\n")
    if all_findings:
        for slug, f in all_findings:
            a(f"- **{slug}** · {f['dimension']}={f['rule']} · 证据 `{f['evidence']}` · {f['context']}")
    else:
        a("_无华为关联命中。_")
    a("")

    a("## 六、落地被隐藏的机场（GeoDNS，本环境看不穿）\n")
    if hidden:
        a("| 机场 | 可解析/总数 | 说明 |")
        a("|---|---|---|")
        for slug, r, n in sorted(hidden, key=lambda x: x[1] - x[2]):
            a(f"| {slug} | {r}/{n} | server 域名企业GeoDNS，非目标网络 NXDOMAIN |")
    else:
        a("_无。_")
    a("")

    text = "\n".join(lines)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    return out_path
