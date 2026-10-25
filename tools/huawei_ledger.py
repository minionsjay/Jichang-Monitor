"""华为关联台账：按修正后的引擎重跑全库检测，并把历史命中归集成「类型分析」。

用法：
  python -X utf8 tools/huawei_ledger.py                 # 当前快照重算 + 历史归集
  python -X utf8 tools/huawei_ledger.py --days 30        # 限定历史回看天数
  python -X utf8 tools/huawei_ledger.py --out data/huawei_ledger.json

产出 data/huawei_ledger.json：
  generated_at / engine
  scanned   —— 扫了多少机场/快照/节点
  current   —— 用当前快照重算的结果（分类型 + 明细）
  history   —— 历史上所有快照里存过的命中（按维度/日期聚合）+ 复核结论
  types     —— 四类语义说明

四种类型（这是本工具存在的意义：同样叫「华为主机」其实是四件不同的事）：
  A 真在华为云   —— 节点 IP 的 RDAP/ASN/CIDR 归华为云（有被封风险，是真正的「华为云机场」）
  B 经华为 CDN   —— 节点域名 CNAME 到 cdnhwc*/hcdnw* 等华为 CDN 接入域
  C 大厂域前置   —— server 直接写别人的大厂域名（如 chat.deepseek.com），借它的 IP 过墙
  D 无佐证      —— 域名里有华为特征但解析不出 IP，只能算「疑似」，不进命中计数
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from airmon.detect import Detector          # noqa: E402
from airmon.models import Node              # noqa: E402
from airmon import snapnames                # noqa: E402
from airmon.store import DATA_DIR           # noqa: E402

OUT = os.path.join(DATA_DIR, "huawei_ledger.json")

TYPE_DESC = {
    "A": "节点真在华为云（IP 的 RDAP/ASN/网段归华为云）—— 这才是通常说的「华为云机场」",
    "B": "节点域名 CNAME 到华为云 CDN —— 借 CDN 做中转/加速",
    "C": "借大厂域名做前置 —— server 直接写别人的域名，用它的 IP 过墙，机器不在华为云",
    "D": "域名含华为特征但解析不出 IP —— 无佐证，不计入命中",
}

# 维度 → 类型
DIM_TYPE = {
    "rdap_name": "A",
    "asn": "A",
    "cidr": "A",
    "huawei_cdn_relay": "B",
    "fronting": "C",
    "domain": "D",
}


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _node_of(d):
    raw = d.get("raw") or {}
    n = Node(name=d.get("name", ""), protocol=d.get("protocol", ""),
             server=d.get("server", ""), port=int(d.get("port") or 0), raw=raw)
    return n


def _weak_names(nodes):
    """协议不明、也不是完整对象的节点：内存里把解析出来的 IP 当 server 写进去的碎片。

    典型：ssrdog 的 node-44313 / node-44352，server=116.205.40.114（chat.deepseek.com
    解析出的华为 IP），proto=unknown、raw 无 _complete——那不是「机场的节点在华为云」。
    """
    out = set()
    for n in nodes:
        proto = (n.protocol or "unknown").lower()
        if proto in ("", "unknown") and not (n.raw or {}).get("_complete"):
            out.add(n.name or n.server)
    return out


def _type_of(f, fronting_names):
    """把一条 finding 归到 A/B/C/D。

    关键：如果命中的 IP 是「大厂域名解析出来的」（节点 server = chat.deepseek.com），
    那 IP 落地在华为云是大厂自己选的机房，与机场无关 → 归 C（前置），不算 A。
    """
    if f.dimension == "fronting":
        return "C"
    nm = (f.context or "").replace("节点 ", "", 1)
    if nm in fronting_names:
        return "C"
    return DIM_TYPE.get(f.dimension, "?")


def scan_current(det: Detector):
    """对每个机场的最新快照重跑一遍检测（不重新联网，用快照里已有的解析结果）。"""
    out = []
    scanned_nodes = 0
    for path in sorted(glob.glob(os.path.join(DATA_DIR, "*", "*.json"))):
        slug = os.path.basename(os.path.dirname(path))
        if slug.startswith("_"):
            continue
        name = os.path.basename(path)
        if not snapnames.is_snap(name):
            continue
        out.append((slug, path))
    # 每机场只留最新一份
    latest = {}
    for slug, path in out:
        cur = latest.get(slug)
        if cur is None or snapnames.epoch(os.path.basename(path)) > snapnames.epoch(os.path.basename(cur)):
            latest[slug] = path

    findings_all = []
    for slug, path in sorted(latest.items()):
        snap = _load(path)
        if not snap:
            continue
        nodes = [_node_of(d) for d in (snap.get("nodes") or [])]
        scanned_nodes += len(nodes)
        rdap_map = {}
        for d in (snap.get("nodes") or []):
            for ip, rec in ((d.get("raw") or {}).get("_rdap") or {}).items():
                if isinstance(rec, (list, tuple)) and len(rec) >= 4:
                    rdap_map[ip] = (rec[0], rec[1], rec[2], rec[3])
        fnames = {(n.name or n.server) for n in nodes if det.is_fronting(n)}
        wnames = _weak_names(nodes)
        wnames = _weak_names(nodes)
        for f in det.scan_nodes(slug, nodes, rdap_map):
            _nm = (f.context or "").replace("节点 ", "", 1)
            findings_all.append({
                "airport": f.airport, "type": _type_of(f, fnames),
                "via_fronting": (_nm in fnames and f.dimension != "fronting"),
                "weak_node": (_nm in wnames),
                "dimension": f.dimension, "rule": f.rule,
                "evidence": f.evidence, "context": f.context,
                "confidence": f.confidence,
                "snapshot": os.path.basename(path),
            })
    return findings_all, len(latest), scanned_nodes


def scan_history(det: Detector, days: int):
    """历史命中：用**现在的引擎**重算历史快照，而不是读旧引擎存下的 findings。

    这样历史的数字与当前口径一致（同一个 bug 不会被历史数据继承）。
    额外记录 `sane`：命中所在的节点 server 是否是合法 host——内存碎片
    （43.131.39.48fastlink.so、多个域名连写）会把假 IP 带进 RDAP 查询，
    历史上大量「华为主机」其实来自这些碎片。
    返回 (华为相关命中, 仅大厂域前置命中, 扫了多少份快照)。
    """
    from airmon.detect import is_sane_host     # noqa: E402

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    files = []
    for path in glob.glob(os.path.join(DATA_DIR, "*", "*.json")):
        slug = os.path.basename(os.path.dirname(path))
        if slug.startswith("_"):
            continue
        name = os.path.basename(path)
        if not snapnames.is_snap(name):
            continue
        try:
            if snapnames.epoch(name) < cutoff.timestamp():
                continue
        except Exception:
            continue
        files.append((slug, path))

    hw_rows, fr_rows = [], []
    used = 0
    for slug, path in files:
        snap = _load(path)
        if not snap:
            continue
        used += 1
        nodes = [_node_of(d) for d in (snap.get("nodes") or [])]
        if not nodes:
            continue
        rdap_map = {}
        for d in (snap.get("nodes") or []):
            for ip, rec in ((d.get("raw") or {}).get("_rdap") or {}).items():
                if isinstance(rec, (list, tuple)) and len(rec) >= 4:
                    rdap_map[ip] = (rec[0], rec[1], rec[2], rec[3])
        sane = {}
        for n in nodes:
            sane[n.name or n.server] = is_sane_host(n.server)
        fnames = {(n.name or n.server) for n in nodes if det.is_fronting(n)}
        wnames = _weak_names(nodes)
        ts = snap.get("ts") or ""
        for f in det.scan_nodes(slug, nodes, rdap_map):
            nm = (f.context or "").replace("节点 ", "", 1)
            row = {
                "airport": slug,
                "date": ts[:10],
                "dimension": f.dimension,
                "rule": f.rule,
                "evidence": (f.evidence or "")[:120],
                "confidence": f.confidence,
                "sane": bool(sane.get(nm, True)),
                "via_fronting": bool(f.dimension != "fronting" and nm in fnames),
                "weak_node": bool(nm in wnames),
                "snapshot": os.path.basename(path),
            }
            # fronting 不是「华为」，单列；其余才是华为相关
            (fr_rows if f.dimension == "fronting" else hw_rows).append(row)
    return hw_rows, fr_rows, used


def scan_old_findings(days: int):
    """旧引擎当年存进快照的 findings（用来复核 domain 误报的历史结论）。"""
    from airmon.detect import _is_clean_domain     # noqa: E402

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = []
    for path in glob.glob(os.path.join(DATA_DIR, "*", "*.json")):
        slug = os.path.basename(os.path.dirname(path))
        if slug.startswith("_"):
            continue
        name = os.path.basename(path)
        if not snapnames.is_snap(name):
            continue
        try:
            if snapnames.epoch(name) < cutoff.timestamp():
                continue
            with open(path, "rb") as f:
                blob = f.read()
        except Exception:
            continue
        if b'"dimension"' not in blob or b'"domain"' not in blob:
            continue
        snap = _load(path)
        if not snap:
            continue
        for f in (snap.get("findings") or []):
            if f.get("dimension") != "domain":
                continue
            ev = f.get("evidence") or ""
            rows.append({"date": (snap.get("ts") or "")[:10], "evidence": ev[:120],
                         "glued": not _is_clean_domain(ev)})
    return rows


def _count_by(rows, key):
    out = {}
    for r in rows:
        out[r.get(key) or "?"] = out.get(r.get(key) or "?", 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1])[:20])


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=30, help="历史回看天数")
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args(argv)

    det = Detector()
    cur, n_ap, n_nodes = scan_current(det)
    hist, fr_hist, n_files = scan_history(det, args.days)
    old_dom = scan_old_findings(args.days)

    # 当前：按类型汇总
    by_type = {"A": 0, "B": 0, "C": 0, "D": 0}
    for f in cur:
        if f["confidence"] == "low":
            continue           # 无佐证的 D 类不进计数
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1
    hit_airports = sorted({f["airport"] for f in cur if f["confidence"] != "low"})

    # 历史：按维度聚合
    hist_dim = {}
    hist_by_date = {}
    hist_by_airport = {}
    ips_seen = {}
    frag_dim = {}
    front_derived = {}
    for r in hist:
        if r.get("via_fronting") or r.get("weak_node"):
            k = "fronting" if r.get("via_fronting") else "weak"
            front_derived[k + ":" + r["dimension"]] = front_derived.get(k + ":" + r["dimension"], 0) + 1
            continue          # 前置带出 / 碎片节点，与机场自身无关
        if not r.get("sane", True):
            frag_dim[r["dimension"]] = frag_dim.get(r["dimension"], 0) + 1
        hist_dim[r["dimension"]] = hist_dim.get(r["dimension"], 0) + 1
        d = r["date"] or "?"
        hist_by_date.setdefault(d, {})
        hist_by_date[d][r["dimension"]] = hist_by_date[d].get(r["dimension"], 0) + 1
        if not r.get("sane", True):
            continue          # 碎片节点上的命中不进机场台账
        a = hist_by_airport.setdefault(r["airport"], {
            "total": 0, "rdap_name": 0, "asn": 0, "domain": 0,
            "first": d, "last": d, "ips": []})
        a["total"] += 1
        a[r["dimension"]] = a.get(r["dimension"], 0) + 1
        if d < a["first"]:
            a["first"] = d
        if d > a["last"]:
            a["last"] = d
        ev = (r["evidence"] or "").split("/")[0].strip()
        if r["dimension"] in ("rdap_name", "asn", "cidr") and ev and ev not in a["ips"]:
            a["ips"].append(ev)
            ips_seen[ev] = ips_seen.get(ev, 0) + 1
    for a in hist_by_airport.values():
        a["ips"] = a["ips"][:8]

    # 历史 domain 命中的复核：用新引擎规则复检（结构校验 + 短串边界）
    dom_hist = old_dom
    dom_bad = [r for r in dom_hist if r["glued"]]
    dom_legal = sorted({r["evidence"] for r in dom_hist if not r["glued"]})[:20]

    data = {
        "generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"),
        "engine": "detect.py · domain 需结构合法+解析佐证；新增 huawei_cdn_relay / fronting",
        "scanned": {"airports": n_ap, "nodes": n_nodes, "history_snapshots": n_files,
                    "history_days": args.days},
        "current": {
            "by_type": by_type,
            "airports_with_hits": hit_airports,
            "findings": [f for f in cur if f["confidence"] != "low"
                         and not f.get("weak_node") and not f.get("via_fronting")][:200],
            "low_only": [f for f in cur if f["confidence"] == "low"][:50],
        },
        "history": {
            "by_dimension": hist_dim,
            "fragment_hits": frag_dim,
            "fronting_derived_hits": front_derived,
            "fronting_hits": len(fr_hist),
            "fronting_by_airport": _count_by(fr_hist, "airport"),
            "fragment_total": sum(frag_dim.values()),
            "by_date": dict(sorted(hist_by_date.items())[-30:]),
            "by_airport": dict(sorted(hist_by_airport.items(),
                                      key=lambda kv: -kv[1]["total"])),
            "ip_count": len(ips_seen),
            "top_ips": sorted(ips_seen.items(), key=lambda kv: -kv[1])[:15],
            "domain_review": {
                "total": len(dom_hist),
                "glued_or_invalid": len(dom_bad),
                "legal_but_unverified": dom_legal,
                "verdict": (f"{len(dom_bad)}/{len(dom_hist)} 条 domain 命中的证据不是合法域名"
                            "（内存拼接串），已确认误报；新引擎不再产出这类命中"),
            },
        },
        "types": TYPE_DESC,
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, args.out)

    print(f"airports {n_ap} | nodes {n_nodes} | history_snapshots {n_files}")
    print(f"current  A真华为云 {by_type['A']} | B经华为CDN {by_type['B']} | "
          f"C大厂前置 {by_type['C']} | D无佐证 {by_type['D']}")
    print(f"history  {hist_dim} | 碎片 {sum(frag_dim.values())} 条 + 前置带出 "
          f"{sum(front_derived.values())} 条已剔除")
    print(f"fronting {len(fr_hist)} 条（大厂域前置，单列不计入华为）")
    print(f"domain   {len(dom_bad)}/{len(dom_hist)} 条为拼接串误报")
    print(f"[写盘] {args.out}")

    # 泄漏自检：台账里只有域名/IP/规则名，不该有凭据
    blob = json.dumps(data, ensure_ascii=False)
    bad = [p for p in ("password", "sub_url", "eyJ", "aead_key", "auth_token", "@") if p in blob]
    print("LEAK-CHECK", "CLEAN" if not bad else f"HIT {bad}")
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
