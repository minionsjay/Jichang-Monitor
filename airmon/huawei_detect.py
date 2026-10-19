# -*- coding: utf-8 -*-
"""华为云租户「翻墙/机场」检测引擎（判据评分卡）。

设计来源：《华为云机场流量主动识别-方案总纲》判据体系 + docs/07 离线验证。
架构 = 日志适配器 → 统一会话记录 → 判据评分卡 → 发现报告。

本模块不联网、不读订阅，只做纯离线分析：
  python -m airmon.huawei_detect --selftest          # 内置合成样本冒烟
  python -m airmon.huawei_detect --in <日志文件> --fmt vpc-flowlog|cfw-json|generic-csv
  python -m airmon.huawei_detect --list-formats

判据（J1-J6）：
  J1 长连接大流量    duration>=600s 且 bytes>=10MB
  J2 高位端口        dport>=10000（10k-65k 是机场节点常用段，docs/07）
  J3 目的扇入        同一 (dst,dport) 被 >=3 个不同源连过（共享代理池特征）
  J4 字节比异常      bytes/packets 均值 > 8000（少报文大流量=加密隧道）
  J5 机场基建命中    dst 或 src 命中本机 44 机场节点 IP/域名集合（最强判据）
  J6 机场域名命中    host/QueryName 命中域名全集活域（CFW/DNS 日志独有）

评分（对聚合实体）：机场 IP 命中 90 / 域名命中 80 / 扇入 +25~35 /
高位端口占比>50% +20 / 长连接每条 +10（cap30）/ 字节比 +15。
level：>=70 强、40-70 疑似、<40 低。

输出 data/huawei_findings.json（tmp+os.replace 原子写；报告含内部 IP，
scope=internal 注记，仅供本机面板显示——面板侧对 src 打码）。
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

_HERE = Path(__file__).resolve().parent
PROJECT = _HERE.parent
DATA_DIR = PROJECT / "data"
OUT_FILE = DATA_DIR / "huawei_findings.json"

# ---- 机场基建关联库（J5/J6 判据的底料） ------------------------------
_SLUG_RE = re.compile(r"^[\w.\-]{1,40}$")
_SNAP_RE = re.compile(r"^\d{8}T\d{6}Z\.json$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9\u4e00-\u9fa5][\w.\-\u4e00-\u9fa5]*\.[a-zA-Z\u4e00-\u9fa5]{2,24}$")


def _ip_norm(v: str) -> str:
    v = str(v or "").strip()
    return v if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v) else ""


def load_airport_ips(data_dir: Path = DATA_DIR) -> dict[str, set[str]]:
    """slug -> {节点 server 域名(小写), 解析 IP}。取每机场最新非空快照。"""
    out: dict[str, set[str]] = {}
    if not data_dir.is_dir():
        return out
    for d in sorted(data_dir.iterdir()):
        if not d.is_dir() or d.name.startswith(("_", ".")) or not _SLUG_RE.match(d.name):
            continue
        snaps = sorted(f for f in d.glob("*.json") if _SNAP_RE.match(f.name))
        picked = None
        for f in reversed(snaps):  # 最新优先，找第一份非空
            try:
                j = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            nodes = j.get("nodes") or []
            if nodes:
                picked = nodes
                break
        if not picked:
            continue
        bag: set[str] = set()
        for nd in picked:
            raw = nd.get("raw") or {}
            s = str(nd.get("server") or "").strip().lower()
            if s:
                bag.add(s)
            ips = raw.get("_resolved_ips") or []
            for ip in ips[:1]:
                ip = _ip_norm(ip)
                if ip:
                    bag.add(ip)
        if bag:
            out[d.name] = bag
    return out


def load_airport_domains() -> set[str]:
    """域名全集活域（docs/机场域名全集 CSV 的 域名入口 列，仅 2xx 行）。"""
    p = PROJECT / "docs" / "机场域名全集-2026-10-18.csv"
    doms: set[str] = set()
    if not p.is_file():
        return doms
    try:
        with io.open(p, encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                d = str(row.get("域名入口") or "").strip().lower()
                st = str(row.get("状态") or "")
                if d and _DOMAIN_RE.match(d) and st.startswith("200"):
                    doms.add(d)
    except Exception:
        pass
    return doms


# ---- 统一会话记录 ----------------------------------------------------
# src/dst 归一化字符串（IP 或小写域名）；proto: tcp/udp/other；epoch 秒。
class SessionRecord(dict):
    pass


def _mk(src, dst, sport, dport, proto, packets, byts, start, end,
        direction="", action="", host="", app=""):
    return SessionRecord(
        src=str(src or "").strip().lower(), dst=str(dst or "").strip().lower(),
        sport=int(sport or 0), dport=int(dport or 0),
        proto=proto if proto in ("tcp", "udp") else "other",
        packets=int(packets or 0), bytes=int(byts or 0),
        start=float(start or 0), end=float(end or 0),
        direction=str(direction or ""), action=str(action or ""),
        host=str(host or "").strip().lower(), app=str(app or ""))


# ---- 适配器：华为云各日志格式 → SessionRecord ------------------------
def parse_vpc_flowlog(text: str) -> list[SessionRecord]:
    """华为云 VPC 流日志 CSV。官方列序（v20）：
    0version 1project-id 2interface-id 3srcaddr 4dstaddr 5srcport 6dstport
    7protocol(IANA) 8packets 9bytes 10start 11end 12action 13log-status
    14direction 15tcp-flag ...。首行若为官方字段表头自动跳过；无表头按列序。"""
    rows = list(csv.reader(io.StringIO(text)))
    if rows and "srcaddr" in ",".join(rows[0]).lower():
        rows = rows[1:]
    out = []
    for r in rows:
        if len(r) < 15:
            continue
        try:
            proto = {"6": "tcp", "17": "udp"}.get(r[7].strip(), "other")
            out.append(_mk(r[3], r[4], r[5], r[6], proto,
                           r[8], r[9], r[10], r[11],
                           direction=r[14], action=r[12]))
        except Exception:
            continue
    return out


def parse_cfw_json(text: str) -> list[SessionRecord]:
    """CFW 流量/访问控制日志 JSON 数组或 JSONL（src_ip/dst_ip/dst_host/app/...）。"""
    out = []
    obj = None
    try:
        obj = json.loads(text)
    except Exception:
        obj = None
    items = obj if isinstance(obj, list) else None
    if items is None:
        items = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except Exception:
                continue
    for it in items or []:
        if not isinstance(it, dict):
            continue
        proto = str(it.get("protocol") or it.get("proto") or "").lower()
        proto = proto if proto in ("tcp", "udp") else ("tcp" if proto in ("6",) else "other")
        t0 = it.get("start_time") or it.get("start") or it.get("hit_time") or 0
        t1 = it.get("end_time") or it.get("end") or t0
        out.append(_mk(it.get("src_ip") or it.get("srcaddr"),
                       it.get("dst_ip") or it.get("dstaddr"),
                       it.get("src_port") or it.get("srcport"),
                       it.get("dst_port") or it.get("dstport"), proto,
                       it.get("packets") or it.get("to_s_pkts"),
                       it.get("bytes") or it.get("to_s_bytes"), t0, t1,
                       direction=it.get("direction"), action=it.get("action"),
                       host=it.get("dst_host") or it.get("QueryName") or "", app=it.get("app")))
    return out


def parse_generic_csv(text: str) -> list[SessionRecord]:
    """通用 CSV：src,dst,sport,dport,proto,packets,bytes,start,end[,host,direction,action]。"""
    out = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 9 or row[0].lower().startswith("src"):
            continue
        try:
            out.append(_mk(row[0], row[1], row[2], row[3], row[4], row[5], row[6],
                           row[7], row[8],
                           host=(row[9] if len(row) > 9 else ""),
                           direction=(row[10] if len(row) > 10 else ""),
                           action=(row[11] if len(row) > 11 else "")))
        except Exception:
            continue
    return out


FORMATS = {"vpc-flowlog": parse_vpc_flowlog, "cfw-json": parse_cfw_json,
           "generic-csv": parse_generic_csv}

# ---- 判据与评分 ------------------------------------------------------
_HI_PORT = 10000


def score_sessions(recs: list[SessionRecord], ips: dict[str, set[str]],
                   doms: set[str]) -> dict:
    """跑 J1-J6 判据，按聚合实体（dst 优先）出评分卡。"""
    # J5 命中表：ip/域名 -> slug 集合
    ip2slug: dict[str, set[str]] = defaultdict(set)
    dom2slug: dict[str, set[str]] = defaultdict(set)
    for slug, bag in ips.items():
        for v in bag:
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
                ip2slug[v].add(slug)
            else:
                dom2slug[v].add(slug)
    for d in doms:
        dom2slug[d] = dom2slug.get(d, set()) | {"<domain-set>"}

    # J3 扇入
    fanin: dict[tuple[str, int], set[str]] = defaultdict(set)
    per_dst: dict[str, list[SessionRecord]] = defaultdict(list)
    for r in recs:
        if r["dst"]:
            per_dst[r["dst"]].append(r)
            if r["dport"]:
                fanin[(r["dst"], r["dport"])].add(r["src"])

    entities = []
    for dst, rs in per_dst.items():
        n = len(rs)
        bytes_sum = sum(r["bytes"] for r in rs)
        pkts_sum = sum(r["packets"] for r in rs)
        long_n = sum(1 for r in rs
                     if r["end"] > r["start"] and r["end"] - r["start"] >= 600
                     and r["bytes"] >= 10 * 1024 * 1024)            # J1
        hi_n = sum(1 for r in rs if r["dport"] >= _HI_PORT)          # J2
        fan_n = max((len(fanin[(dst, r["dport"])]) for r in rs if r["dport"]), default=0)  # J3
        bpr = bytes_sum / pkts_sum if pkts_sum else 0.0             # J4
        hits_ip = sorted(ip2slug.get(dst) or set())                  # J5
        hits_dom = sorted(dom2slug.get(dst) or set())                # J6

        s = 0
        why = []
        if hits_ip:
            s += 90
            why.append("机场节点IP命中:" + ",".join(hits_ip[:3]))
        if hits_dom:
            s = max(s, 80)
            why.append("机场域名命中:" + ",".join(hits_dom[:3]))
        if fan_n >= 3:
            s += 35 if fan_n >= 10 else 25
            why.append(f"扇入{fan_n}源")
        if n and hi_n / n > 0.5:
            s += 20
            why.append(f"高位端口{int(hi_n * 100 / n)}%")
        if long_n:
            s += min(30, long_n * 10)
            why.append(f"长连接{long_n}条")
        if bpr > 8000:
            s += 15
            why.append(f"字节比{int(bpr)}")
        s = min(100, s)
        level = "strong" if s >= 70 else ("mid" if s >= 40 else "low")
        if s >= 40 or hits_ip or hits_dom:
            entities.append({
                "dst": dst, "sessions": n, "bytes": bytes_sum,
                "score": s, "level": level,
                "hits": hits_ip[:3] or hits_dom[:3] or [],
                "why": why[:6],
                "sample": [{"dport": r["dport"], "proto": r["proto"],
                            "dur_s": int(r["end"] - r["start"]), "kb": int(r["bytes"] / 1024),
                            "host": r["host"][:40]} for r in rs[:3]],
            })
    entities.sort(key=lambda e: (-e["score"], -e["sessions"]))
    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scope": "internal; 含内部 IP，勿外传",
        "judges": "J1长连接 J2高位端口 J3扇入 J4字节比 J5机场IP J6机场域名",
        "input_sessions": len(recs),
        "airport_lib": {"airports": len(ips),
                        "ip_dom_entries": sum(len(v) for v in ips.values()),
                        "domains": len(doms)},
        "entities": entities[:200],
        "summary": {
            "entities_total": len(entities),
            "strong": sum(1 for e in entities if e["level"] == "strong"),
            "mid": sum(1 for e in entities if e["level"] == "mid"),
        },
    }


# ---- 负向自检 --------------------------------------------------------
_SECRET_SHAPES = (re.compile(r"token=[A-Za-z0-9]"), re.compile(r"eyJ[A-Za-z0-9]{10}"),
                  re.compile(r"sub_url"), re.compile(r"aead"), re.compile(r"auth_token"))


def _assert_clean(report: dict) -> None:
    txt = json.dumps(report, ensure_ascii=False)
    for pat in _SECRET_SHAPES:
        if pat.search(txt):
            raise SystemExit(f"secret-like pattern leaked: {pat.pattern}")


# ---- 内置合成样本（冒烟 + 让用户不用真日志也能看懂格式） --------------
_SELFTEST_CSV = "\n".join([
    "src,dst,sport,dport,proto,packets,bytes,start,end,host,direction,action",
    "192.168.1.10,152.69.227.30,51000,8443,tcp,900,15000000,0,1800,,egress,ACCEPT",
    "192.168.1.11,152.69.227.30,51001,8443,tcp,950,16000000,0,1700,,egress,ACCEPT",
    "192.168.1.12,152.69.227.30,51002,8443,tcp,800,12000000,0,1600,,egress,ACCEPT",
    "192.168.1.10,198.51.100.7,40000,51820,udp,120000,900000000,0,3600,,egress,ACCEPT",
    "192.168.1.10,10.0.0.53,33333,53,tcp,20,2000,0,2,,egress,ACCEPT",
])


def build(out_file: Path = OUT_FILE, text: str = "", fmt: str = "") -> dict:
    ips = load_airport_ips()
    doms = load_airport_domains()
    parser = FORMATS.get(fmt) if fmt else None
    if parser is None:  # 猜格式
        parser = parse_cfw_json if text.lstrip().startswith(("[", "{")) else parse_generic_csv
    recs = parser(text) if text else []
    report = score_sessions(recs, ips, doms)
    report["format"] = fmt or "auto"
    _assert_clean(report)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, out_file)
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="华为云租户机场检测（判据评分卡）")
    ap.add_argument("--in", dest="infile", help="日志文件路径")
    ap.add_argument("--fmt", choices=sorted(FORMATS), help="日志格式")
    ap.add_argument("--out", default=str(OUT_FILE))
    ap.add_argument("--selftest", action="store_true", help="内置合成样本冒烟")
    ap.add_argument("--list-formats", action="store_true")
    a = ap.parse_args(argv)
    if a.list_formats:
        print("\n".join(sorted(FORMATS)))
        return 0
    if a.selftest:
        rep = build(Path(a.out), text=_SELFTEST_CSV, fmt="generic-csv")
        print(f"SELFTEST: sessions={rep['input_sessions']} "
              f"entities={rep['summary']['entities_total']} "
              f"strong={rep['summary']['strong']} mid={rep['summary']['mid']}")
        for e in rep["entities"][:5]:
            print(f"  [{e['level']:6}] {e['score']:3d}  {e['dst'][:44]:44} {';'.join(e['why'])}")
        return 0
    if not a.infile:
        ap.print_help()
        return 10
    text = Path(a.infile).read_text(encoding="utf-8", errors="replace")
    rep = build(Path(a.out), text=text, fmt=a.fmt or "")
    s = rep["summary"]
    print(f"华为云检测完成：会话 {rep['input_sessions']}，实体 {s['entities_total']} "
          f"（强 {s['strong']} / 疑似 {s['mid']}）→ {a.out}")
    return 0 if True else 1


if __name__ == "__main__":
    sys.exit(main())
