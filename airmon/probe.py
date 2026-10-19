"""节点探活（抽样 TCP 握手测延迟）——docs/04 阶段四的最小落地。

设计原则：
- 抽样制：每机场默认抽 5 个节点（不是 2600+ 全量，降低对机场侧的风控暴露）。
- 只做 TCP 三层握手（connect + RTT），不发任何代理协议流量。
- 确定性抽样：按 hash(节点key+当日日期) 排序取前 N —— 同一天测同一批，
  跨天自然轮换，趋势可比且不会永远盯着同一批节点。
- 落地 data/probe.json（只含存活统计与节点名/服务器/端口，无任何凭据）。

用法：
  python -m airmon.probe                    # 全部机场抽样探活
  python -m airmon.probe --per-airport 8    # 每机场抽 8 个
  python -m airmon.probe --only hhy,fastlink
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from .store import DATA_DIR, _ts_of

OUT = os.path.join(DATA_DIR, "probe.json")
_SLUG_RE = __import__("re").compile(r"^[\w.\-]{1,40}$")


def _sample_nodes(slug: str, n: int) -> tuple[list[dict], int]:
    """确定性抽样：返回 [(name, server, port, ip)] 与该机场节点总数。"""
    snaps = sorted(f for f in glob.glob(os.path.join(DATA_DIR, slug, "*.json"))
                   if os.path.basename(f).endswith(".json"))
    if not snaps:
        return [], 0
    try:
        with open(snaps[-1], encoding="utf-8") as f:
            s = json.load(f)
    except Exception:
        return [], 0
    nodes = s.get("nodes") or []
    total = len(nodes)
    if not nodes:
        return [], 0
    today = time.strftime("%Y%m%d")

    def rank(nd):
        key = f"{nd.get('protocol')}://{nd.get('server')}:{nd.get('port')}|{today}"
        return hashlib.md5(key.encode()).hexdigest()

    picked = sorted(nodes, key=rank)[:max(1, min(n, total))]
    out = []
    for nd in picked:
        raw = nd.get("raw") or {}
        ips = raw.get("_resolved_ips") or []
        ip = ips[0] if ips else None
        out.append({"name": (nd.get("name") or "")[:40],
                    "server": (nd.get("server") or "")[:60],
                    "port": int(nd.get("port") or 0),
                    "ip": ip})
    return out, total


def _tcp_probe(server: str, port: int, ip: str | None, timeout: float) -> tuple[bool, float | None]:
    """对 (server|ip):port 做 TCP connect。返回 (ok, rtt_ms)。"""
    host = ip or server
    if not host or not port:
        return False, None
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            rtt = (time.perf_counter() - t0) * 1000
        return True, round(rtt, 1)
    except Exception:
        return False, None


def probe(per_airport: int = 5, timeout: float = 3.0, only: list[str] | None = None,
          workers: int = 32) -> dict:
    root = os.path.join(DATA_DIR, "*")
    slugs = [os.path.basename(d) for d in sorted(glob.glob(root)) if os.path.isdir(d)]
    slugs = [s for s in slugs if not s.startswith(("_", ".")) and _SLUG_RE.match(s)]
    if only:
        slugs = [s for s in slugs if s in set(only)]
    jobs = []
    for slug in slugs:
        sampled, total = _sample_nodes(slug, per_airport)
        for nd in sampled:
            jobs.append((slug, nd, total))
    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_tcp_probe, nd["server"], nd["port"], nd["ip"], timeout): (slug, nd, total)
                for slug, nd, total in jobs}
        for fut in futs:
            pass
        # 按机场聚合
        agg: dict[str, dict] = {}
        for fut, (slug, nd, total) in futs.items():
            ok, rtt = fut.result()
            a = agg.setdefault(slug, {"n_total": total, "n_sample": 0, "ok": 0, "fail": 0,
                                      "rtts": [], "dead": []})
            a["n_sample"] += 1
            if ok:
                a["ok"] += 1
                if rtt is not None:
                    a["rtts"].append(rtt)
            else:
                a["fail"] += 1
                if len(a["dead"]) < 5:
                    a["dead"].append({"name": nd["name"], "server": nd["server"], "port": nd["port"]})
    for slug, a in agg.items():
        rtts = a.pop("rtts", [])
        a["rtt_avg_ms"] = round(sum(rtts) / len(rtts), 1) if rtts else None
        a["rtt_min_ms"] = min(rtts) if rtts else None
        a["rate"] = round(a["ok"] / a["n_sample"], 3) if a["n_sample"] else None
        results[slug] = a
    out = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "per_airport": results,
           "summary": {"airports": len(results),
                       "alive": sum(1 for a in results.values() if (a.get("ok") or 0) > 0),
                       "probes": sum(a.get("n_sample", 0) for a in results.values()),
                       "ok_probes": sum(a.get("ok", 0) for a in results.values())}}
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
    os.replace(tmp, OUT)
    return out


def main(argv=None):
    p = argparse.ArgumentParser(prog="airmon.probe", description="节点抽样 TCP 探活")
    p.add_argument("--per-airport", type=int, default=5, help="每机场抽样数（默认 5）")
    p.add_argument("--timeout", type=float, default=3.0, help="单节点 TCP 超时秒（默认 3）")
    p.add_argument("--only", default="", help="逗号分隔 slug 列表")
    a = p.parse_args(argv)
    only = [s.strip() for s in a.only.split(",") if s.strip()] or None
    r = probe(a.per_airport, a.timeout, only)
    s = r["summary"]
    print(f"探活完成：{s['airports']} 机场 / {s['probes']} 探针 / "
          f"通 {s['ok_probes']} / 有存活节点机场 {s['alive']} → {OUT}")


if __name__ == "__main__":
    raise SystemExit(main())
