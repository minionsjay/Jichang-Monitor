"""华为云 IP 前缀表（动态）。

`signatures/huawei.yaml` 里手写了 17 段 CIDR，只覆盖华为云的一小部分；
华为云实际公告的前缀有一千条上下（AS55990 / AS136907 / AS137876）。
只靠 17 段兜底，就会出现「IP 明明在华为云，RDAP 的 netname 又没写成
HWCSNET（转售/二次分配常见）→ 查不出来」的漏报。

这里从 RIPE Stat 的公开 API 取各 ASN 当前公告的全部前缀，落成
`data/huawei_prefixes.json`，检测时用二分查找（970 段也能 O(log n) 命中）。
纯只读、无凭据；抓不到就用上一份缓存，没有缓存就退化成静态 17 段。
"""
from __future__ import annotations

import bisect
import io
import json
import os
import time
import urllib.request

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
CACHE = os.path.join(DATA, "huawei_prefixes.json")

ASNS = ("AS55990", "AS136907", "AS137876")
API = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=%s"
REFRESH_HOURS = 24.0

_index: dict | None = None  # {"v4": [(start, end, prefix)], "v6": [...], "at": ..., "count": n}


def _load_cache() -> dict:
    try:
        with io.open(CACHE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save_cache(v4: list, v6: list, per_asn: dict) -> dict:
    d = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "epoch": int(time.time()),
        "asns": list(ASNS),
        "per_asn": per_asn,
        "v4": sorted(v4),
        "v6": sorted(v6),
        "count": {"v4": len(v4), "v6": len(v6)},
        "source": "stat.ripe.net announced-prefixes",
    }
    os.makedirs(DATA, exist_ok=True)
    tmp = CACHE + ".tmp"
    with io.open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.replace(tmp, CACHE)
    return d


def _fetch_asn(asn: str, timeout: float = 20.0) -> list:
    """取单个 ASN 当前公告前缀；代理可用就走代理，失败再直连。"""
    try:
        from .netcfg import proxy_dict
        proxies = proxy_dict() or {}
    except Exception:
        proxies = {}
    last = None
    for handler_proxies in (proxies, {}):
        try:
            op = urllib.request.build_opener(urllib.request.ProxyHandler(handler_proxies))
            req = urllib.request.Request(API % asn, headers={"User-Agent": "airmon/1.0"})
            with op.open(req, timeout=timeout) as r:
                d = json.loads(r.read().decode("utf-8", "replace"))
            return [p.get("prefix") for p in (d.get("data", {}).get("prefixes") or [])
                    if p.get("prefix")]
        except Exception as e:  # noqa: BLE001
            last = e
    raise RuntimeError("取 %s 前缀失败：%s" % (asn, last))


def refresh() -> dict:
    """联网刷新前缀表，返回写入的缓存内容。失败抛异常（调用方负责降级）。"""
    import ipaddress

    v4: set = set()
    v6: set = set()
    per_asn = {}
    for asn in ASNS:
        pref = _fetch_asn(asn)
        per_asn[asn] = len(pref)
        for p in pref:
            try:
                net = ipaddress.ip_network(p, strict=False)
            except ValueError:
                continue
            (v4 if net.version == 4 else v6).add(str(net))
    global _index
    _index = None
    return _save_cache(sorted(v4), sorted(v6), per_asn)


def should_refresh(hours: float = REFRESH_HOURS) -> bool:
    d = _load_cache()
    ep = d.get("epoch")
    if not isinstance(ep, (int, float)):
        return True
    return (time.time() - float(ep)) / 3600.0 > hours


def _build_index() -> dict:
    """把前缀编译成按区间排序的二分索引（合并重叠/相邻段）。"""
    import ipaddress

    d = _load_cache()
    out = {"v4": [], "v6": [], "at": d.get("at") or "", "count": (d.get("count") or {})}
    for key in ("v4", "v6"):
        spans = []
        for p in (d.get(key) or []):
            try:
                net = ipaddress.ip_network(p, strict=False)
            except ValueError:
                continue
            spans.append((int(net.network_address), int(net.broadcast_address), str(net)))
        spans.sort()
        merged = []
        for s, e, pfx in spans:
            if merged and s <= merged[-1][1]:
                if e > merged[-1][1]:
                    merged[-1] = (merged[-1][0], e, merged[-1][2])
            else:
                merged.append((s, e, pfx))
        out[key] = merged
    return out


def index() -> dict:
    global _index
    if _index is None:
        _index = _build_index()
    return _index


def contains(ip: str) -> str | None:
    """IP 是否落在华为云公告前缀里；命中返回前缀字符串。无缓存/非法 IP 返回 None。"""
    import ipaddress

    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    idx = index()
    key = "v4" if addr.version == 4 else "v6"
    spans = idx.get(key) or []
    if not spans:
        return None
    n = int(addr)
    starts = [s[0] for s in spans]
    i = bisect.bisect_right(starts, n) - 1
    if i >= 0:
        s, e, pfx = spans[i]
        if s <= n <= e:
            return pfx
    return None


def summary() -> dict:
    d = _load_cache()
    idx = index()
    return {
        "at": d.get("at") or "",
        "age_h": round((time.time() - float(d.get("epoch") or 0)) / 3600.0, 1) if d.get("epoch") else None,
        "v4_spans": len(idx.get("v4") or []),
        "v6_spans": len(idx.get("v6") or []),
        "raw": d.get("count") or {},
    }


if __name__ == "__main__":
    import sys

    if "--refresh" in sys.argv or not _load_cache():
        print("refresh:", json.dumps(refresh(), ensure_ascii=False)[:300])
    print("summary:", json.dumps(summary(), ensure_ascii=False))
    for ip in ("116.205.40.113", "60.204.2.4", "8.8.8.8", "1.2.3.4"):
        print("  %-16s -> %s" % (ip, contains(ip)))
