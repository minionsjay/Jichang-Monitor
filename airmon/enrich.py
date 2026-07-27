"""IP 解析 + RDAP 归属富化。复用上级 rdap_enrich.py 的 rdap.org 引导思路，纯标准库。"""
from __future__ import annotations

import json
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor


def resolve(host: str) -> list[str]:
    """域名 → IP 列表；本身是 IP 则原样返回；解析不到返回 []。"""
    if not host:
        return []
    if _is_ip(host):
        return [host]
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos})
    except socket.gaierror:
        return []


def _is_ip(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


_RDAP_CACHE: dict[str, tuple[str, str, str, str]] = {}   # 只缓存成功结果


def rdap(ip: str) -> tuple[str, str, str, str]:
    """返回 (netname, owner, country, asn)。失败返回占位且**不缓存**（可重试）。
    429/503 限流时退避重试。先试 rdap.org，失败回退 ip-api.com。"""
    import time
    if ip in _RDAP_CACHE:
        return _RDAP_CACHE[ip]
    
    # 方法1: rdap.org
    d = None
    for attempt in range(2):
        try:
            req = urllib.request.Request(f"https://rdap.org/ip/{ip}",
                                         headers={"User-Agent": "airmon-rdap"})
            with urllib.request.urlopen(req, timeout=10) as r:
                d = json.load(r)
            break
        except Exception:
            break
    
    if d is not None:
        netname = d.get("name") or d.get("handle") or ""
        country = d.get("country") or ""
        owner = ""
        for e in d.get("entities", []) or []:
            roles = e.get("roles", [])
            if any(x in roles for x in ("registrant", "administrative", "owner")):
                for item in (e.get("vcardArray", [None, []])[1] or []):
                    if item and item[0] == "fn":
                        owner = item[3]
                        break
            if owner:
                break
        asn = ""
        for remark in d.get("remarks", []) or []:
            for t in remark.get("description", []) or []:
                if "AS" in str(t):
                    asn = asn or str(t)
        result = (netname, owner or netname, country, asn)
        _RDAP_CACHE[ip] = result
        return result
    
    # 方法2: ip-api.com 回退 (不支持 rdap.org 时的备选)
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,query&lang=zh-CN",
            headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            d2 = json.load(r)
        if d2.get("status") == "success":
            isp = d2.get("isp", "")
            org = d2.get("org", "")
            country = d2.get("country", "")
            asn = d2.get("as", "")
            result = (isp, org, country, asn)
            _RDAP_CACHE[ip] = result
            return result
    except Exception as e:
        return ("n/a", f"n/a({e})", "", "")
    
    return ("n/a", "n/a(failed)", "", "")
    netname = d.get("name") or d.get("handle") or ""
    country = d.get("country") or ""
    owner = ""
    for e in d.get("entities", []) or []:
        roles = e.get("roles", [])
        if any(x in roles for x in ("registrant", "administrative", "owner")):
            for item in (e.get("vcardArray", [None, []])[1] or []):
                if item and item[0] == "fn":
                    owner = item[3]
                    break
        if owner:
            break
    asn = ""
    for remark in d.get("remarks", []) or []:
        for t in remark.get("description", []) or []:
            if "AS" in str(t):
                asn = asn or str(t)
    result = (netname, owner or netname, country, asn)
    _RDAP_CACHE[ip] = result       # 只缓存成功
    return result


def rdap_many(ips, workers: int = 4) -> dict[str, tuple[str, str, str, str]]:
    ips = sorted(set(ips))
    if not ips:
        return {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return dict(zip(ips, ex.map(rdap, ips)))
