"""IP 解析 + RDAP 归属富化。复用上级 rdap_enrich.py 的 rdap.org 引导思路，纯标准库。"""
from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor


_ALT_DNS = "1.1.1.1"     # 海外视角（国内 DNS 与它常给不同的 A 记录，见 GeoDNS）
_ALT_TIMEOUT = 1.5


def _getaddrinfo(host: str, timeout: float = 5.0) -> list[str]:
    """系统解析器（Windows DNS Client）拿到的全部 A 记录，即国内视角。

    getaddrinfo 无原生超时，用单线程池 + future timeout 防止卡死整批。"""
    import concurrent.futures
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.getaddrinfo, host, None)
            infos = fut.result(timeout=timeout)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def resolve_detail(host: str, timeout: float = 5.0) -> tuple[list[str], list[str]]:
    """域名 → (全部 IP, 只有海外视角才解析到的 IP)。

    为什么要两手：机场普遍用 GeoDNS/ECS 分线，国内 DNS 给一组国内落地、海外
    DNS 给另一组。实测 xinaleye.owolist.cn：223.5.5.5 → 8 个腾讯/电信 IP，
    1.1.1.1 → 只有 1 个 AWS 香港 IP。只用系统解析器会漏掉另一半。
    """
    if not host:
        return ([], [])
    if _is_ip(host):
        return ([host], [])
    # 给海外补充留出时间：调用方（collect）对单域名只等 5s，别让 getaddrinfo 吃满
    ips = set(_getaddrinfo(host, min(timeout, 3.5)))
    alt: list[str] = []
    try:
        from .dnsq import query as _dnsq_query
        _cn, extra = _dnsq_query(host, _ALT_DNS, timeout=_ALT_TIMEOUT)
        for ip in (extra or []):
            if ip not in ips:
                alt.append(ip)
        ips.update(alt)
    except Exception:
        pass
    return (sorted(ips), sorted(alt))


def resolve(host: str, timeout: float = 5.0) -> list[str]:
    """域名 → IP 列表（国产 + 海外两路视角取并集）；本身是 IP 则原样返回。"""
    return resolve_detail(host, timeout)[0]


def _is_ip(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


_RDAP_CACHE: dict[str, tuple[str, str, str, str]] = {}   # 只缓存成功结果
_RDAP_LOCK = threading.Lock()   # 12 线程并发查缓存/写盘的互斥锁（P0 修复）


def rdap(ip: str) -> tuple[str, str, str, str]:
    """返回 (netname, owner, country, asn)。失败返回占位且**不缓存**（可重试）。
    429/503 限流时退避重试一次；其他失败直接回退 ip-api.com。
    只更新内存缓存，落盘由 rdap_many 收尾统一 _flush_disk_cache() 原子写。"""
    with _RDAP_LOCK:
        if ip in _RDAP_CACHE:
            return _RDAP_CACHE[ip]

    # 方法1: rdap.org（429/503 退避重试一次）
    d = None
    for attempt in range(2):
        try:
            req = urllib.request.Request(f"https://rdap.org/ip/{ip}",
                                         headers={"User-Agent": "airmon-rdap"})
            with urllib.request.urlopen(req, timeout=8) as r:
                d = json.load(r)
            break
        except urllib.error.HTTPError as e:
            if e.code in (429, 503) and attempt == 0:
                time.sleep(1.5)
                continue
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
        with _RDAP_LOCK:
            _RDAP_CACHE[ip] = result
        return result

    # 方法2: ip-api.com 回退 (不支持 rdap.org 时的备选)
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,query&lang=zh-CN",
            headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            d2 = json.load(r)
        if d2.get("status") == "success":
            isp = d2.get("isp", "")
            org = d2.get("org", "")
            country = d2.get("country", "")
            asn = d2.get("as", "")
            result = (isp, org, country, asn)
            with _RDAP_LOCK:
                _RDAP_CACHE[ip] = result
            return result
    except Exception as e:
        return ("n/a", f"n/a({e})", "", "")

    return ("n/a", "n/a(failed)", "", "")


# ---- 持久化 RDAP 缓存（跨次 pull 复用）----
_DISK_CACHE: dict[str, tuple] = {}
_DISK_PATH: str | None = None


def _disk_cache_path() -> str:
    import os
    d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", ".cache")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "rdap_cache.json")


def _load_disk_cache() -> None:
    global _DISK_CACHE, _DISK_PATH
    if _DISK_PATH is None:
        _DISK_PATH = _disk_cache_path()
    try:
        with open(_DISK_PATH, encoding="utf-8") as f:
            raw = json.load(f)
        _DISK_CACHE = {k: tuple(v) for k, v in raw.items()}
    except Exception:
        _DISK_CACHE = {}


def _save_disk_cache(ip: str, result: tuple) -> None:
    """单条入内存缓存（兼容旧签名）；实际落盘交给 _flush_disk_cache()。"""
    global _DISK_PATH
    if _DISK_PATH is None:
        _DISK_PATH = _disk_cache_path()
    with _RDAP_LOCK:
        _DISK_CACHE[ip] = result
        _RDAP_CACHE[ip] = result


def _flush_disk_cache() -> None:
    """把内存缓存整体原子落盘（tmp + os.replace），供 rdap_many 收尾调用一次。"""
    import os
    global _DISK_PATH
    if _DISK_PATH is None:
        _DISK_PATH = _disk_cache_path()
    with _RDAP_LOCK:
        snapshot = {k: list(v) for k, v in _DISK_CACHE.items()}
    tmp = _DISK_PATH + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, ensure_ascii=False)
        os.replace(tmp, _DISK_PATH)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass


def rdap_many(ips, workers: int = 12) -> dict[str, tuple[str, str, str, str]]:
    ips = sorted(set(ips))
    if not ips:
        return {}
    # 加载持久缓存
    if not _DISK_CACHE:
        _load_disk_cache()
    # 合并内存缓存
    with _RDAP_LOCK:
        for ip, result in _DISK_CACHE.items():
            if ip not in _RDAP_CACHE:
                _RDAP_CACHE[ip] = result
    # 只查未缓存的
    todo = [ip for ip in ips if ip not in _RDAP_CACHE]
    if todo:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = dict(zip(todo, ex.map(rdap, todo)))
        # 统一持久化（一次原子写，替代每线程并发写整文件）
        with _RDAP_LOCK:
            for ip, result in results.items():
                if result[0] != "n/a":
                    _DISK_CACHE[ip] = result
        _flush_disk_cache()
    return {ip: _RDAP_CACHE.get(ip, ("n/a", "n/a", "", "")) for ip in ips}
