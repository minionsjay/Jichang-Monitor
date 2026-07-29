"""域名基础设施 + 华为关联侦察。

对每个机场域名自动做：
  - 归一化 host（去 scheme/path/port，中文域名 IDNA 编码）
  - dig A 解析 + GFW 污染判定（命中已知假 IP → 被墙）
  - dig CNAME 链（抓华为云 CDN cdnhwc* 之类）
  - 真实 IP 走 RDAP 归属
  - 跑华为签名（rdap_name / cidr / domain / cname）

不需要账号；产出基础设施画像 + 华为 findings。真正的订阅节点需登录拿 token 后另行采集。
"""
from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor

from .detect import Detector
from .enrich import rdap_many
from .models import Finding

# GFW DNS 污染常见假 IP（命中即判被墙）
GFW_FAKE_IPS = {
    "8.7.198.45", "8.7.198.46", "37.61.54.158", "46.82.174.68", "46.82.174.69",
    "59.24.3.173", "78.16.49.15", "93.46.8.89", "93.46.8.90", "159.106.121.75",
    "203.98.7.65", "203.161.230.171", "243.185.187.30", "243.185.187.39",
    "249.129.46.48", "253.157.14.165", "54.76.135.1", "89.31.55.106",
    "0.0.0.0", "127.0.0.1",
}


def to_host(raw: str) -> tuple[str, str]:
    """'https://a.b.com:6908/path' → (显示host 'a.b.com', 可解析host punycode)。"""
    h = raw.strip()
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]      # 去 path
    h = h.split(":", 1)[0]      # 去 port
    try:
        ascii_h = h.encode("idna").decode()   # 中文域名 → punycode
    except Exception:
        ascii_h = h
    return h, ascii_h


def _dig(host: str, rtype: str) -> list[str]:
    """DNS 查询。优先用 dig（Linux），回退到 Python socket（Windows）。"""
    # 优先 dig（Linux 上有）
    try:
        out = subprocess.run(["dig", "+short", "+time=3", "+tries=1", rtype, host],
                             capture_output=True, text=True, timeout=8)
        if out.returncode == 0 and out.stdout.strip():
            return [l.strip() for l in out.stdout.splitlines() if l.strip()]
    except (FileNotFoundError, Exception):
        pass
    # 回退：Python socket.getaddrinfo（Windows 上没有 dig）
    if rtype == "A":
        import socket as _sock
        try:
            infos = _sock.getaddrinfo(host, None)
            return sorted({i[4][0] for i in infos if i[4][0].count(".") == 3})
        except Exception:
            return []
    # CNAME 查询在 Windows 上用 nslookup
    try:
        out = subprocess.run(["nslookup", "-type=" + rtype, host],
                             capture_output=True, text=True, timeout=8)
        cnames = []
        for line in out.stdout.splitlines():
            if "canonical name" in line.lower() or "alias" in line.lower():
                parts = line.split("=") if "=" in line else line.split(":")
                if len(parts) > 1:
                    cnames.append(parts[-1].strip().rstrip("."))
        return cnames
    except Exception:
        return []


def recon_host_dns(display: str, ascii_h: str) -> dict:
    """只做 DNS（dig 可高并发）；RDAP 留到批量阶段。"""
    a = _dig(ascii_h, "A")
    ips = [x for x in a if x[0].isdigit() and x.count(".") == 3]
    cnames = [x.rstrip(".") for x in _dig(ascii_h, "CNAME")]
    poisoned = [ip for ip in ips if ip in GFW_FAKE_IPS]
    real = [ip for ip in ips if ip not in GFW_FAKE_IPS]
    if not ips:
        status = "无解析"
    elif poisoned and not real:
        status = "被墙(GFW污染)"
    elif poisoned:
        status = "部分污染"
    else:
        status = "解析正常"
    return {"host": display, "ascii": ascii_h, "ips": ips, "real": real,
            "cnames": cnames, "status": status, "rdap": {}}


def recon_airport(slug: str, display: str, domains: list[str],
                  detector: Detector) -> dict:
    hosts = [to_host(d) for d in domains]
    with ThreadPoolExecutor(max_workers=10) as ex:
        rows = list(ex.map(lambda hp: recon_host_dns(*hp), hosts))
    # 批量低并发 RDAP（避免 rdap.org 限流），再回填到各行
    all_ips = {ip for r in rows for ip in r["real"]}
    rdap_map = rdap_many(all_ips, workers=4)
    for r in rows:
        r["rdap"] = {ip: rdap_map.get(ip, ("", "", "", "")) for ip in r["real"]}
    findings: list[Finding] = []
    for r in rows:
        ctx = f"{r['host']} [{r['status']}]"
        # 域名本身 + CNAME 的华为域名签名
        for name in [r["host"], r["ascii"], *r["cnames"]]:
            hit = detector.check_domain(name)
            if hit:
                findings.append(Finding(slug, "domain", hit, name, ctx, "high"))
        # 真实 IP 的 RDAP / CIDR
        for ip, (netname, owner, country, asn) in r["rdap"].items():
            findings += detector.scan_ip_record(slug, ip=ip, netname=netname,
                                                owner=owner, asn=asn, context=ctx)
    return {"slug": slug, "display": display, "rows": rows,
            "findings": _dedup(findings)}


def _dedup(findings):
    seen, out = set(), []
    for f in findings:
        k = (f.dimension, f.rule, f.evidence, f.context)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def load_seeds(path: str) -> list[tuple[str, str, list[str]]]:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 3:
                continue
            slug, display, doms = parts
            out.append((slug, display, [d.strip() for d in doms.split(";") if d.strip()]))
    return out
