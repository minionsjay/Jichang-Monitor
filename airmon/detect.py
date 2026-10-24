"""华为关联检测引擎。加载 signatures/huawei.yaml，跨多维度匹配产出 Finding。

维度：
  rdap_name  —— RDAP netname/owner 子串（主判据）
  asn        —— ASN 号
  cidr       —— IP 落在华为云段（兜底）
  domain     —— 域名/CNAME 子串（server 本身 + 实测 CNAME 链）
  string     —— 软件二进制/文本 strings 子串
"""
from __future__ import annotations

import ipaddress
import os
import re
import yaml

from .models import Finding, Node

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SIG = os.path.join(_HERE, "signatures", "huawei.yaml")


class Detector:
    def __init__(self, sig_path: str | None = None):
        with open(sig_path or DEFAULT_SIG, encoding="utf-8") as f:
            sig = yaml.safe_load(f)
        self.name = sig.get("name", "huawei")
        self.rdap_name = [s.lower() for s in sig.get("rdap_name", [])]
        self.asn = {str(a).lstrip("ASas") for a in sig.get("asn", [])}
        self.networks = [ipaddress.ip_network(c) for c in sig.get("cidr", [])]
        self.domain = [s.lower() for s in sig.get("domain", [])]
        self.string = [s.lower() for s in sig.get("string", [])]

    # ---- 单维度检查（返回命中的签名，未命中返回 None）----
    def check_rdap(self, netname: str, owner: str) -> str | None:
        hay = f"{netname} {owner}".lower()
        for s in self.rdap_name:
            if s in hay:
                return s
        return None

    def check_asn(self, asn: str) -> str | None:
        nums = re.findall(r"\d+", asn or "")
        for n in nums:
            if n in self.asn:
                return f"AS{n}"
        return None

    def check_cidr(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net in self.networks:
            if addr.version == net.version and addr in net:
                return str(net)
        return None

    def check_domain(self, domain: str) -> str | None:
        d = (domain or "").lower()
        for s in self.domain:
            if s in d:
                return s
        return None

    def check_string(self, text: str) -> list[str]:
        t = (text or "").lower()
        return [s for s in self.string if s in t]

    # ---- 组合：对一条富化后的 IP 记录做全维度检查 ----
    def scan_ip_record(self, airport: str, *, ip: str = "", netname: str = "",
                       owner: str = "", asn: str = "", domain: str = "",
                       context: str = "") -> list[Finding]:
        out: list[Finding] = []
        if netname or owner:
            hit = self.check_rdap(netname, owner)
            if hit:
                out.append(Finding(airport, "rdap_name", hit,
                                   f"{netname}/{owner}", context, "high"))
        if asn:
            hit = self.check_asn(asn)
            if hit:
                out.append(Finding(airport, "asn", hit, asn, context, "high"))
        if ip and not out:  # rdap 已命中就不必再靠 CIDR 兜底
            hit = self.check_cidr(ip)
            if hit:
                out.append(Finding(airport, "cidr", hit, ip, context, "medium"))
        if domain:
            hit = self.check_domain(domain)
            if hit:
                out.append(Finding(airport, "domain", hit, domain, context, "high"))
        return out

    def scan_text(self, airport: str, text: str, context: str) -> list[Finding]:
        return [Finding(airport, "string", s, s, context, "high")
                for s in self.check_string(text)]

    # ---- 对一批节点（已富化 server→ips）做检查 ----
    def scan_nodes(self, airport: str, nodes: list[Node],
                   rdap_map: dict[str, tuple]) -> list[Finding]:
        out: list[Finding] = []
        for n in nodes:
            ctx = f"节点 {n.name or n.server}"
            # server 本身 + 它的 CNAME 链都要查域名维度：
            # 机场常把节点域名 CNAME 到 CDN 边缘域（cdnhwc* = 华为云 CDN），
            # 只看 server 会漏掉这一层。
            names = [n.server]
            for c in (n.raw.get("_cnames") or []):
                if c and c not in names:
                    names.append(c)
            for nm in names:
                f = self._domain_finding(airport, nm, ctx)
                if f:
                    out.append(f)
            for ip in n.raw.get("_resolved_ips", []):
                netname, owner, country, asn = rdap_map.get(ip, ("", "", "", ""))
                out += self.scan_ip_record(airport, ip=ip, netname=netname,
                                           owner=owner, asn=asn, context=ctx)
        return _dedup(out)

    def _domain_finding(self, airport, domain, ctx):
        hit = self.check_domain(domain)
        return Finding(airport, "domain", hit, domain, ctx, "high") if hit else None


def _dedup(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        k = (f.dimension, f.rule, f.evidence, f.context)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
