"""采集器：direct（直连订阅）+ client（客户端锁定型，摄入落盘 profile）。

两者产出一致的 Snapshot（节点已富化 server→IP→RDAP，并跑过华为检测）。
"""
from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor

import requests

from . import store
from .detect import Detector
from .enrich import resolve, rdap_many
from .login import smart_login, fetch_subscription
from .models import Snapshot, Node, Finding
from .parse import parse_subscription, parse_clash_yaml


def _enrich_and_detect(airport: str, nodes: list[Node], detector: Detector):
    """给每个节点解析 server→IP，批量 RDAP，再跑华为检测。"""
    all_ips = set()
    for n in nodes:
        ips = resolve(n.server)
        n.raw["_resolved_ips"] = ips
        all_ips.update(ips)
    rdap_map = rdap_many(all_ips)
    # 把 RDAP 结果也塞回节点，方便快照留档
    for n in nodes:
        n.raw["_rdap"] = {ip: rdap_map.get(ip) for ip in n.raw.get("_resolved_ips", [])}
    findings = detector.scan_nodes(airport, nodes, rdap_map)
    return findings


def collect_direct(airport: dict, detector: Detector) -> Snapshot:
    name = airport["name"]
    sub = airport.get("subscription") or {}
    url = sub.get("url")
    if not url:
        raise ValueError(f"{name}: airports.yaml 未填 subscription.url（直连型必填）")
    ua = sub.get("user_agent", "clash.meta")
    resp = requests.get(url, headers={"User-Agent": ua}, timeout=30, verify=False)
    resp.raise_for_status()
    nodes = parse_subscription(resp.text)
    snap = Snapshot(airport=name, ts=store.now_iso(), source=url, nodes=nodes)
    # 订阅流量/到期信息常在响应头
    for h in ("subscription-userinfo", "profile-update-interval"):
        if h in resp.headers:
            snap.meta[h] = resp.headers[h]
    snap.findings = _enrich_and_detect(name, nodes, detector)
    return snap


def collect_client(slug: str, client_dir: str, detector: Detector):
    """扫"下客户端登录"型机场的数据目录 → 抽节点 + 内嵌订阅链接。返回 (snap, sub_urls)。"""
    from .clientscan import scan_client_dir
    nodes, sub_urls, meta = scan_client_dir(client_dir)
    meta["panel_type"] = "client-dir"
    meta["sub_urls"] = sub_urls
    snap = Snapshot(airport=slug, ts=store.now_iso(),
                    source=f"client-dir:{client_dir}", nodes=nodes, meta=meta)
    snap.findings = _enrich_and_detect(slug, nodes, detector)
    return snap, sub_urls


def collect_node_pages(slug: str, base_url: str, cookie: str, detector: Detector,
                       max_id: int = 300, workers: int = 8) -> Snapshot:
    """SSPanel JS 渲染节点页：用浏览器 cookie 登录态，遍历 /user/node/{id} 抽全部节点。

    适用于"无订阅链接、节点详情点击弹窗(JS 拉 /user/node/{id})"的机场。
    cookie 从浏览器 F12→Network 里任一已登录请求复制。
    """
    from .nodepage import parse_node_page
    base = base_url.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base
    headers = {"User-Agent": "Mozilla/5.0", "Cookie": cookie}

    def fetch(i):
        try:
            r = requests.get(f"{base}/user/node/{i}?ismu=0&relay_rule=0",
                             headers=headers, timeout=10, verify=False)
            return parse_node_page(r.text)
        except Exception:
            return []

    seen: dict[str, Node] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for ns in ex.map(fetch, range(1, max_id + 1)):
            for n in ns:
                seen[n.key()] = n
    nodes = list(seen.values())
    snap = Snapshot(airport=slug, ts=store.now_iso(),
                    source=f"{base}/user/node (cookie遍历)", nodes=nodes,
                    meta={"panel_type": "node-page-cookie"})
    snap.findings = _enrich_and_detect(slug, nodes, detector)
    return snap


def collect_page(slug: str, page_text: str, detector: Detector) -> Snapshot:
    """从 /user/node 页面 HTML/文本抽节点 → 富化 → 华为检测（无订阅链接的机场用）。"""
    from .nodepage import parse_node_page
    nodes = parse_node_page(page_text)
    snap = Snapshot(airport=slug, ts=store.now_iso(), source="node-page",
                    nodes=nodes, meta={"panel_type": "node-page"})
    snap.findings = _enrich_and_detect(slug, nodes, detector)
    return snap


def collect_from_url(slug: str, sub_url: str, detector: Detector,
                     user_agent: str = "clash.meta") -> Snapshot:
    """已知订阅链接（手动取/反爬机场兜底）：直接抓 → 富化 → 华为检测。"""
    text, meta = fetch_subscription(sub_url, user_agent)
    nodes = parse_subscription(text)
    meta["panel_type"] = "manual-url"
    snap = Snapshot(airport=slug, ts=store.now_iso(), source=sub_url,
                    nodes=nodes, meta=meta)
    snap.findings = _enrich_and_detect(slug, nodes, detector)
    return snap


def collect_login(slug: str, panel: str, email: str, password: str,
                  detector: Detector, ptype: str = "auto") -> tuple[Snapshot, str, str]:
    """凭证驱动：自动登录取订阅链接 → 抓节点 → 富化 → 华为检测。

    返回 (snap, sub_url, 识别到的面板类型)。
    """
    sub_url, _auth, kind = smart_login(panel, email, password, ptype)
    text, meta = fetch_subscription(sub_url)
    nodes = parse_subscription(text)
    meta["panel_type"] = kind
    snap = Snapshot(airport=slug, ts=store.now_iso(), source=sub_url,
                    nodes=nodes, meta=meta)
    snap.findings = _enrich_and_detect(slug, nodes, detector)
    return snap, sub_url, kind


def collect_profile(airport: dict, profile_path: str, detector: Detector,
                    index_path: str | None = None) -> Snapshot:
    """类型 B：摄入常驻客户端落盘的明文 Clash profile。

    index_path：客户端的 profiles.yaml（订阅索引），含账号元数据 crisp.regip 等。
    不显式给时，自动探测 profile 同目录/上级目录的 profiles.yaml。
    """
    name = airport["name"]
    if not os.path.exists(profile_path):
        raise FileNotFoundError(profile_path)
    with open(profile_path, encoding="utf-8") as f:
        nodes = parse_clash_yaml(f.read())
    snap = Snapshot(airport=name, ts=store.now_iso(),
                    source=profile_path, nodes=nodes)
    snap.findings = _enrich_and_detect(name, nodes, detector)

    index_path = index_path or _auto_index(profile_path)
    if index_path and os.path.exists(index_path):
        acct_findings, acct_meta = scan_account_index(name, index_path, detector)
        snap.findings += acct_findings
        snap.meta.update(acct_meta)
    return snap


def _auto_index(profile_path: str) -> str | None:
    """profiles/ 里的 xxx.yaml → 上级的 profiles.yaml。"""
    d = os.path.dirname(profile_path)
    for cand in (os.path.join(d, "profiles.yaml"),
                 os.path.join(os.path.dirname(d), "profiles.yaml")):
        if os.path.exists(cand):
            return cand
    return None


def scan_account_index(airport: str, index_path: str, detector: Detector):
    """扫客户端 profiles.yaml 的账号元数据：注册 IP(regip) 查华为云 + 全文域名签名。"""
    with open(index_path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    findings: list[Finding] = []
    meta: dict = {}
    regips = sorted(set(re.findall(r"regip:\s*([0-9.]+)", text)))
    if regips:
        meta["regip"] = regips
        rdap_map = rdap_many(regips)
        for ip in regips:
            netname, owner, country, asn = rdap_map.get(ip, ("", "", "", ""))
            findings += detector.scan_ip_record(
                airport, ip=ip, netname=netname, owner=owner, asn=asn,
                context=f"账号注册IP regip={ip}")
    # profiles.yaml 里可能出现 huaweicloud/obs 等域名
    for m in set(re.findall(r"[a-z0-9.\-]+\.[a-z]{2,}", text.lower())):
        hit = detector.check_domain(m)
        if hit:
            findings.append(Finding(airport, "domain", hit, m,
                                    "profiles.yaml 域名", "high"))
    return _dedup(findings), meta


def _dedup(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        k = (f.dimension, f.rule, f.evidence, f.context)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
