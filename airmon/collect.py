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
from .dnsq import cname_many
from .enrich import resolve_detail, rdap_many
from .login import smart_login, fetch_subscription
from .rawstore import save_raw
from .models import Snapshot, Node, Finding
from .parse import parse_subscription, parse_clash_yaml


_PLACEHOLDER_IPS = {"1.1.1.1", "7.7.7.7", "0.0.0.0", "127.0.0.1", "8.8.8.8", "8.8.4.4",
                    "239.255.255.250"}   # SSDP 组播地址（探活实测出现的假节点）
_PLACEHOLDER_HOSTS = {"time.apple.com", "time.windows.com", "time.asia.apple.com",
                      "ntp.aliyun.com", "trace.go"}   # NTP/追踪占位域名
_PLACEHOLDER_PORTS = {1, 0, 123, 1900}   # 123=NTP 1900=SSDP


def _filter_placeholders(nodes: list[Node]) -> list[Node]:
    """过滤占位节点：订阅服务器对非官方客户端返回的假节点。
    特征：server是1.1.1.1/7.7.7.7等，或port=1/0，或 NTP/SSDP/追踪占位。"""
    real = []
    for n in nodes:
        srv = (n.server or "").strip()
        port = n.port or 0
        if srv.lower() in _PLACEHOLDER_HOSTS:
            continue
        if srv in _PLACEHOLDER_IPS:
            continue
        if port in _PLACEHOLDER_PORTS:
            continue
        # 名字含"占位"/"placeholder"也滤
        name = (n.name or "").lower()
        if "占位" in name or "placeholder" in name:
            continue
        real.append(n)
    return real


def _is_ip_literal(host: str) -> bool:
    """server 本身就是 IP（含 IPv6 冒号写法）时不需要查 CNAME。"""
    h = (host or "").strip()
    if not h:
        return False
    if ":" in h:
        return True
    parts = h.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _enrich_and_detect(airport: str, nodes: list[Node], detector: Detector):
    """给每个节点解析 server→IP，批量 RDAP，再跑华为检测。"""
    import concurrent.futures
    # 过滤占位节点
    nodes[:] = _filter_placeholders(nodes)
    all_ips = set()
    
    # 并发解析域名→IP，单域名超时5s
    # 如果节点已有预填的 _resolved_ips（如 v2board server/fetch 的 listen_ip），跳过DNS
    hosts = [(i, n.server) for i, n in enumerate(nodes)
             if not n.raw.get("_resolved_ips")]
    # P0 修复：as_completed 的总超时只作死锁兜底（原 30s 会把大订阅正常富化
    # 500域名×5s/16线程≈156s 判成超时炸掉整个机场）；未完成项统一标空，
    # 单域名失败已被 fut.result(timeout=5) 隔离，不再连坐全批。
    fut_map = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for i, h in hosts:
            fut_map[ex.submit(resolve_detail, h)] = i
        pending = set(fut_map)
        try:
            for fut in concurrent.futures.as_completed(fut_map, timeout=600):
                idx = fut_map[fut]
                try:
                    ips, alt = fut.result(timeout=5)
                except Exception:
                    ips, alt = [], []
                nodes[idx].raw["_resolved_ips"] = ips
                if alt:
                    # 海外 DNS 才解析到的 IP（GeoDNS 分线的另一半），面板单独标注
                    nodes[idx].raw["_ip_alt"] = alt
                all_ips.update(ips)
                pending.discard(fut)
        except concurrent.futures.TimeoutError:
            pass
        for fut in pending:
            nodes[fut_map[fut]].raw["_resolved_ips"] = []

    # 收集所有IP（包括预填的）
    for n in nodes:
        ips = n.raw.get("_resolved_ips") or []
        all_ips.update(ips)
    
    # 未完成的节点也标记空
    for n in nodes:
        if "_resolved_ips" not in n.raw:
            n.raw["_resolved_ips"] = []
    
    # CNAME 链：节点名 CNAME 到 CDN 域（cdnhwc* = 华为云 CDN）时，
    # 只看 server 字符串是看不见的，这里补一层域名维度证据。
    domain_hosts = [n.server for n in nodes
                    if n.server and not _is_ip_literal(n.server)]
    if domain_hosts:
        try:
            cmap = cname_many(domain_hosts)
        except Exception:
            cmap = {}
        for n in nodes:
            if n.server in cmap:
                n.raw["_cnames"] = cmap[n.server]

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
    save_raw(name, resp.text, {"status": resp.status_code,
                               "via": "direct"}, via="direct")
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
    save_raw(slug, text, meta, via="manual-url")
    nodes = parse_subscription(text)
    meta["panel_type"] = "manual-url"
    snap = Snapshot(airport=slug, ts=store.now_iso(), source=sub_url,
                    nodes=nodes, meta=meta)
    snap.findings = _enrich_and_detect(slug, nodes, detector)
    return snap


def collect_server_fetch(slug: str, panel: str, email: str, password: str,
                         detector: Detector) -> Snapshot:
    """v2board server/fetch 采集器：登录→直接拿节点列表→转Node→富化→华为检测。

    绕过订阅URL的客户端指纹检测（如 wdy/wandacloud 返回占位1.1.1.1）。
    只要有账号能登录就能拿真节点。"""
    from .login import v2board_server_fetch
    servers, auth = v2board_server_fetch(panel, email, password)
    nodes = _v2board_servers_to_nodes(servers)
    snap = Snapshot(airport=slug, ts=store.now_iso(),
                    source=f"{panel}/api/v1/user/server/fetch",
                    nodes=nodes, meta={"panel_type": "v2board-server-fetch"})
    snap.findings = _enrich_and_detect(slug, nodes, detector)
    return snap


def _v2board_servers_to_nodes(servers: list[dict]) -> list[Node]:
    """把 v2board /api/v1/user/server/fetch 返回的 server 数组转成 Node 列表。"""
    nodes = []
    for sv in servers:
        # v2board 偶尔把 name/host 返回成 null（不是缺字段），直接 .strip() 会
        # AttributeError: 'NoneType' object has no attribute 'strip'，
        # 表现为「server/fetch失败」但订阅直抓正常——cloudnx 就是这样被误判的。
        name = (sv.get("name") or "").strip()
        host = (sv.get("host") or "").strip()
        port = sv.get("port") or sv.get("server_port") or 0
        proto = sv.get("type", "") or sv.get("protocol", "")
        if not host or not port:
            continue
        # v2board 的 type 字段如 v2node/xxx，protocol 字段才是真正的协议
        proto = sv.get("protocol", "") or proto
        # 映射到标准协议名
        proto_map = {"v2node": "anytls", "vmess": "vmess", "vless": "vless",
                     "trojan": "trojan", "shadowsocks": "ss", "ss": "ss"}
        proto = proto_map.get(proto, proto)
        # listen_ip 是服务器真实IP，直接预填到 _resolved_ips 避免DNS解析
        listen_ip = sv.get("listen_ip") or ""
        resolved = []
        if listen_ip and listen_ip != "0.0.0.0":
            resolved = [listen_ip]
        raw = {
            "host": host,
            "tls": sv.get("tls"),
            "tls_settings": sv.get("tls_settings"),
            "network": sv.get("network"),
            "network_settings": sv.get("network_settings"),
            "tags": sv.get("tags"),
            "is_online": sv.get("is_online"),
            "_resolved_ips": resolved,  # 预填落地IP
        }
        nodes.append(Node(name=name, protocol=proto or "unknown", server=host,
                          port=int(port) if port else 0, raw=raw))
    return nodes


def collect_login(slug: str, panel: str, email: str, password: str,
                  detector: Detector, ptype: str = "auto") -> tuple[Snapshot, str, str]:
    """凭证驱动：自动登录取订阅链接 → 抓节点 → 富化 → 华为检测。

    返回 (snap, sub_url, 识别到的面板类型)。
    """
    sub_url, _auth, kind = smart_login(panel, email, password, ptype)
    text, meta = fetch_subscription(sub_url)
    save_raw(slug, text, meta, via="login:" + str(kind))
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
