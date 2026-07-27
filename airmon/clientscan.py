"""扫描"下客户端登录"型机场的**客户端数据目录**，自动抽节点 + 挖内嵌订阅链接。

适用于任何把节点落到本地配置的客户端(Clash/mihomo/Clash Verge、sing-box、Xray…)。
思路(承接 0701-muniu recon)：客户端自己过签名/登录拉到节点后一定落到本地配置，抠出来即可。

产出：
  - nodes：从各配置文件解析出的节点(已去重)
  - sub_urls：文件里出现的订阅链接(可能直接拿去 pull)
  - api_hits：本地代理内核 external-controller 探到的活节点(可选)
"""
from __future__ import annotations

import json
import os
import re

import requests

from .models import Node
from .parse import parse_clash_yaml, parse_singbox_json

# 非节点配置(规则库/缓存/窗口状态等)，跳过
_SKIP_NAMES = ("geoip", "geosite", "country.mmdb", "cache", "window_state",
               "verge.yaml", ".mmdb", ".dat")

_SUB_URL_RE = re.compile(
    r'https?://[^\s"\'<>]+?(?:subscribe|/link/|/link2/|\?token=|/777/|sub=|/api/v1/client)[^\s"\'<>]*',
    re.I)
# 常见内核 external-controller 端口
_API_PORTS = [9090, 9091, 9097, 6170, 7890]


def scan_client_dir(path: str) -> tuple[list[Node], list[str], dict]:
    """递归扫目录：解析配置里的节点 + 抽订阅链接。返回 (nodes, sub_urls, meta)。"""
    nodes: dict[str, Node] = {}
    sub_urls: set[str] = set()
    scanned = 0
    for root, _, files in os.walk(path):
        for fn in files:
            low = fn.lower()
            if not low.endswith((".yaml", ".yml", ".json")):
                continue
            if any(s in low for s in _SKIP_NAMES):
                continue
            fp = os.path.join(root, fn)
            try:
                with open(fp, encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            scanned += 1
            for m in _SUB_URL_RE.findall(text):
                sub_urls.add(m)
            ns = []
            try:
                if "proxies:" in text:
                    ns = parse_clash_yaml(text)
                elif '"outbounds"' in text or "'outbounds'" in text:
                    ns = parse_singbox_json(text)
            except Exception:
                ns = []
            for n in ns:
                if n.server:
                    nodes[n.key()] = n
    return list(nodes.values()), sorted(sub_urls), {"files_scanned": scanned}


def probe_local_core(secret: str = "", ports=None) -> list[Node]:
    """探本地内核 external-controller，命中就 /proxies dump 活节点(客户端在跑时用)。"""
    ports = ports or _API_PORTS
    headers = {"Authorization": f"Bearer {secret}"} if secret else {}
    out: dict[str, Node] = {}
    for p in ports:
        try:
            r = requests.get(f"http://127.0.0.1:{p}/proxies", headers=headers, timeout=3)
            if r.status_code != 200:
                continue
            data = r.json().get("proxies", {})
            for name, info in data.items():
                if not isinstance(info, dict):
                    continue
                typ = str(info.get("type", "")).lower()
                if typ in ("selector", "urltest", "direct", "reject", "fallback"):
                    continue
                # external-controller 不直接给 server，记录类型/名字，主要用于确认活跃
                out[name] = Node(name=name, protocol=typ, server="", port=None,
                                 raw={"from": f"api:{p}", **info})
        except Exception:
            continue
    return list(out.values())
