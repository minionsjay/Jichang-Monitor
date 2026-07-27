"""订阅内容 → list[Node]。

支持三种输入：
  1) Base64 blob（解码后每行一个 xxx:// 节点 URI）
  2) 明文节点 URI 列表（每行一个）
  3) Clash / mihomo YAML（proxies: 列表；含私有 type: ninja）
"""
from __future__ import annotations

import base64
import binascii
import json
from urllib.parse import urlparse, unquote, parse_qs

import yaml

from .models import Node

_URI_SCHEMES = ("vmess", "vless", "trojan", "ss", "ssr",
                "hysteria", "hysteria2", "hy2", "tuic", "anytls", "socks", "http")


def _b64decode(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def parse_subscription(content: str) -> list[Node]:
    """自动识别格式并解析。"""
    text = content.strip()
    if not text:
        return []
    # Clash YAML？
    if "proxies:" in text and ("server:" in text or "type:" in text):
        try:
            return parse_clash_yaml(text)
        except Exception:
            pass
    # 直接就是 URI 列表？
    if any(text.startswith(s + "://") for s in _URI_SCHEMES):
        return parse_uri_list(text)
    # 否则当 Base64 blob
    try:
        decoded = _b64decode(text).decode("utf-8", "replace")
        if any((s + "://") in decoded for s in _URI_SCHEMES):
            return parse_uri_list(decoded)
    except (binascii.Error, ValueError):
        pass
    # 最后再试 YAML
    return parse_clash_yaml(text)


def parse_clash_yaml(text: str) -> list[Node]:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        return []
    nodes = []
    for p in data.get("proxies", []) or []:
        if not isinstance(p, dict):
            continue
        port = p.get("port")
        try:
            port = int(port) if port is not None else None
        except (TypeError, ValueError):
            port = None
        nodes.append(Node(
            name=str(p.get("name", "")),
            protocol=str(p.get("type", "")),
            server=str(p.get("server", "")),
            port=port,
            raw=p,
        ))
    return nodes


_SINGBOX_SKIP = {"direct", "block", "dns", "selector", "urltest", "socks", "http"}


def parse_singbox_json(text: str) -> list[Node]:
    """sing-box config.json 的 outbounds 列表 → Node。"""
    data = json.loads(text)
    obs = data.get("outbounds") if isinstance(data, dict) else None
    if not isinstance(obs, list):
        return []
    nodes = []
    for o in obs:
        if not isinstance(o, dict):
            continue
        typ = str(o.get("type", "")).lower()
        if typ in _SINGBOX_SKIP or not o.get("server"):
            continue
        port = o.get("server_port")
        try:
            port = int(port) if port is not None else None
        except (TypeError, ValueError):
            port = None
        nodes.append(Node(name=str(o.get("tag", "")), protocol=typ,
                          server=str(o.get("server", "")), port=port, raw=o))
    return nodes


def parse_uri_list(text: str) -> list[Node]:
    nodes = []
    for line in text.splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        node = _parse_uri(line)
        if node:
            nodes.append(node)
    return nodes


def _parse_uri(uri: str) -> Node | None:
    scheme = uri.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            return _parse_vmess(uri)
        if scheme == "ss":
            return _parse_ss(uri)
        return _parse_generic(uri, scheme)
    except Exception:
        return None


def _parse_vmess(uri: str) -> Node | None:
    body = uri.split("://", 1)[1]
    info = json.loads(_b64decode(body).decode("utf-8", "replace"))
    port = info.get("port")
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = None
    return Node(name=info.get("ps", ""), protocol="vmess",
                server=str(info.get("add", "")), port=port, raw=info)


def _parse_ss(uri: str) -> Node | None:
    # ss://base64(method:pass)@host:port#name  或  ss://base64(method:pass@host:port)#name
    rest = uri.split("://", 1)[1]
    name = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        name = unquote(frag)
    if "@" in rest:
        _, hostport = rest.rsplit("@", 1)
    else:
        decoded = _b64decode(rest).decode("utf-8", "replace")
        _, hostport = decoded.rsplit("@", 1) if "@" in decoded else ("", decoded)
    host, _, port = hostport.partition(":")
    port = port.split("/")[0].split("?")[0]
    return Node(name=name, protocol="ss", server=host,
                port=int(port) if port.isdigit() else None, raw={"uri": uri})


def _parse_generic(uri: str, scheme: str) -> Node | None:
    # vless / trojan / hysteria2 / tuic / ...：都是 scheme://userinfo@host:port?query#name
    u = urlparse(uri)
    name = unquote(u.fragment) if u.fragment else ""
    proto = {"hy2": "hysteria2"}.get(scheme, scheme)
    raw = {"uri": uri}
    if u.query:
        raw["query"] = {k: v[0] for k, v in parse_qs(u.query).items()}
    return Node(name=name, protocol=proto, server=u.hostname or "",
                port=u.port, raw=raw)
