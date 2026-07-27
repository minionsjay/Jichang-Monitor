"""解析 SSPanel /user/node 页面（或复制的节点文本）→ list[Node]。

页面里每个节点是一组"字段：值"，典型 SSR：
  服务器地址：x  服务器端口：x  加密方式：x  密码：x
  协议：x  协议参数：x  混淆：x  混淆参数：x
支持 HTML（自动去标签）与纯文本；一页多个节点按"服务器地址"切块。
落地 = 服务器地址；混淆参数里的假 host（如 *.windowsupdate.com）不是落地，忽略。
"""
from __future__ import annotations

import html as _html
import re

from .models import Node

_SERVER_ALIASES = ["服务器地址", "主机地址", "服务器", "主机", r"\bhost\b",
                   r"\bserver\b", r"\baddress\b"]
_SERVER_SPLIT = re.compile("(?:%s)\\s*[：:]" % "|".join(_SERVER_ALIASES), re.I)

# 每个字段的标签别名（正则片段）。注意 协议参数/协议、混淆参数/混淆 要区分。
_FIELDS = {
    "server":        _SERVER_ALIASES,
    "port":          ["服务器端口", "端口", r"\bport\b"],
    "method":        ["加密方式", "加密方法", "加密", r"\bmethod\b", "encryption", "cipher"],
    "password":      ["密码", "password", "passwd", r"\bpass\b"],
    "protocol":      [r"协议(?!参数)", r"protocol(?!\s*[_ ]?param)"],
    "protocol_param":["协议参数", r"protocol[_ ]?param", r"proto[_ ]?param"],
    "obfs":          [r"混淆(?!参数)", r"obfs(?!\s*[_ ]?param)"],
    "obfs_param":    ["混淆参数", r"obfs[_ ]?param"],
    "name":          ["节点名称", "节点名", "备注", "名称", r"\bremark\b", r"\bname\b"],
}


def _strip_html(text: str) -> str:
    if "<" in text and ">" in text:
        text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
        text = re.sub(r"<[^>]+>", "\n", text)      # 标签→换行，字段各自成行
        text = _html.unescape(text)
    return text


def _field(block: str, aliases: list[str]) -> str | None:
    for a in aliases:
        m = re.search(a + r"\s*[：:]\s*([^\s<）)]+)", block, re.I)
        if m:
            return m.group(1).strip()
    return None


def parse_node_page(text: str) -> list[Node]:
    text = _strip_html(text)
    idxs = [m.start() for m in _SERVER_SPLIT.finditer(text)]
    if not idxs:
        return []
    idxs.append(len(text))
    nodes = []
    for i in range(len(idxs) - 1):
        block = text[idxs[i]:idxs[i + 1]]
        vals = {k: _field(block, al) for k, al in _FIELDS.items()}
        server = vals.get("server")
        if not server:
            continue
        port = vals.get("port")
        try:
            port = int(port) if port else None
        except ValueError:
            port = None
        proto = "ssr" if (vals.get("protocol") or vals.get("obfs")) else "ss"
        raw = {k: v for k, v in vals.items() if v}
        nodes.append(Node(name=vals.get("name") or "", protocol=proto,
                          server=server, port=port, raw=raw))
    return nodes
