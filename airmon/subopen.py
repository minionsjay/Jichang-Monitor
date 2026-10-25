# -*- coding: utf-8 -*-
"""订阅「限时开关」自动开启。

有些机场（ss-id 就是）面板上的订阅链接是**限时开关**：默认关闭，点「开启订阅」后
10 分钟内有效，之后请求一律 403。关键点是——**订阅 token 不变**，变的只是开关状态。
所以不需要重新获取链接，只要把开关打开，原来的订阅地址立刻恢复。

这里直接调面板 API 把开关打开：

    POST {panel}/api/v1/access/openSubscribe
    Authorization: <auth_token>            （无 Bearer 前缀）
    → {"data": {"expired_at": 1792906417, "duration": 600}}

auth_token 是面板登录后的 JWT，存在浏览器的 localStorage（键 `pu:auth`）。
它通常有几周有效期，放在 credentials.yaml 的 <机场名>.auth_token 里；
不要写密码——密码登录会过 Cloudflare Turnstile，脚本过不去。

token 失效时本模块返回 (False, '未登录或登陆已过期…')，上层把机场标成
「订阅关闭」并提示去面板重新登录复制 token，不要反复重试（会触发风控）。
"""
from __future__ import annotations

import base64
import json
import re
import time

import requests


TIMEOUT = 15


def _api_base(panel: str) -> str:
    """把面板地址规整成 API 前缀：去掉 hash、路径，补 /api/v1/access。"""
    p = (panel or "").strip()
    p = p.split("#", 1)[0]
    m = re.match(r"(https?://[^/]+)", p)
    if not m:
        return ""
    return m.group(1).rstrip("/") + "/api/v1/access"


def token_exp(token: str) -> int:
    """解析 JWT 的 exp（不验签，只是本地看一眼）。失败返回 0。"""
    try:
        seg = (token or "").split(".")
        if len(seg) < 2:
            return 0
        s = seg[1] + "=" * (-len(seg[1]) % 4)
        d = json.loads(base64.urlsafe_b64decode(s))
        return int(d.get("exp") or 0)
    except Exception:
        return 0


def token_left_hours(token: str) -> float:
    """token 还剩多少小时；解析不出返回 -1。"""
    exp = token_exp(token)
    if not exp:
        return -1
    return round((exp - time.time()) / 3600.0, 1)


def open_subscribe(panel: str, token: str, proxy: dict | None = None):
    """打开订阅开关。返回 (ok, msg, duration_seconds)。"""
    base = _api_base(panel)
    if not base:
        return False, "面板地址不可用", 0
    if not token:
        return False, "没有 auth_token（需要在面板登录后复制 localStorage 的 pu:auth）", 0
    left = token_left_hours(token)
    if left != -1 and left <= 0:
        return False, f"auth_token 已过期（{abs(left):.0f} 小时前），请重新登录面板复制", 0

    url = base + "/openSubscribe"
    headers = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": token,
    }
    origin = base.split("/api/")[0]
    headers["Referer"] = origin + "/"
    headers["Origin"] = origin
    try:
        r = requests.post(url, headers=headers, json={}, proxies=proxy, timeout=TIMEOUT)
    except Exception as e:
        return False, f"请求面板失败：{str(e)[:80]}", 0

    if r.status_code in (401, 403):
        msg = ""
        try:
            msg = (r.json() or {}).get("message") or ""
        except Exception:
            msg = r.text[:60]
        return False, f"面板拒绝（HTTP {r.status_code}）：{msg or '未登录或登陆已过期'}", 0
    if r.status_code != 200:
        return False, f"面板返回 HTTP {r.status_code}", 0
    try:
        data = (r.json() or {}).get("data") or {}
    except Exception:
        data = {}
    dur = int(data.get("duration") or 0) or 600
    return True, f"已开启，{dur // 60} 分钟内有效", dur


def open_for(slug: str, cred: dict, proxy: dict | None = None):
    """按机场凭据打开订阅开关：读 cred 里的 panel / auth_token。"""
    panel = cred.get("panel") or ""
    token = cred.get("auth_token") or ""
    if not token:
        return False, "该机场没有配置 auth_token（不是限时开关型，或还没填）", 0
    return open_subscribe(panel, token, proxy=proxy)


if __name__ == "__main__":  # 手工排查用：python -m airmon.subopen <机场名>
    import sys

    from .config import load_credentials

    name = sys.argv[1] if len(sys.argv) > 1 else ""
    if not name:
        print("用法：python -X utf8 -m airmon.subopen <机场名>")
        raise SystemExit(1)
    cred = (load_credentials() or {}).get(name) or {}
    print("panel:", cred.get("panel"))
    print("auth_token 剩余小时:", token_left_hours(cred.get("auth_token") or ""))
    ok, msg, dur = open_for(name, cred)
    print("结果:", "OK" if ok else "FAIL", "|", msg)
