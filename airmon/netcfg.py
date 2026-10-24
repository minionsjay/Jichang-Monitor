"""本机 HTTP 代理探测。

为什么需要它：项目里到处硬编码 `http://[::1]:7890`（Clash 的 mixed-port），
但这台机器上真正在跑的是 v2rayN，它的 mixed 入站在 `127.0.0.1:10808`
（实测 http:// 和 socks5:// 两种方式都能转发）。端口写死的结果是：
代理明明开着，所有抓取却报「代理没开」，然后逐家超时。

这里不猜端口，按候选列表逐个**真发一次请求**验证，返回第一个能用的。
只认 HTTP 代理形式（requests 的 proxies 直接吃它；v2rayN 的 mixed 入站也支持）。
"""

from __future__ import annotations

import os
import socket

# 顺序即优先级：Clash 系最常用，其次 v2rayN（实测 10808 是 mixed 入站）
CANDIDATES = (
    "http://127.0.0.1:7890",
    "http://[::1]:7890",
    "http://127.0.0.1:10808",
    "http://127.0.0.1:10809",
    "http://127.0.0.1:7897",
    "http://127.0.0.1:1080",
)

# 探测目标：够小、够稳、不走机场订阅站点（别用机场自己的域名，免得站点挂了误判代理挂了）
TEST_URL = "https://www.gstatic.com/generate_204"

_cache: dict[str, object] = {"url": None, "checked": False}


def _split(url: str) -> tuple[str, int]:
    """http://[::1]:7890 -> ('::1', 7890)"""
    body = url.split("://", 1)[-1]
    host, _, port = body.rpartition(":")
    return host.strip("[]"), int(port)


def _tcp_ok(host: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_ok(url: str, timeout: float = 4.0) -> bool:
    """真走一次代理：能拿到 2xx/3xx 才算通。TCP 通但代理不通的情况太多了。"""
    try:
        import requests
        r = requests.get(TEST_URL, proxies={"http": url, "https": url},
                         timeout=timeout, allow_redirects=False)
        return 200 <= r.status_code < 400
    except Exception:  # noqa: BLE001
        return False


def detect(refresh: bool = False, quick: bool = True) -> str | None:
    """返回第一个可用的代理地址；全不可用返回 None。

    quick=True 只做 TCP 探测（快，几百毫秒）；TCP 通了再确认一次 HTTP，
    都不通就试下一个。quick=False 直接逐个真发请求。
    """
    if _cache["checked"] and not refresh:
        return _cache["url"]  # type: ignore[return-value]

    found = None
    for url in CANDIDATES:
        host, port = _split(url)
        if quick and not _tcp_ok(host, port):
            continue
        if _http_ok(url):
            found = url
            break
    _cache["url"] = found
    _cache["checked"] = True
    return found


def proxy_dict(refresh: bool = False) -> dict | None:
    """给 requests 用的 proxies 字典；没有可用代理返回 None。"""
    url = detect(refresh)
    return {"http": url, "https": url} if url else None


def apply_env(refresh: bool = False) -> str | None:
    """把可用的代理写进环境变量。

    已经设了 HTTP_PROXY 但那个端口不通时（常见：脚本里写死 7890，机器上开的是
    v2rayN 10808），会被改成探测到的地址，而不是傻傻地按死端口重试到超时。
    """
    want = detect(refresh)
    if not want:
        return None
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        os.environ[k] = want
    # 本地/内网地址不该走代理
    os.environ.setdefault(
        "NO_PROXY",
        "127.0.0.1,localhost,::1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,.local",
    )
    return want


def describe(refresh: bool = True) -> dict:
    """给面板/诊断用的说明。"""
    rows = []
    for url in CANDIDATES:
        host, port = _split(url)
        tcp = _tcp_ok(host, port)
        rows.append({"url": url, "listening": tcp,
                     "usable": (_http_ok(url) if tcp else False)})
    usable = next((r["url"] for r in rows if r["usable"]), None)
    return {"usable": usable, "candidates": rows,
            "env": {k: os.environ.get(k) for k in ("HTTP_PROXY", "HTTPS_PROXY")}}


if __name__ == "__main__":
    import json
    print(json.dumps(describe(), ensure_ascii=False, indent=1))
