"""Velochron 无客户端订阅采集器 —— 2026-09-17 逆向成果。

完全复刻官方客户端的订阅拉取协议, 无需安装/运行客户端、无需 DPAPI、无需内存扫描:

  1. POST /api/v1/passport/auth/login {email,password} → auth_data
  2. GET  /api/v1/user/getSubscribe (Authorization + App头)
     → subscribe_url (带 600s 短期 app_grant 参数 + flag=aero)
     → aero_sub_key  (32字节hex, 原生订阅的 AES-256-GCM 解密密钥, 随账号下发)
  3. GET  subscribe_url (App头) → base64( nonce(12) + AES-256-GCM(密文) )
  4. AESGCM(aero_sub_key).decrypt(nonce, rest) → aero_v2 节点明文 JSON 数组

协议要点(逆向自 Velochron.exe data/app.so + 内存抓包):
  - 全部 API 需要头: X-App-Signature(客户端构建指纹, 本构建静态值) +
    X-App-Version + X-Client-Platform + User-Agent(必须是 Velochron/x.y.z 形态,
    服务端同时校验 UA 与签名, 缺一 403 "app signature not trusted")
  - getSubscribe 的 subscribe_url 带 &flag=aero&app_grant=<600秒短授权>&rule_caps=udp_port
    —— 缺 app_grant/flag 时订阅端点返回空体
  - 加密方案 X-Aero-Sub-Encrypted: v2 = base64( nonce(12B) || AES-256-GCM(ct) ),
    key = aero_sub_key(hex解码), AAD=None
  - 设备认证(device/challenge + device/attest, RSA-2048 PKCS#1-SHA256)在订阅拉取里
    不是必需的(X-Device-Attest 可省) —— 只影响 trust_level, 不影响 aero 订阅内容
  - X-App-Signature 由客户端对 4 个核心文件(Velochron.exe/nanocore.exe/wintun.dll/
    data/app.so 的 size+mtime)计算, 同一安装包恒定; 1.2.5.3 = e9d56d28…

用法(由 run.py _pull_one 的 velochron-api 优先级自动调用):
    from airmon.velo_api import collect_velo_api
    snap = collect_velo_api("velochron", email, password, detector)
"""
from __future__ import annotations

import base64
import json

import requests
import urllib3

from .models import Node, Snapshot
from . import store

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 本构建(1.2.5.3)的客户端签名 —— 见 shared_preferences.win_bundle_sig_cache_v1
# 若客户端升级导致 403, 重装/解包新版本并从其 sig cache 提取新值
APP_SIGNATURE = "e9d56d284f5f3e7003c987f6c6557be0da8e7f98f381d4e5bf184e56811adc93"
APP_VERSION = "1.2.5.3"
PANEL = "https://api.9aero.com"
UA = f"Velochron/{APP_VERSION} (Windows)"

_AERO_FIELDS = ("type", "aero_v2_edge_psk", "aero_v2_edge_key_version",
                "aero_v2_aead_key", "aero_v2_transport", "aero_v2_carrier_sni",
                "aero_v2_ws_path", "aero_v2_device_identity_mode", "password",
                "auth_id", "node_id", "udp_port", "mtu", "iplc_mode",
                "udp_lane_mode", "resume_ticket", "admin_log_host")


def _login_headers() -> dict:
    """登录必须用普通浏览器头 —— 带 App UA+签名时服务端把请求视为官方客户端,
    会要求设备身份(X-Device-Attest), 返回 403 device_identity_required。"""
    return {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/json"}


def _headers(auth: str | None = None) -> dict:
    h = {"User-Agent": UA, "X-App-Signature": APP_SIGNATURE,
         "X-App-Version": APP_VERSION, "X-Client-Platform": "windows"}
    if auth:
        h["Authorization"] = auth
    return h


def velo_login(email: str, password: str, proxies=None, timeout=25) -> str:
    r = requests.post(f"{PANEL}/api/v1/passport/auth/login",
                      json={"email": email, "password": password},
                      headers=_login_headers(), timeout=timeout, verify=False, proxies=proxies)
    r.raise_for_status()
    d = (r.json().get("data") or {})
    auth = d.get("auth_data") or d.get("token")
    if not auth:
        raise RuntimeError(f"登录失败: {str(r.json())[:120]}")
    return auth


def velo_get_subscribe(auth: str, proxies=None, timeout=25) -> tuple[str, bytes]:
    """返回 (subscribe_url_with_grant, aero_sub_key)。"""
    r = requests.get(f"{PANEL}/api/v1/user/getSubscribe", headers=_headers(auth),
                     timeout=timeout, verify=False, proxies=proxies)
    r.raise_for_status()
    d = (r.json().get("data") or {})
    sub_url = d.get("subscribe_url")
    key_hex = d.get("aero_sub_key")
    if not sub_url or "app_grant=" not in sub_url:
        raise RuntimeError(f"subscribe_url 缺少 app_grant: {str(sub_url)[:120]}")
    if not key_hex:
        raise RuntimeError("响应缺少 aero_sub_key")
    return sub_url, bytes.fromhex(key_hex)


def velo_fetch_decrypt(sub_url: str, key: bytes, proxies=None, timeout=40) -> bytes:
    """拉取并解密原生 aero 订阅 → 明文 JSON 字节。"""
    r = requests.get(sub_url, headers=_headers(), timeout=timeout,
                     verify=False, proxies=proxies)
    r.raise_for_status()
    if not r.content:
        raise RuntimeError("订阅响应为空(grant 过期? 重新 getSubscribe)")
    if r.headers.get("x-aero-sub-encrypted") not in ("v2", None):
        raise RuntimeError(f"未知加密版本: {r.headers.get('x-aero-sub-encrypted')}")
    raw = base64.b64decode(r.content + b"=" * (-len(r.content) % 4))
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    pt = AESGCM(key).decrypt(raw[:12], raw[12:], None)
    return pt


def parse_aero_nodes(payload: bytes) -> list[Node]:
    items = json.loads(payload.decode("utf-8", errors="replace"))
    nodes = []
    for it in items:
        if not isinstance(it, dict) or not it.get("server"):
            continue
        raw = {"source": "velo_api"}
        for k in _AERO_FIELDS:
            if it.get(k) is not None:
                raw[k] = it[k]
        nodes.append(Node(name=str(it.get("name", "node"))[:64],
                          protocol=str(it.get("type", "aero_v2")),
                          server=it["server"],
                          port=int(it.get("server_port") or it.get("port") or 0),
                          raw=raw))
    return nodes


def collect_velo_api(slug: str, email: str, password: str, detector=None,
                     proxies=None) -> Snapshot:
    """完整无客户端流水线: 登录 → getSubscribe → 拉取解密 → Snapshot。"""
    auth = velo_login(email, password, proxies=proxies)
    sub_url, key = velo_get_subscribe(auth, proxies=proxies)
    pt = velo_fetch_decrypt(sub_url, key, proxies=proxies)
    nodes = parse_aero_nodes(pt)
    snap = Snapshot(airport=slug, ts=store.now_iso(),
                    source="velo_api:login+getSubscribe+aesgcm",
                    nodes=nodes,
                    meta={"app_signature": APP_SIGNATURE[:16] + "…",
                          "app_version": APP_VERSION,
                          "protocol": "aero_v2"})
    if detector and nodes:
        from .collect import _enrich_and_detect
        snap.findings = _enrich_and_detect(slug, nodes, detector)
    return snap
