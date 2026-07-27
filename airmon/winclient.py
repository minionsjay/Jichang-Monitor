"""Windows 客户端数据目录扫描 — 从 AppData 提取订阅 URL、API 域名、节点配置。

适用于在 Windows 上安装了客户端软件的机场（FlClash 变种等）。
能处理加密的 config.yaml（通过 shared_preferences.json 和 database.sqlite 提取信息）。

使用方式：
  python3 run.py scan-win-client --airport wandacloud --dir "C:\\Users\\minions\\AppData\\Roaming\\wandacloud"
  python3 run.py scan-win-client --airport speedcat --dir "C:\\Users\\minions\\AppData\\Roaming\\SpeedCat"
"""
from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
from urllib.parse import urlparse

from .models import Node, Snapshot, Finding
from . import store


def _to_wsl_path(path: str) -> str:
    """Convert Windows path to WSL-compatible path."""
    if len(path) >= 3 and path[1] == ":" and path[2] in ("\\", "/"):
        drive = path[0].lower()
        rest = path[3:].replace("\\", "/")
        return f"/mnt/{drive}/{rest}"
    return path




# 已知的非代理域名
NON_PROXY_DOMAINS = {
    'www.gstatic.com', 'dns.alidns.com', 'dns.cloudflare.com',
    'api2.cursor.sh', 'gemini.google.com', 'github.com',
    'metacubex.com', 'img.alicdn.com', 'o.alicdn.com',
}


def _is_ip(s: str) -> bool:
    parts = s.split('.')
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def scan_shared_preferences(dir_path: str) -> dict:
    """从 shared_preferences.json 提取信息。"""
    sp_path = os.path.join(dir_path, "shared_preferences.json")
    if not os.path.exists(sp_path):
        # Try subdirectory (FlClash nests it)
        for root, _, files in os.walk(dir_path):
            if "shared_preferences.json" in files:
                sp_path = os.path.join(root, "shared_preferences.json")
                break

    if not os.path.exists(sp_path):
        return {}

    with open(sp_path, encoding="utf-8") as f:
        data = json.load(f)

    result = {
        "email": data.get("flutter.email", "").strip(),
        "auth_token": data.get("flutter.auth_token", ""),
        "api_base_url": data.get("flutter.api_base_url", ""),
        "cached_subscribe_info": {},
        "config": {},
    }

    # Parse cached subscribe info
    sub_info_str = data.get("flutter.cached_subscribe_info", "")
    if sub_info_str:
        try:
            result["cached_subscribe_info"] = json.loads(sub_info_str)
        except (json.JSONDecodeError, TypeError):
            pass

    # Parse flutter.config
    config_str = data.get("flutter.config", "{}")
    if config_str:
        try:
            config = json.loads(config_str)
            patch = config.get("patchClashConfig", {})
            result["config"] = {
                "mixed_port": patch.get("mixed-port"),
                "external_controller": patch.get("external-controller", ""),
                "current_profile_id": config.get("currentProfileId"),
            }
        except (json.JSONDecodeError, TypeError):
            pass

    return result


def scan_database(dir_path: str) -> list[dict]:
    """从 database.sqlite 提取订阅信息。"""
    db_path = os.path.join(dir_path, "database.sqlite")
    if not os.path.exists(db_path):
        for root, _, files in os.walk(dir_path):
            if "database.sqlite" in files:
                db_path = os.path.join(root, "database.sqlite")
                break

    if not os.path.exists(db_path):
        return []

    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        tables = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]

        profiles = []
        if "profiles" in tables:
            cur.execute("SELECT id, label, url, subscription_info FROM profiles")
            for row in cur.fetchall():
                profiles.append({
                    "id": row[0],
                    "label": row[1],
                    "url": row[2],
                    "subscription_info": row[3],
                })
        conn.close()
        return profiles
    except sqlite3.Error:
        return []


def scan_binary_for_urls(app_so_path: str) -> list[str]:
    """从 Flutter app.so 二进制中提取 API 域名和 URL。"""
    if not os.path.exists(app_so_path):
        return []

    urls = set()
    with open(app_so_path, "rb") as f:
        data = f.read()

    # Search for URLs
    for m in re.finditer(rb'https?://[a-zA-Z0-9._\-/]{5,100}', data):
        url = m.group().decode('ascii', errors='replace')
        # Filter out framework/library URLs
        if any(skip in url for skip in [
            'flutter.dev', 'github.com', 'google.com', 'w3.org',
            'ibm.com', 'mozilla.org', 'schema.org',
        ]):
            continue
        urls.add(url)

    return sorted(urls)


def scan_config_yaml(dir_path: str) -> dict:
    """尝试读取 config.yaml（可能是加密的）。"""
    cfg_path = os.path.join(dir_path, "config.yaml")
    if not os.path.exists(cfg_path):
        return {}

    with open(cfg_path, "r", encoding="utf-8", errors="replace") as f:
        data = f.read()

    result = {"encrypted": False, "size": len(data)}

    # Check if it's base64 encoded (encrypted)
    import string
    b64_chars = set(string.ascii_letters + string.digits + '+/=')
    non_b64 = set(data) - b64_chars - set('\n\r')
    if len(non_b64) == 0 and len(data) > 100:
        result["encrypted"] = True
        try:
            decoded = base64.b64decode(data)
            result["decoded_size"] = len(decoded)
            result["entropy"] = _entropy(decoded)
        except Exception:
            pass
    elif "proxies:" in data or "mixed-port" in data:
        # Plain text config
        result["encrypted"] = False
        result["content"] = data

    return result


def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy of bytes."""
    if not data:
        return 0.0
    from collections import Counter
    import math
    cnt = Counter(data)
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in cnt.values())


def collect_win_client(slug: str, client_dir: str, detector=None,
                       app_dir: str = None) -> tuple[Snapshot, dict]:
    client_dir = _to_wsl_path(client_dir)
    if app_dir:
        app_dir = _to_wsl_path(app_dir)
    """扫描 Windows 客户端数据目录。

    Args:
        slug: 机场 slug
        client_dir: 客户端数据目录（如 AppData/Roaming/wandacloud）
        detector: 华为检测器
        app_dir: 客户端安装目录（含 data/app.so），用于二进制扫描

    Returns:
        (snapshot, metadata) — metadata 包含订阅URL、API域名、账号信息等
    """
    meta = {}
    sub_urls = []
    api_urls = []

    # 1. shared_preferences.json
    sp = scan_shared_preferences(client_dir)
    if sp:
        meta["email"] = sp.get("email", "")
        meta["api_base_url"] = sp.get("api_base_url", "")
        if sp.get("api_base_url"):
            api_urls.append(sp["api_base_url"])

        sub_info = sp.get("cached_subscribe_info", {})
        if sub_info.get("subscribe_url"):
            sub_urls.append(sub_info["subscribe_url"])

    # 2. database.sqlite
    profiles = scan_database(client_dir)
    if profiles:
        meta["profiles"] = profiles
        for p in profiles:
            if p.get("url"):
                sub_urls.append(p["url"])

    # 3. config.yaml
    cfg = scan_config_yaml(client_dir)
    if cfg:
        meta["config_encrypted"] = cfg.get("encrypted", False)
        meta["config_size"] = cfg.get("size", 0)
        if cfg.get("content"):
            # Plain text config — parse nodes
            from .parse import parse_clash_yaml
            nodes = parse_clash_yaml(cfg["content"])
            if nodes:
                snap = Snapshot(
                    airport=slug, ts=store.now_iso(),
                    source=f"win_client:{client_dir}",
                    nodes=nodes, meta=meta,
                )
                if detector:
                    from .collect import _enrich_and_detect
                    snap.findings = _enrich_and_detect(slug, nodes, detector)
                return snap, {"sub_urls": sub_urls, "api_urls": api_urls, **meta}

    # 4. Binary scan for URLs
    if app_dir:
        app_so = os.path.join(app_dir, "data", "app.so")
        if not os.path.exists(app_so):
            # Try direct path
            for candidate in [
                os.path.join(app_dir, "app.so"),
                os.path.join(app_dir, "data", "flutter_assets", "app.so"),
            ]:
                if os.path.exists(candidate):
                    app_so = candidate
                    break

        if os.path.exists(app_so):
            urls = scan_binary_for_urls(app_so)
            meta["binary_urls"] = urls
            api_urls.extend(urls)

    # 5. If we have sub_urls, try to fetch nodes
    nodes = []
    if sub_urls:
        meta["sub_urls"] = sub_urls
        for url in sub_urls[:3]:  # Try first 3 URLs
            try:
                import requests
                resp = requests.get(url, headers={"User-Agent": "clash.meta"},
                                    timeout=30, verify=False)
                if resp.status_code == 200:
                    from .parse import parse_subscription
                    parsed = parse_subscription(resp.text)
                    if parsed:
                        nodes.extend(parsed)
                        meta["fetched_from"] = url
                        break
            except Exception:
                pass

    # 6. Fallback: collect what we know as raw info
    meta["sub_urls"] = sub_urls
    meta["api_urls"] = list(set(api_urls))

    snap = Snapshot(
        airport=slug, ts=store.now_iso(),
        source=f"win_client:{client_dir}",
        nodes=nodes, meta=meta,
    )

    if detector and nodes:
        from .collect import _enrich_and_detect
        snap.findings = _enrich_and_detect(slug, nodes, detector)

    return snap, {"sub_urls": sub_urls, "api_urls": api_urls, **meta}
