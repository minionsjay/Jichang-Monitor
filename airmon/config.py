"""加载 airports.yaml 机场注册表。"""
from __future__ import annotations

import os
import yaml

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_REGISTRY = os.path.join(_HERE, "airports.yaml")


def load_airports(path: str | None = None) -> dict[str, dict]:
    """返回 {name: airport_dict}。"""
    path = path or DEFAULT_REGISTRY
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    out = {}
    for a in data.get("airports", []):
        out[a["name"]] = a
    return out


def get_airport(name: str, path: str | None = None) -> dict:
    airports = load_airports(path)
    if name not in airports:
        raise KeyError(f"未知机场: {name}（可选: {', '.join(airports)}）")
    return airports[name]


def load_credentials(path: str | None = None) -> dict:
    """读 credentials.yaml → {slug: {email, password, panel}}，已并入 defaults。"""
    path = path or os.path.join(_HERE, "credentials.yaml")
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"未找到 {path}；请把 credentials.example.yaml 复制为 credentials.yaml 并填写")
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    defaults = data.get("defaults") or {}
    out = {}
    for slug, acct in (data.get("accounts") or {}).items():
        acct = acct or {}
        out[slug] = {
            "email": acct.get("email", defaults.get("email")),
            "password": acct.get("password", defaults.get("password")),
            "panel": acct.get("panel"),
            "type": acct.get("type", defaults.get("type", "auto")),
            "sub_url": acct.get("sub_url"),
            "user_agent": acct.get("user_agent", "clash.meta"),
            "cookie": acct.get("cookie"),      # JS节点页机场：浏览器登录态
            "base": acct.get("base"),          # 该机场后台域名（cookie 类用）
            "max_id": acct.get("max_id", 300),
            # 客户端配置（也可在 airports.yaml 的 client 字段里配）
            "client": acct.get("client"),     # {package, install_dir, core_process, data_dir}
        }
    return out


def seed_domains(path: str | None = None) -> dict[str, list[str]]:
    """从 seeds.txt 读 {slug: [domains]}，用于 panel 兜底。"""
    path = path or os.path.join(_HERE, "seeds.txt")
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "|" not in line:
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) == 3:
                out[parts[0]] = [d.strip() for d in parts[2].split(";") if d.strip()]
    return out
