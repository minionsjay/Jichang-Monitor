"""订阅原始文件存档（data/subraw/）。

为什么单独存：`fetch_subscription()` 拿到的是整段文本（Clash YAML / base64 / 明文链接），
解析成节点后原文就丢了。一旦解析逻辑改版、或想回溯「那天机场到底给了什么」，
没有原文就只能重抓 —— 而机场的订阅链接经常几小时就失效。

目录结构：
    data/subraw/<slug>/<YYYYMMDDTHHMMSSZ>.yaml     ← 原始响应体（后缀按内容嗅探）
    data/subraw/<slug>/<YYYYMMDDTHHMMSSZ>.json     ← 同批元数据（大小/sha256/头/来源）
    data/subraw/index.json                         ← 每机场最新一份的索引（面板读这个）

安全：原文本里必然有节点密码/uuid，也可能带订阅 token。
  · data/subraw/ 已在 .gitignore（和 nodes/ 同级处理）
  · 面板只暴露「时间/大小/格式/host」，不返回正文
  · 正文只给本机 /api/raw/<slug> 下载，且下载前做 token 打码
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import time

from . import snapnames
from typing import Any

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(_HERE, "data", "subraw")

KEEP_PER_AIRPORT = 30          # 每机场保留最近 N 份，更早的删掉
MAX_BYTES = 8 * 1024 * 1024    # 超过 8MB 不存（正常订阅 20~200KB）


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _fname_ts() -> str:
    """本地时间命名，与快照文件名保持一致（如 20261024-212028）。"""
    return snapnames.fmt()


def sniff_ext(text: str) -> str:
    """按内容判格式，给文件起对的后缀（人看的时候能秒懂）。"""
    t = text.lstrip()
    if not t:
        return "empty"
    if t.startswith("proxies:") or "\nproxies:" in t[:2000] or t.startswith("port:"):
        return "yaml"
    if t.startswith("{") or t.startswith("["):
        return "json"
    head = t[:400]
    if re.search(r"^(ss|ssr|vmess|vless|trojan|hysteria2?|anytls|mieru)://", head, re.M):
        return "txt"
    # base64 订阅：只有 base64 字符集且长度像
    compact = re.sub(r"\s+", "", t)
    if compact and re.fullmatch(r"[A-Za-z0-9+/=_\-]+", compact[:2000] or "x") and len(compact) > 64:
        return "b64"
    return "txt"


def save_raw(slug: str, text: str, meta: dict[str, Any] | None = None,
             via: str = "sub") -> dict[str, Any] | None:
    """存一份原始订阅。返回索引项；失败返回 None（绝不抛，调用方是采集主链路）。"""
    try:
        if not slug or text is None:
            return None
        raw = text.encode("utf-8", "replace")
        if len(raw) > MAX_BYTES:
            return None
        d = os.path.join(RAW_DIR, slug)
        os.makedirs(d, exist_ok=True)
        ts = _fname_ts()
        ext = sniff_ext(text)
        fpath = os.path.join(d, f"{ts}.{ext}")
        # 同名（同一秒两次）加序号，避免覆盖
        n = 1
        while os.path.exists(fpath):
            fpath = os.path.join(d, f"{ts}-{n}.{ext}")
            n += 1
        with io.open(fpath, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        item = {
            "slug": slug,
            "at": _now_iso(),
            "file": os.path.relpath(fpath, _HERE).replace("\\", "/"),
            "ext": ext,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()[:16],
            "via": via,
            "meta": {k: (str(v)[:200]) for k, v in (meta or {}).items()},
        }
        with io.open(os.path.splitext(fpath)[0] + ".json", "w", encoding="utf-8") as f:
            json.dump(item, f, ensure_ascii=False, indent=2)
        _trim(d)
        _update_index(slug, item)
        return item
    except Exception:  # noqa: BLE001
        return None


def _trim(d: str) -> None:
    """只留最近 KEEP_PER_AIRPORT 份（按文件名时间序）。"""
    try:
        names = sorted(x for x in os.listdir(d) if not x.endswith(".json"))
        for old in names[:-KEEP_PER_AIRPORT]:
            for cand in (os.path.join(d, old),
                         os.path.join(d, os.path.splitext(old)[0] + ".json")):
                if os.path.exists(cand):
                    os.remove(cand)
    except OSError:
        pass


def _update_index(slug: str, item: dict[str, Any]) -> None:
    try:
        os.makedirs(RAW_DIR, exist_ok=True)
        p = os.path.join(RAW_DIR, "index.json")
        idx: dict[str, Any] = {}
        if os.path.exists(p):
            try:
                with io.open(p, encoding="utf-8") as f:
                    idx = json.load(f) or {}
            except (OSError, ValueError):
                idx = {}
        idx[slug] = {k: item[k] for k in ("at", "file", "ext", "bytes", "sha256", "via")}
        with io.open(p, "w", encoding="utf-8") as f:
            json.dump(idx, f, ensure_ascii=False, indent=2, sort_keys=True)
    except OSError:
        pass


def load_index() -> dict[str, Any]:
    """面板用：slug → 最新一份的元信息（绝不含正文）。"""
    p = os.path.join(RAW_DIR, "index.json")
    try:
        with io.open(p, encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def count_for(slug: str) -> int:
    d = os.path.join(RAW_DIR, slug)
    try:
        return len([x for x in os.listdir(d) if not x.endswith(".json")])
    except OSError:
        return 0


_SECRET_PAT = [
    (re.compile(r"(eyJ[\w-]{6,}\.[\w-]{6,}\.[\w-]{6,})"), "<jwt已隐藏>"),
    (re.compile(r'(?i)("?(?:password|uuid|auth|token|key)"?\s*[:=]\s*")([^"]{6,})(")'), r"\1<已隐藏>\3"),
    (re.compile(r"(?i)(token=)([A-Za-z0-9]{6,})"), r"\1<已隐藏>"),
]


def scrubbed_text(path: str, limit: int = 200_000) -> str:
    """给下载/预览用：把明显凭据打码（不追求完美，避免面板直接把节点密码甩到页面上）。"""
    try:
        with io.open(path, encoding="utf-8", errors="replace") as f:
            t = f.read(limit)
    except OSError:
        return ""
    for pat, rep in _SECRET_PAT:
        t = pat.sub(rep, t)
    return t


if __name__ == "__main__":
    print("RAW_DIR =", RAW_DIR)
    print("索引条目:", len(load_index()))
    for s, it in list(load_index().items())[:5]:
        print(f"  {s:16s} {it['at']}  {it['ext']:5s} {it['bytes']:>7d}B  x{count_for(s)}")
