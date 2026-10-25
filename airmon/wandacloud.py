#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""wandacloud / 万达云（含 wdy）—— 用 `wandacloud_get_nodes.py` 一条命令拿完整节点。

为什么是这个路子
----------------
以前只能提权读 `wandacloudCore.exe` 的进程内存，而且 `airmon/memsan.py` 只认
`"server":"` 开头的完整 JSON，万达云的节点对象是 `{"alpn":…,"server":…,"type":…}`
（server 在中间），所以历来只捞到 IP:端口碎片、协议全 unknown。

但内核无论怎么拿到配置，最终都要交给 Go 的 YAML 解析器
（`gopkg.in/yaml.v3.unmarshal`）。`客户端逆向/wandacloud/工具/wandacloud_get_nodes.py`
用 Frida 在那个入口 dump 入参，就能拿到**完整明文配置**：实测 77 个 anytls 节点，
不需要管理员、不读进程内存。

代价：它每次都会先 taskkill 残留客户端再拉起（单实例锁会让新实例秒退），
所以跑完客户端会被关掉；`client.keep_alive` 也保不住。

用法
----
    python -X utf8 -m airmon.wandacloud                  # 用现有产物导入
    python -X utf8 -m airmon.wandacloud --capture        # 先抓（约 45-60 秒）再导入
    python -X utf8 -m airmon.wandacloud --probe          # 只看现在能不能抓
    python -X utf8 -m airmon.wandacloud --slug wdy       # 写到 wdy 名下
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REVERSE = os.path.join(ROOT, "客户端逆向", "wandacloud")
TOOLS = os.path.join(REVERSE, "工具")
GET_PY = os.path.join(TOOLS, "wandacloud_get_nodes.py")
NODEDIR = os.path.join(REVERSE, "节点")
OUT_DIR = os.path.join(ROOT, "data", "client_nodes")

# 优先用剪好的节点清单（只含 proxies），没有才退到完整配置
CONFIG_CANDIDATES = (
    os.path.join(NODEDIR, "wandacloud-nodes.yaml"),
    os.path.join(NODEDIR, "wandacloud-config.yaml"),
)

# 万达云的入口域名/端口相对稳定，但节点集合会变；太久没抓就别当活的
STALE_HOURS = 36

CAPTURE_MODE_ENV = "AIRMON_WD_CAPTURE"    # always(默认) / auto / never
FRESH_HOURS = 6

# 一个客户端服务两个机场：wandacloud 和 wdy 都是它
SLUGS = ("wandacloud", "wdy", "wandayun")


def _slug_ok(slug: str, client_cfg: dict | None) -> bool:
    """只对万达云生效：按 slug 或 client.package / core_process 认。"""
    cfg = client_cfg or {}
    pkg = str(cfg.get("package") or "").strip().lower()
    core = str(cfg.get("core_process") or "").strip().lower()
    s = (slug or "").strip().lower()
    return (
        s in SLUGS
        or "wandacloud" in pkg or "wandacloud" in core
        or "wandayun" in pkg or "wanda" in core
    )


def _load_yaml(path: str) -> dict:
    try:
        import yaml
    except Exception:                                        # noqa: BLE001
        return {}
    try:
        with io.open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        return doc if isinstance(doc, dict) else {}
    except Exception:                                        # noqa: BLE001
        return {}


def config_path() -> str:
    """最近一次抓到的配置（剪好的节点清单优先）。"""
    for p in CONFIG_CANDIDATES:
        if os.path.exists(p):
            return p
    return ""


def available(slug: str = "wandacloud", client_cfg: dict | None = None) -> bool:
    """能不能拿到配置：认得这台机场，且（有抓包产物 或 抓取脚本还在）。"""
    if not _slug_ok(slug, client_cfg):
        return False
    return bool(config_path()) or os.path.exists(GET_PY)


def age_hours(path: str = "") -> float:
    p = path or config_path()
    if not p or not os.path.exists(p):
        return -1.0
    return round((time.time() - os.path.getmtime(p)) / 3600.0, 1)


def _usable(proxies: list) -> list:
    """剔掉不是节点的条目：信息行（剩余流量/套餐到期）和无效地址。"""
    out = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        t = str(p.get("type") or "").strip().lower()
        srv = str(p.get("server") or "").strip()
        port = p.get("port")
        if not t or not srv:
            continue
        try:
            port = int(port)
        except Exception:                                    # noqa: BLE001
            continue
        if srv.startswith("127.") or srv in ("0.0.0.0", "localhost"):
            continue
        if port <= 1:
            continue
        out.append(p)
    return out


def ingest(slug: str = "wandacloud", path: str = "", write: bool = True) -> dict:
    """把抓包产物转成 data/client_nodes/<slug>.json（nodeset 会读它合并进快照）。

    返回 {ok, path, src, count, protos, captured_at, age_hours, stale, error}
    """
    src = path or config_path()
    out = {"ok": False, "slug": slug, "src": src, "path": "", "count": 0, "protos": {},
           "captured_at": "", "age_hours": -1.0, "stale": False, "error": ""}
    if not src or not os.path.exists(src):
        out["error"] = "还没有抓包结果（先跑 wandacloud_get_nodes.py）"
        return out

    doc = _load_yaml(src)
    raw = [p for p in (doc.get("proxies") or []) if isinstance(p, dict)]
    if not raw:
        out["error"] = "配置里没有 proxies（路径可能不对：%s）" % os.path.basename(src)
        return out
    proxies = _usable(raw)
    if not proxies:
        out["error"] = "配置里全是信息条目，没有可拨号的"
        return out

    at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    age = age_hours(src)
    cap_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(src)))
    src_tag = "wandacloud-yaml:%s" % os.path.basename(src)
    payload = {
        "extracted_at": at,
        "slug": slug,
        "source": src_tag,
        "captured_at": cap_at,
        "nodes": proxies,
        "groups": [g for g in (doc.get("proxy-groups") or []) if isinstance(g, dict)],
    }
    out.update({
        "ok": True,
        "count": len(proxies),
        "protos": dict(Counter((x.get("type") or "?") for x in proxies)),
        "captured_at": cap_at,
        "age_hours": age,
        "stale": bool(age >= 0 and age > STALE_HOURS),
        "snapshot_source": src_tag,
        "finish_tag": "wandacloud-yaml",
        "dropped": len(raw) - len(proxies),
    })
    if write:
        os.makedirs(OUT_DIR, exist_ok=True)
        dst = os.path.join(OUT_DIR, "%s.json" % slug)
        tmp = dst + ".tmp"
        with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, ensure_ascii=False, indent=1)
        os.replace(tmp, dst)
        out["path"] = dst
    return out


def capture(secs: int = 45, slug: str = "wandacloud") -> dict:
    """拉起客户端→Frida 在内核 YAML 解析入口 dump→导出，然后 ingest。约 45-60 秒。"""
    if not os.path.exists(GET_PY):
        return {"ok": False, "error": "找不到 %s" % GET_PY}
    try:
        r = subprocess.run(
            [sys.executable, "-X", "utf8", GET_PY, "--seconds", str(int(secs))],
            cwd=TOOLS, capture_output=True, timeout=int(secs) * 3 + 180,
        )
    except Exception as e:                                    # noqa: BLE001
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    log = (r.stdout or b"").decode("utf-8", "replace") + (r.stderr or b"").decode("utf-8", "replace")
    res = ingest(slug)
    res["capture_log"] = log[-1200:]
    res["capture_rc"] = r.returncode
    return res


def _mode() -> str:
    m = (os.environ.get(CAPTURE_MODE_ENV) or "always").strip().lower()
    return m if m in ("always", "auto", "never") else "always"


def prepare(slug: str = "wandacloud", client_cfg: dict | None = None, secs: int = 45) -> dict:
    """点一次按钮时该做什么：默认**真去抓**一份新的，而不是读旧缓存。

    - always（默认）：每次拉起客户端抓一份（约 45-60 秒）→ 失败才退回缓存
    - auto：缓存比 FRESH_HOURS 新就直接用，否则抓
    - never：只读缓存
    返回 ingest() 结构，额外带 via = capture / cache / cache-fallback。
    """
    if not _slug_ok(slug, client_cfg):
        return {"ok": False, "error": "这台不是万达云"}
    mode = _mode()
    age = age_hours()
    if mode == "never":
        r = ingest(slug); r["via"] = "cache"; return r
    if mode == "auto" and 0 <= age <= FRESH_HOURS:
        r = ingest(slug); r["via"] = "cache"; return r
    cap = capture(secs, slug)
    if cap.get("ok") and cap.get("count"):
        cap["via"] = "capture"
        return cap
    alt = ingest(slug)
    if alt.get("ok") and alt.get("count"):
        alt["via"] = "cache-fallback"
        alt["capture_error"] = (cap.get("error") or ("rc=%s" % cap.get("capture_rc")))
        alt["capture_log"] = cap.get("capture_log", "")[-600:]
        return alt
    cap["via"] = "capture"
    return cap


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="万达云 / wandacloud 节点导入/抓取")
    ap.add_argument("--capture", action="store_true", help="先抓（约 45-60 秒）再导入")
    ap.add_argument("--probe", action="store_true", help="只看现在能不能抓")
    ap.add_argument("--secs", type=int, default=45, help="抓取等待上限（秒）")
    ap.add_argument("--slug", default="wandacloud", choices=SLUGS)
    ap.add_argument("--src", default="", help="指定配置文件")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)

    if a.probe:
        p = config_path()
        print(json.dumps({
            "slug": a.slug,
            "can_capture": os.path.exists(GET_PY),
            "config": p,
            "age_hours": age_hours(p),
            "stale_hours": STALE_HOURS,
            "mode": _mode(),
        }, ensure_ascii=False, indent=1))
        return 0

    r = capture(a.secs, a.slug) if a.capture else ingest(a.slug, a.src)
    if not a.quiet:
        print(json.dumps({k: r.get(k) for k in
                          ("ok", "count", "protos", "captured_at", "age_hours",
                           "stale", "dropped", "via", "error", "path")},
                         ensure_ascii=False, indent=1))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
