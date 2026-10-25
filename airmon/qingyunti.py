"""青云梯（Apex / 极速版）节点提取：从客户端写进内核的那份配置里取。

原理（见 客户端逆向/青云梯-极速版/报告 §11）：
青云梯把整份 mihomo 配置通过本地管道交给内核 `ApexCore.exe`。抓包工具
`qyt_capture_config.py` 用 Frida hook `ws2_32!WriteFile`，在配置被写进管道的
那一瞬间复制一份（客户端窗口隐藏、不点登录/连接，跑完自动收尾）。抓到的
`qyt_config.json` 就是内核配置原文 —— 62 个 vless 节点带 uuid / flow /
reality 参数，比读进程内存捞的碎片完整得多。

两个必须知道的点（来自实测）：
1. `servername`（TLS SNI）每次订阅都会重新随机，server/port/uuid 不变
   → 节点文件有时效，超过 `STALE_HOURS` 就在结果里标 stale，建议重抓。
2. 抓取依赖客户端仍持有登录态；登录态丢了要先在客户端点一次「登录」。

用法：
    python -X utf8 -m airmon.qingyunti            # 从现有 qyt_config.json 导入
    python -X utf8 -m airmon.qingyunti --capture  # 先抓（约 40 秒）再导入
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
REVERSE = os.path.join(ROOT, "客户端逆向", "青云梯-极速版")
TOOLS = os.path.join(REVERSE, "工具")
CAPTURE_PY = os.path.join(TOOLS, "qyt_capture_config.py")
EXPORT_PY = os.path.join(TOOLS, "qyt_export_nodes.py")
OUT_DIR = os.path.join(ROOT, "data", "client_nodes")

CONFIG_CANDIDATES = (
    os.path.join(TOOLS, "qyt_config.json"),
    os.path.join(REVERSE, "证据", "qyt_config.json"),
    os.path.join(REVERSE, "节点", "qingyunti-nodes.json"),
)

# SNI 会随订阅轮换：超过这个小时数就提示重抓（不是"不能用"，是"可能还没轮换"）
STALE_HOURS = 36


def _slug_ok(slug: str, client_cfg: dict | None) -> bool:
    """只对青云梯生效：按 slug 或 client.package / core_process 认。"""
    cfg = client_cfg or {}
    pkg = str(cfg.get("package") or "").strip().lower()
    core = str(cfg.get("core_process") or "").strip().lower()
    if pkg in ("apex", "qingyunti", "qingyunlite") or core == "apexcore":
        return True
    return str(slug or "").strip().lower() in ("qingyunti",)


def config_path() -> str:
    """最近一次抓到的配置文件。

    按候选顺序取第一个存在的：优先原始抓包（`工具/qyt_config.json`，里面还有
    proxy-groups 和规则），没有才退到导出过的 `节点/qingyunti-nodes.json`。
    """
    for p in CONFIG_CANDIDATES:
        if os.path.exists(p):
            return p
    return ""


def available(slug: str = "qingyunti", client_cfg: dict | None = None) -> bool:
    """能不能拿到配置：认得这台机场，且（手上有抓包结果 或 抓包脚本还在）。"""
    if not _slug_ok(slug, client_cfg):
        return False
    return bool(config_path()) or os.path.exists(CAPTURE_PY)


def age_hours(path: str = "") -> float:
    p = path or config_path()
    if not p or not os.path.exists(p):
        return -1.0
    return round((time.time() - os.path.getmtime(p)) / 3600.0, 1)


def ingest(slug: str = "qingyunti", path: str = "", write: bool = True) -> dict:
    """把抓包结果转成 data/client_nodes/<slug>.json（nodeset 会读它合并进快照）。

    返回 {ok, path, src, count, protos, captured_at, age_hours, stale, error}
    """
    src = path or config_path()
    out = {"ok": False, "slug": slug, "src": src, "path": "", "count": 0, "protos": {},
           "captured_at": "", "age_hours": -1.0, "stale": False, "error": ""}
    if not src or not os.path.exists(src):
        out["error"] = "还没有抓包结果（先跑 qyt_capture_config.py --secs 40）"
        return out
    try:
        with io.open(src, encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:                                    # noqa: BLE001
        out["error"] = "配置读不出来：%s: %s" % (type(e).__name__, e)
        return out

    proxies = [p for p in (doc.get("proxies") or []) if isinstance(p, dict)]
    groups = [g for g in (doc.get("proxy-groups") or []) if isinstance(g, dict)]
    if not proxies:
        out["error"] = "配置里没有 proxies（抓到的可能不是内核配置）"
        return out

    at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    age = age_hours(src)
    payload = {
        "extracted_at": at,
        "slug": slug,
        "source": "qyt-capture:%s" % os.path.basename(src),
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(src))),
        "nodes": proxies,
        "groups": groups,
    }
    out.update({
        "ok": True,
        "count": len(proxies),
        "protos": dict(Counter((x.get("type") or "?") for x in proxies)),
        "captured_at": payload["captured_at"],
        "age_hours": age,
        "stale": bool(age >= 0 and age > STALE_HOURS),
        "snapshot_source": "qyt-capture:%s" % os.path.basename(src),
        "finish_tag": "qyt-capture",
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


def capture(secs: int = 40, slug: str = "qingyunti") -> dict:
    """拉起客户端→Frida 截配置→收尾，然后 ingest。约 40 秒，需要登录态还在。"""
    if not os.path.exists(CAPTURE_PY):
        return {"ok": False, "error": "找不到 %s" % CAPTURE_PY}
    try:
        r = subprocess.run([sys.executable, "-X", "utf8", CAPTURE_PY, "--secs", str(secs)],
                           cwd=TOOLS, capture_output=True, timeout=int(secs) + 120)
    except Exception as e:                                    # noqa: BLE001
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    log = (r.stdout or b"").decode("utf-8", "replace") + (r.stderr or b"").decode("utf-8", "replace")
    res = ingest(slug)
    res["capture_log"] = log[-1200:]
    res["capture_rc"] = r.returncode
    return res


CAPTURE_MODE_ENV = "AIRMON_QYT_CAPTURE"   # always(默认) / auto / never
FRESH_HOURS = 6          # auto 模式下，缓存比这新就不重抓


def _mode() -> str:
    m = (os.environ.get(CAPTURE_MODE_ENV) or "always").strip().lower()
    return m if m in ("always", "auto", "never") else "always"


def prepare(slug: str = "qingyunti", client_cfg: dict | None = None,
            secs: int = 40) -> dict:
    """点一次按钮时该做什么：默认**真去抓**一份新的，而不是读旧缓存。

    - always（默认）：每次都拉起客户端抓一份（约 40 秒）→ 失败才退回缓存
    - auto：缓存比 FRESH_HOURS 新就直接用，否则抓
    - never：只读缓存（CI / 不想被打断客户端时用）
    返回 ingest() 结构，额外带 via = capture / cache / cache-fallback。
    """
    if not _slug_ok(slug, client_cfg):
        return {"ok": False, "error": "这台不是青云梯"}
    mode = _mode()
    age = age_hours()
    if mode == "never":
        r = ingest(slug); r["via"] = "cache"; return r
    if mode == "auto" and 0 <= age <= FRESH_HOURS:
        r = ingest(slug); r["via"] = "cache"; return r
    cap = capture(secs, slug)          # capture() 里已经 ingest 过
    if cap.get("ok") and cap.get("count"):
        cap["via"] = "capture"
        return cap
    alt = ingest(slug)                 # 抓失败 → 退回手上的旧缓存，别让这次变 0
    if alt.get("ok") and alt.get("count"):
        alt["via"] = "cache-fallback"
        alt["capture_error"] = (cap.get("error") or ("rc=%s" % cap.get("capture_rc")))
        alt["capture_log"] = cap.get("capture_log", "")[-600:]
        return alt
    cap["via"] = "capture"
    return cap


def main(argv=None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="airmon.qingyunti",
                                description="青云梯节点提取（抓包结果 → client_nodes）")
    p.add_argument("--capture", action="store_true", help="先跑一次抓包（约 40 秒）再导入")
    p.add_argument("--secs", type=int, default=40, help="抓包时长（默认 40）")
    p.add_argument("--slug", default="qingyunti")
    p.add_argument("--src", default="", help="指定 qyt_config.json")
    p.add_argument("--probe", action="store_true", help="只看现状，不写盘")
    a = p.parse_args(argv)

    if a.probe:
        cp = config_path()
        print("配置: %s" % (cp or "（没有）"))
        if cp:
            print("抓于: %s（%.1f 小时前）" % (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(cp))),
                age_hours(cp)))
        r = ingest(a.slug, a.src, write=False)
    elif a.capture:
        print("开始抓包（%d 秒，客户端会短暂出现后自动收尾）..." % a.secs, flush=True)
        r = capture(a.secs, a.slug)
    else:
        r = ingest(a.slug, a.src)

    if not r.get("ok"):
        print("失败：%s" % r.get("error"))
        return 1
    print("节点 %d | 协议 %s | 抓于 %s（%.1f 小时前）%s" % (
        r["count"], r["protos"], r["captured_at"], r["age_hours"],
        " · 已超 %d 小时建议重抓（SNI 会轮换）" % STALE_HOURS if r["stale"] else ""))
    if r.get("path"):
        print("已写 %s" % r["path"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
