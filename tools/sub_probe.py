"""探一下每家登记的订阅地址现在还能不能拉。

只做一件事：对 `credentials.yaml` 里每个 `sub_url` 发一次 GET（直连优先，
不通再走本机代理），记下状态码与响应大小。**不保存正文**——正文里有节点凭据。

用途：面板抽屉里那条"订阅"链接是真能用、还是早就 404 了，得有个实测依据，
否则客户端型机场（青云梯/DOVE）明明靠本地提取拿节点，界面上却挂着一条死链，
看着像"它有订阅"。

用法：
    python -X utf8 tools/sub_probe.py                # 全部有 sub_url 的机场
    python -X utf8 tools/sub_probe.py --only qingyunti,dovex
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import requests  # noqa: E402
import yaml  # noqa: E402

OUT = os.path.join(ROOT, "data", "sub_probe.json")
UA = "clash.meta/1.18.0"
TIMEOUT = 12


def _accounts() -> dict:
    p = os.path.join(ROOT, "credentials.yaml")
    if not os.path.exists(p):
        return {}
    with io.open(p, encoding="utf-8") as f:
        d = yaml.safe_load(f) or {}
    acc = d.get("accounts") or {}
    return acc if isinstance(acc, dict) else {}


def _proxy() -> str:
    try:
        from airmon import netcfg
        return netcfg.detect() or ""
    except Exception:                                    # noqa: BLE001
        return ""


def probe_one(slug: str, url: str, proxy: str) -> dict:
    out = {"slug": slug, "host": urlparse(url).netloc, "status": None, "bytes": 0,
           "via": "", "ok": False, "note": "", "at": ""}
    if not url:
        out["note"] = "未登记"
        return out
    for via, px in (("direct", None), ("proxy", proxy or None)):
        if via == "proxy" and not px:
            continue
        try:
            r = requests.get(url, proxies={"http": px, "https": px} if px else None,
                             headers={"User-Agent": UA}, timeout=TIMEOUT,
                             allow_redirects=True)
        except Exception as e:                            # noqa: BLE001
            out["note"] = type(e).__name__
            continue
        out.update({"status": r.status_code, "bytes": len(r.content or b""), "via": via,
                    "ok": 200 <= r.status_code < 300 and len(r.content or b"") > 200,
                    "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "note": ""})
        if out["ok"]:
            break
    if not out["at"]:
        out["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tools.sub_probe")
    ap.add_argument("--only", default="", help="逗号分隔 slug")
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args(argv)

    acc = _accounts()
    only = {s.strip() for s in a.only.split(",") if s.strip()}
    targets = [(s, (v or {}).get("sub_url") or "") for s, v in acc.items()
               if isinstance(v, dict) and (not only or s in only)]
    targets = [(s, u) for s, u in targets if u]
    if only:
        targets += [(s, "") for s in only if s not in {t[0] for t in targets}]

    proxy = _proxy()
    print("代理：%s | 目标 %d 家" % (proxy or "（不可用，只测直连）", len(targets)), flush=True)
    res = {}
    with ThreadPoolExecutor(max_workers=max(1, a.workers)) as ex:
        futs = {ex.submit(probe_one, s, u, proxy): s for s, u in targets}
        for f in as_completed(futs):
            r = f.result()
            res[r["slug"]] = {k: v for k, v in r.items() if k != "slug"}
            print("  %-12s %-6s %-7s %8d B  %s" % (
                r["slug"], r["status"] if r["status"] is not None else "-",
                r["via"] or "-", r["bytes"], "OK" if r["ok"] else (r["note"] or "")),
                flush=True)

    doc = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "proxy": bool(proxy), "ua": UA, "airports": res}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = OUT + ".tmp"
    with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(tmp, OUT)
    ok = sum(1 for v in res.values() if v.get("ok"))
    print("可用 %d / %d → %s" % (ok, len(res), OUT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
