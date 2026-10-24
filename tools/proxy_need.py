"""探测每家机场「直连能不能拿到订阅/面板」，产出 data/proxy_need.json。

为什么要有这个：面板上的「获取节点」按钮会按代理是否可用决定走直连还是走代理，
但没人知道**哪几家其实不需要代理**。有了这份清单，代理没开时面板可以明确告诉你
「这 12 家直连就行，剩下 35 家没代理大概率超时」。

判定口径（每个目标分别测两次）：
- direct: 不走代理直接请求
- proxy : 通过本机 HTTP 代理（默认 http://[::1]:7890）
只读第一段响应（最多 4KB），不下载全部；只看「能不能拿到 HTTP 响应」，
不判断响应内容是不是节点——那是拉取阶段的事。

用法：
    python -X utf8 tools/proxy_need.py [--only a,b] [--workers 12] [--timeout 8]
"""

from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(DATA, "proxy_need.json")
CRED = os.path.join(ROOT, "credentials.yaml")

# 不再写死端口：Clash 用 7890，v2rayN 的 mixed 入站是 10808，探测见 airmon/netcfg.py
def _proxy_url() -> "str | None":
    sys.path.insert(0, ROOT)
    try:
        from airmon.netcfg import detect
        return detect()
    except Exception:  # noqa: BLE001
        return None
UA = "clash.meta/1.19.0"


def _load_creds() -> dict:
    try:
        import yaml
    except ImportError:
        print("需要 pyyaml")
        return {}
    try:
        with io.open(CRED, encoding="utf-8") as f:
            j = yaml.safe_load(f) or {}
    except OSError:
        return {}
    acc = j.get("accounts") or {}
    return acc if isinstance(acc, dict) else {}


def _proxy_alive(timeout: float = 1.0) -> bool:
    return bool(_proxy_url())


def _probe(url: str, use_proxy: bool, timeout: float) -> dict:
    """返回 {ok, code, ms, err}。只读第一段。"""
    import time
    import requests

    t0 = time.time()
    proxies = None
    if use_proxy:
        proxies = {"http": _proxy_url(), "https": _proxy_url()} if use_proxy else None
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout,
                         verify=False, stream=True, proxies=proxies)
        try:
            next(r.iter_content(4096), b"")
        except Exception:  # noqa: BLE001
            pass
        code = r.status_code
        r.close()
        return {"ok": 200 <= code < 400, "code": code,
                "ms": int((time.time() - t0) * 1000)}
    except Exception as e:  # noqa: BLE001
        name = type(e).__name__
        detail = str(e)[:80]
        return {"ok": False, "code": None, "ms": int((time.time() - t0) * 1000),
                "err": (name + ": " + detail) if detail else name}


def _one(slug: str, cred: dict, use_proxy: bool, timeout: float) -> tuple[str, dict]:
    out = {}
    sub = (cred or {}).get("sub_url")
    panel = (cred or {}).get("panel")
    if sub:
        out["sub_direct" if not use_proxy else "sub_proxy"] = _probe(sub, use_proxy, timeout)
    if panel:
        base = panel.strip()
        if not base.startswith("http"):
            base = "https://" + base
        out["panel_direct" if not use_proxy else "panel_proxy"] = _probe(base, use_proxy, timeout)
    return slug, out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--no-proxy-group", action="store_true",
                    help="跳过走代理那一组（代理没开时用）")
    a = ap.parse_args(argv)

    creds = _load_creds()
    if not creds:
        print("读不到 credentials.yaml")
        return 1
    only = [x.strip() for x in a.only.split(",") if x.strip()]
    slugs = [s for s in creds if not only or s in only]

    import urllib3
    urllib3.disable_warnings()

    proxy_on = _proxy_alive()
    print(f"代理 {_proxy_url() or '（未探测到）'} → {'可用' if proxy_on else '不可用'}；机场 {len(slugs)} 家")

    result = {
        "generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "proxy_alive": proxy_on,
        "proxy_url": _proxy_url() or "",
        "timeout_s": a.timeout,
        "airports": {},
    }

    def job(slug: str) -> tuple[str, dict]:
        cred = creds.get(slug) or {}
        _, d = _one(slug, cred, False, a.timeout)
        p = {}
        if proxy_on and not a.no_proxy_group:
            _, p = _one(slug, cred, True, a.timeout)
        d.update(p)
        return slug, d

    done = 0
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        for slug, d in ex.map(job, slugs):
            result["airports"][slug] = d
            done += 1
            if done % 10 == 0:
                print(f"  ... {done}/{len(slugs)}")

    # 汇总：订阅维度（本清单的主用途）
    only_direct = [s for s, d in result["airports"].items()
                   if (d.get("sub_direct") or {}).get("ok") and not (d.get("sub_proxy") or {}).get("ok")]
    need_proxy = [s for s, d in result["airports"].items()
                  if not (d.get("sub_direct") or {}).get("ok") and (d.get("sub_proxy") or {}).get("ok")]
    both = [s for s, d in result["airports"].items()
            if (d.get("sub_direct") or {}).get("ok") and (d.get("sub_proxy") or {}).get("ok")]
    neither = [s for s, d in result["airports"].items()
               if d.get("sub_direct") and not (d.get("sub_direct") or {}).get("ok")
               and (not proxy_on or not (d.get("sub_proxy") or {}).get("ok"))]
    result["summary"] = {
        "sub_direct_only": only_direct,
        "sub_need_proxy": need_proxy,
        "sub_both": both,
        "sub_unreachable": neither,
        "counts": {"direct_only": len(only_direct), "need_proxy": len(need_proxy),
                   "both": len(both), "unreachable": len(neither)},
    }

    os.makedirs(DATA, exist_ok=True)
    with io.open(OUT, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)

    c = result["summary"]["counts"]
    print(f"订阅可达性：只直连 {c['direct_only']} / 只代理 {c['need_proxy']} / "
          f"都通 {c['both']} / 都不通 {c['unreachable']}")
    print(f"已写入 {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
