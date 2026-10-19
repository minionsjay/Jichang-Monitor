# -*- coding: utf-8 -*-
"""sitewatch —— 免费机场/候选机场域名存活监控（不登录、不抓订阅、零机密）。

读取项目根目录 freewatch.yaml 的监控名单，逐个探测官网/面板域名是否存活，
结果写入 data/sitewatch.json 并打印表格。供未购买/未注册机场的「可达性监控」用。

用法：
    python -m airmon.sitewatch              # 探测全部并落盘
    python -m airmon.sitewatch --name glados  # 只测指定 name
"""

import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WATCH_FILE = ROOT / "freewatch.yaml"
OUT_FILE = ROOT / "data" / "sitewatch.json"
TIMEOUT = 12
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
PROXY = {"http": "http://[::1]:7890", "https": "http://[::1]:7890"}


def _probe(url: str):
    """返回 (status, title, via)；直连失败走本地代理重试。"""
    last = "ERR"
    for label, ph in (("direct", {"http": None, "https": None}), ("proxy", PROXY)):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            h = urllib.request.build_opener(urllib.request.ProxyHandler(ph))
            h.addheaders = [("User-Agent", UA), ("Accept-Language", "zh-CN")]
            r = h.open(url, timeout=TIMEOUT)
            body = r.read(2500)
            m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.S | re.I)
            title = (m.group(1).decode("utf-8", "ignore").strip() if m else "")[:60]
            return r.status, title, label
        except urllib.error.HTTPError as e:
            return e.code, "", label
        except Exception as e:  # noqa: BLE001
            last = str(e)[:60]
            continue
    return None, last, "fail"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    only = None
    if "--name" in argv:
        only = argv[argv.index("--name") + 1]

    entries = yaml.safe_load(WATCH_FILE.read_text(encoding="utf-8")) or []
    results = []
    for ent in entries:
        name = ent.get("name", "")
        if only and name != only:
            continue
        url = ent["url"]
        status, title, via = _probe(url)
        ok = isinstance(status, int) and 200 <= status < 400 and status != 403
        results.append({
            "name": name,
            "url": url,
            "note": ent.get("note", ""),
            "status": status,
            "title": title,
            "via": via,
            "ok": bool(ok),
        })
        flag = "OK " if ok else "!! "
        print(f"{flag}{name:<14} {url:<36} {str(status):<5} {title}")

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "results": results}
    OUT_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"saved {OUT_FILE} ({len(results)} entries @ {payload['at']})")


if __name__ == "__main__":
    main()
