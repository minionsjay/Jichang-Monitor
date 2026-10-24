# -*- coding: utf-8 -*-
"""把「机场已知域名全集」固化成 data/domains.json，供面板抽屉与导出脚本使用。

数据源（任一存在即可）：
  %TEMP%\\domain_manifest.json   —— 2026-10-18 那次全域普查的产物（47 机场 378 域名）
    { slug: { domain: {domain, srcs[], code, title, note} } }

输出：data/domains.json
  { generated_at, note, airports: { slug: {n, alive, domains: [{d, c, t, s[]}]} } }

只输出域名、HTTP 状态码、页面标题、来源标签四类字段，绝不输出任何凭据。
页面标题若出现中文乱码（GBK 被按 latin1 解码）会尝试反向修复。

用法：python -X utf8 tools/build_domains.py [--src <manifest.json>]
"""
from __future__ import annotations

import argparse
import datetime
import io
import json
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(DATA, "domains.json")

DEFAULT_SRC = os.path.join(tempfile.gettempdir(), "domain_manifest.json")

BAD_TITLE = re.compile(r"(?i)(BaseHandler|Traceback|Exception|dict'>|Error 5\d\d)")


def fix_mojibake(s: str) -> str:
    """GBK 被当作 latin1 解码后的乱码，反向还原。"""
    if not s:
        return ""
    if not re.search(r"[ÃÂåæçèéï¼ç]", s):
        return s
    try:
        raw = s.encode("latin1")
    except Exception:
        return s
    # 常见两种：UTF-8 被按 latin1 解码（本机多数），或 GBK 被按 latin1 解码
    for enc in ("utf-8", "gb18030"):
        try:
            out = raw.decode(enc)
            if "\ufffd" not in out:
                return out
        except Exception:
            pass
    # 标题曾按 90 字截断，末字节被切断 → 容忍尾部损坏
    try:
        out = raw.decode("utf-8", "ignore").strip()
        if len(out) >= 2 and "\ufffd" not in out:
            return out
    except Exception:
        pass
    return s


def clean_title(t) -> str:
    s = re.sub(r"\s+", " ", str(t or "")).strip()
    s = fix_mojibake(s)
    if BAD_TITLE.search(s):
        return ""
    return s[:90]


def clean_domain(d) -> str:
    s = re.sub(r"\s+", "", str(d or "")).strip().lower().rstrip(".")
    if not s or len(s) > 120 or "/" in s or " " in s:
        return ""
    if ":" in s:            # IP:端口 之类，不是面板域名
        return ""
    return s


def norm_code(c):
    try:
        return int(c)
    except Exception:
        return "不通"


def build(src: str) -> dict:
    with io.open(src, encoding="utf-8") as f:
        manifest = json.load(f)

    out = {
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "note": "机场已知域名全集（来源：airports.yaml / credentials 面板 / 域名探测 / 推荐站文章）。"
                "只含域名、HTTP 状态码、页面标题、来源标签，不含任何凭据。",
        "airports": {},
    }

    tot = alive = 0
    for slug, bucket in manifest.items():
        vals = list(bucket.values()) if isinstance(bucket, dict) else (bucket or [])
        items, seen = [], set()
        for it in vals:
            if not isinstance(it, dict):
                continue
            dom = clean_domain(it.get("domain"))
            if not dom or dom in seen:
                continue
            seen.add(dom)
            srcs = [re.sub(r"\s+", " ", str(x)).strip()[:28] for x in (it.get("srcs") or [])]
            items.append({
                "d": dom,
                "c": norm_code(it.get("code")),
                "t": clean_title(it.get("title")),
                "s": [x for x in srcs if x][:3],
            })

        items.sort(key=lambda x: (0 if x["c"] == 200 else 1, str(x["d"])))
        n_alive = sum(1 for x in items if x["c"] == 200)
        out["airports"][slug] = {"n": len(items), "alive": n_alive, "domains": items}
        tot += len(items)
        alive += n_alive

    out["totals"] = {"airports": len(out["airports"]), "domains": tot, "alive": alive}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="固化机场域名全集到 data/domains.json")
    ap.add_argument("--src", default=DEFAULT_SRC, help="domain_manifest.json 路径")
    a = ap.parse_args()

    if not os.path.isfile(a.src):
        print(f"找不到清单: {a.src}", file=sys.stderr)
        return 2

    doc = build(a.src)
    blob = json.dumps(doc, ensure_ascii=False, indent=1)

    leaks = [p for p in ("password", "aead_key", "auth_token", "sub_url=",
                         "subscribe?token", "eyJ", "@qq.com", "@gmail.com") if p in blob]
    if leaks:
        print(f"泄漏自检未通过：{leaks}", file=sys.stderr)
        return 3

    tmp = OUT + ".tmp"
    with io.open(tmp, "w", encoding="utf-8") as f:
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, OUT)

    t = doc["totals"]
    print(f"written {OUT} | 机场 {t['airports']} | 域名 {t['domains']} | 可打开 {t['alive']} | 泄漏自检 CLEAN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
