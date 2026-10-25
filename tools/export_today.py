"""导出「今天」拿到的全部节点（一个包，可直接导入 Clash / v2rayN）。

用途：用户点一下按钮，把今天所有机场的快照里能导出的节点汇成一份
`exports/<日期>/` —— 里面有 Clash 配置、base64 订阅体、CSV 清单、摘要。

设计要点：
* 同一机场当天可能拉过多次，只取**最新**那份（否则同一节点重复几十遍）。
* 节点名加机场前缀，避免不同机场的「香港01」撞名被客户端覆盖。
* 输出目录 exports/ 已在 .gitignore（含凭据，绝不入公开仓库）。
"""
from __future__ import annotations

import argparse
import base64
import calendar
import csv
import io
import json
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from airmon import nodeset  # noqa: E402

DATA = os.path.join(ROOT, "data")
OUT_ROOT = os.path.join(ROOT, "exports")
SNAP_RE = re.compile(r"^(\d{8})[-T]\d{6}Z?\.json$")


def _today_local() -> str:
    return time.strftime("%Y%m%d")


def _snaps_of_day(slug: str, day: str) -> list[str]:
    d = os.path.join(DATA, slug)
    if not os.path.isdir(d):
        return []
    out = []
    for fn in os.listdir(d):
        m = SNAP_RE.match(fn)
        if m and m.group(1) == day:
            out.append(os.path.join(d, fn))
    out.sort()
    return out


def _slugs() -> list[str]:
    root = os.path.join(DATA)
    skip = {"_trash", "_archive", "client_nodes", "subraw", "backup",
            "exports", "quota", "raw", "logs", "sites"}
    out = []
    try:
        for fn in sorted(os.listdir(root)):
            if fn in skip:
                continue
            p = os.path.join(root, fn)
            if os.path.isdir(p) and not fn.startswith("_"):
                out.append(fn)
    except OSError:
        pass
    return out


def _load(path: str) -> dict:
    try:
        with io.open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def export_day(day: str | None = None, out_dir: str | None = None,
               only: list[str] | None = None) -> dict:
    day = day or _today_local()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    res = {"ok": True, "day": day, "generated_at": stamp, "airports": [],
           "proxies": 0, "exported": 0, "skipped": 0, "files": {}}

    rows = []
    proxies_all: list[dict] = []
    seen_names: set[str] = set()
    per_airport = []

    for slug in (only or _slugs()):
        snaps = _snaps_of_day(slug, day)
        if not snaps:
            continue
        snap = _load(snaps[-1])
        nodes = snap.get("nodes") or []
        if not nodes:
            continue
        p_list, skips = [], []
        for nd in nodes:
            if not isinstance(nd, dict):
                continue
            p, why = nodeset._proxy_of(nd)
            if p is None:
                skips.append(why)
                continue
            raw = nd.get("raw") or {}
            ips = raw.get("_resolved_ips") or []
            ip0 = ips[0] if ips else ""
            # 名称加机场前缀去重
            base = str(p.get("name") or nd.get("name") or "node")
            nm = "[%s] %s" % (slug, base)
            k = 2
            orig = nm
            while nm in seen_names:
                nm = "%s #%d" % (orig, k)
                k += 1
            seen_names.add(nm)
            p["name"] = nm
            p_list.append(p)
            rows.append({
                "机场": slug,
                "节点名": base[:60],
                "协议": str(nd.get("protocol") or p.get("type") or ""),
                "server": str(nd.get("server") or "")[:80],
                "port": nd.get("port") or "",
                "解析IP": ip0,
                "IP数": len(ips),
                "可导出": "是",
            })
        if not p_list:
            continue
        proxies_all.extend(p_list)
        per_airport.append({"slug": slug, "exported": len(p_list),
                            "skipped": len(skips), "snapshot": os.path.basename(snaps[-1]),
                            "at": str(snap.get("ts") or "")})
        res["exported"] += len(p_list)
        res["skipped"] += len(skips)

    if not proxies_all:
        res["ok"] = False
        res["error"] = "今天没有可导出的节点（可能还没跑过采集）"
        return res

    out = out_dir or os.path.join(OUT_ROOT, "%s-%s" % (day, time.strftime("%H%M%S")))
    os.makedirs(out, exist_ok=True)

    # ① Clash 配置（一份文件包含全部节点 + 一个手选组）
    names = [p["name"] for p in proxies_all]
    cfg = {
        "proxies": proxies_all,
        "proxy-groups": [
            {"name": "机场合集", "type": "select", "proxies": names},
            {"name": "自动选择", "type": "url-test", "proxies": names,
             "url": "http://www.gstatic.com/generate_204", "interval": 600, "tolerance": 50},
        ],
        "rules": ["MATCH,机场合集"],
    }
    import yaml  # 局部导入：只有导出时才需要
    yaml_path = os.path.join(out, "all-nodes.yaml")
    with io.open(yaml_path, "w", encoding="utf-8", newline="\n") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False, width=4096)

    # ② base64 订阅体（可直接当「订阅链接」导入 v2rayN / NekoBox / Shadowrocket）
    links = []
    for p in proxies_all:
        try:
            links.append(nodeset._link(p))
        except Exception:
            continue
    b64_path = os.path.join(out, "all-nodes-sub.txt")
    body = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")
    with io.open(b64_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)

    # ③ CSV 清单（人读，不含密码）
    csv_path = os.path.join(out, "nodes.csv")
    with io.open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["机场", "节点名", "协议", "server",
                                          "port", "解析IP", "IP数", "可导出"])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    # ④ 摘要 JSON（机读）
    res["links"] = len(links)
    res["airports"] = sorted(per_airport, key=lambda x: -x["exported"])
    res["files"] = {
        "yaml": os.path.relpath(yaml_path, ROOT).replace("\\", "/"),
        "sub": os.path.relpath(b64_path, ROOT).replace("\\", "/"),
        "csv": os.path.relpath(csv_path, ROOT).replace("\\", "/"),
    }
    json_path = os.path.join(out, "summary.json")
    with io.open(json_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    res["files"]["summary"] = os.path.relpath(json_path, ROOT).replace("\\", "/")
    res["out_dir"] = os.path.relpath(out, ROOT).replace("\\", "/")

    # ⑤ 人读索引
    md = ["# %s 节点导出" % day, "",
          "生成于 %s · %d 家机场 · %d 个可导出节点 · %d 条跳过" % (
              stamp, len(per_airport), res["exported"], res["skipped"]), "",
          "## 怎么用", "",
          "- `all-nodes.yaml`：Clash / mihomo / Clash Verge 直接当配置导入（含「机场合集」选择组）",
          "- `all-nodes-sub.txt`：base64 订阅体，复制内容当订阅链接用（v2rayN / NekoBox / Shadowrocket）",
          "- `nodes.csv`：清单（机场 / 协议 / 地址 / 解析 IP），不含密码",
          "", "## 各家产出", "",
          "| 机场 | 可导出 | 跳过 | 快照 |", "|---|---|---|---|"]
    for a in res["airports"]:
        md.append("| %s | %d | %d | %s |" % (a["slug"], a["exported"], a["skipped"], a["snapshot"]))
    md += ["", "> ⚠ 本目录含节点密码/uuid，**不要**提交到任何公开仓库，也不要随意分享。"]
    md_path = os.path.join(out, "README.md")
    with io.open(md_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(md) + "\n")
    res["files"]["readme"] = os.path.relpath(md_path, ROOT).replace("\\", "/")
    return res


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="导出今天拿到的全部节点")
    p.add_argument("--day", default=None, help="YYYYMMDD，默认今天（本地时区）")
    p.add_argument("--out", default=None, help="输出目录，默认 exports/<日期>-<时分秒>/")
    p.add_argument("--only", default=None, help="只导这些机场（逗号分隔）")
    a = p.parse_args(argv)
    only = [x.strip() for x in a.only.split(",") if x.strip()] if a.only else None
    r = export_day(a.day, a.out, only)
    if not r.get("ok"):
        print("✗", r.get("error"))
        return 1
    print("✓ %s：%d 家 / %d 个可导出节点 / %d 条跳过" % (
        r["day"], len(r["airports"]), r["exported"], r["skipped"]))
    for k, v in r["files"].items():
        print("  %-8s %s" % (k, v))
    return 0


if __name__ == "__main__":
    sys.exit(main())
