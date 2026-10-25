"""把「今天」的机场状态与节点清单同步到 Git 仓库（每天一份，可追溯）。

安全边界（默认值，改之前请想清楚）：
* 默认只推 `docs/每日摘要/<日期>.md` 与 `docs/每日摘要/<日期>-nodes.csv`
  —— 含机场名、协议、地址、端口、解析 IP、归属，**不含**密码 / uuid / 订阅 token。
* 完整配置（all-nodes.yaml / base64 订阅体）里含凭据，**默认不推**；
  真想推必须显式 `--with-secrets`，并且仓库必须是私有。

用法：
    python -X utf8 tools/sync_daily.py                  # 生成 + 提交 + 推送（当前 remote）
    python -X utf8 tools/sync_daily.py --no-push        # 只生成、不提交
    python -X utf8 tools/sync_daily.py --day 20261024
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

DATA = os.path.join(ROOT, "data")
OUT = os.path.join(ROOT, "docs", "每日摘要")

LEAK = re.compile(r"(?i)(password|passwd|uuid|aead_key|auth_token|psk|token=)[^\s\"',;}]{6,}")


def _load(p):
    try:
        with io.open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _git(*args, check=False):
    r = subprocess.run(["git"] + list(args), cwd=ROOT, capture_output=True, timeout=180)
    out = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace").strip()
    if check and r.returncode != 0:
        raise RuntimeError("git %s → %s" % (" ".join(args), out[:400]))
    return r.returncode, out


def collect(day: str) -> dict:
    """汇总当天状态（全部来自本地文件，不联网）。"""
    import csv as _csv
    from airmon import nodeset  # noqa: F401  仅确保 import 路径正确

    res = {"day": day, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "airports": [], "nodes": [], "totals": {}}

    # ① 面板数据（状态/通道/套餐）
    dj = os.path.join(ROOT, "docs", "09-新界面-preview", "app", "data.js")
    panel = {}
    if os.path.isfile(dj):
        try:
            txt = io.open(dj, encoding="utf-8").read()
            m = re.search(r'window\.AIRMON\s*=\s*(\{.*\});?\s*$', txt, re.S)
            if m:
                panel = json.loads(m.group(1))
        except Exception:
            panel = {}
    for a in (panel.get("airports") or []):
        res["airports"].append({
            "机场": a.get("slug"), "名称": a.get("name") or "",
            "状态": a.get("state"), "通道": a.get("channel") or "",
            "节点": a.get("nodes"), "可导出": a.get("exported"),
            "套餐到期": a.get("expire") or "", "剩余天数": a.get("days"),
        })
    t = panel.get("totals") or {}
    res["totals"] = {"机场": t.get("airports"), "可用": t.get("ok"), "异常": t.get("b"),
                     "仅客户端": t.get("c"), "断流": t.get("d"),
                     "节点": t.get("nodes"), "可导出": t.get("exported"),
                     "华为命中": t.get("hw")}

    # ② 当天最新导出包里的 nodes.csv（只取 CSV，不要 yaml/sub）
    exp = os.path.join(ROOT, "exports")
    if os.path.isdir(exp):
        cands = [d for d in sorted(os.listdir(exp)) if d.startswith(day + "-")]
        for d in reversed(cands):
            csvp = os.path.join(exp, d, "nodes.csv")
            if os.path.isfile(csvp):
                with io.open(csvp, encoding="utf-8-sig", newline="") as f:
                    for row in _csv.DictReader(f):
                        res["nodes"].append(row)
                res["export_dir"] = "exports/" + d
                break
    res["node_rows"] = len(res["nodes"])
    return res


def render_md(res: dict, with_secrets: bool = False, has_zip: bool = False) -> str:
    d = res["day"]
    t = res["totals"]
    md = ["# %s 机场监控日报" % d, "",
          "生成于 %s（本地时区 Asia/Shanghai）" % res["generated_at"], "",
          "## 总览", "",
          "| 指标 | 值 |", "|---|---|",
          "| 机场总数 | %s |" % (t.get("机场") or "—"),
          "| 可用 / 异常 / 仅客户端 / 断流 | %s / %s / %s / %s |" % (
              t.get("可用") or "—", t.get("异常") or "—", t.get("仅客户端") or "—", t.get("断流") or "—"),
          "| 节点总数 | %s |" % (t.get("节点") or "—"),
          "| 可导出配置 | %s |" % (t.get("可导出") or "—"),
          "| 华为云命中 | %s |" % (t.get("华为命中") if t.get("华为命中") is not None else "—"),
          "", "## 各机场状态", "",
          "| 机场 | 名称 | 状态 | 获取通道 | 节点 | 可导出 | 套餐到期 | 剩余天数 |",
          "|---|---|---|---|---|---|---|---|"]
    for a in res["airports"]:
        md.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            a["机场"], a["名称"], a["状态"], a["通道"] or "—",
            a["节点"] if a["节点"] is not None else "—",
            a["可导出"] if a["可导出"] is not None else "—",
            a["套餐到期"] or "—", a["剩余天数"] if a["剩余天数"] is not None else "—"))
    if res["nodes"]:
        md += ["", "## 当天可导出节点（%d 条）" % res["node_rows"], "",
               "完整清单见 `%s-nodes.csv`（机场 / 节点名 / 协议 / 地址 / 端口 / 解析 IP）。" % d,
               "", "协议分布：", ""]
        cnt = {}
        for n in res["nodes"]:
            cnt[(n.get("协议") or "unknown")] = cnt.get((n.get("协议") or "unknown"), 0) + 1
        for k, v in sorted(cnt.items(), key=lambda x: -x[1]):
            md.append("- %s：%d" % (k, v))
        ipc = sum(1 for n in res["nodes"] if (n.get("解析IP") or "").strip())
        md.append("")
        md.append("- 已解析出 IP 的节点：%d / %d" % (ipc, res["node_rows"]))
    else:
        md += ["", "## 当天节点", "", "今天还没有导出包（在面板上点「导出今日节点」，或跑 `tools/export_today.py`）。"]
    md += ["", "## 说明", "",
           "- 数据源：`data/<机场>/<日期>-*.json` 快照 + `data/*.json` 派生文件；全程只读本地，不联网。",
           "- **本文件不含任何凭据**：没有节点密码、uuid、订阅 token。",
           "- 含凭据的完整配置（Clash yaml / base64 订阅体）留在本地 `exports/`，不随本文件同步。"
           + ("（本次例外：`--with-secrets` 已开启，见目录内 yaml。）" if with_secrets else "")]
    return "\n".join(md) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="每日机场状态同步到 Git")
    ap.add_argument("--day", default=None, help="YYYYMMDD，默认今天")
    ap.add_argument("--no-push", action="store_true", help="只生成文件，不 git add/commit/push")
    ap.add_argument("--with-secrets", action="store_true",
                    help="把含凭据的 yaml/订阅体也一起提交（仓库必须私有！）")
    ap.add_argument("--remote", default="origin", help="推到哪个 remote（默认 origin）")
    a = ap.parse_args(argv)

    day = a.day or time.strftime("%Y%m%d")
    res = collect(day)
    os.makedirs(OUT, exist_ok=True)
    has_zip = bool(res.get("export_dir"))

    md = render_md(res, a.with_secrets, has_zip)
    hits = LEAK.findall(md)
    if hits:
        print("✗ 摘要里检出疑似凭据 %d 处（%s），已中止" % (len(hits), hits[:3]))
        return 2

    md_path = os.path.join(OUT, "%s.md" % day)
    with io.open(md_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(md)
    print("✓ 摘要 %s" % os.path.relpath(md_path, ROOT))

    files = [md_path]
    if res["nodes"]:
        import csv as _csv
        cp = os.path.join(OUT, "%s-nodes.csv" % day)
        with io.open(cp, "w", encoding="utf-8-sig", newline="") as f:
            w = _csv.DictWriter(f, fieldnames=list(res["nodes"][0].keys()))
            w.writeheader()
            for r in res["nodes"]:
                w.writerow(r)
        files.append(cp)
        print("✓ 节点清单 %s（%d 行）" % (os.path.relpath(cp, ROOT), len(res["nodes"])))

    if a.with_secrets and has_zip:
        import shutil
        src = os.path.join(ROOT, res["export_dir"])
        dst = os.path.join(OUT, day)
        os.makedirs(dst, exist_ok=True)
        for fn in ("all-nodes.yaml", "all-nodes-sub.txt"):
            s = os.path.join(src, fn)
            if os.path.isfile(s):
                shutil.copy2(s, os.path.join(dst, fn))
                files.append(os.path.join(dst, fn))
        print("⚠ 已复制含凭据文件（确认仓库是私有）")

    if a.no_push:
        print("（--no-push：不提交）")
        return 0

    for f in files:
        _git("add", "-f", os.path.relpath(f, ROOT))
    rc, out = _git("diff", "--cached", "--name-only")
    if not out.strip():
        print("（没有变化，跳过提交）")
        return 0
    _git("commit", "-q", "-m", "日报 %s：机场状态与节点清单" % day)
    rc, out = _git("push", "-q", a.remote, "HEAD", check=False)
    if rc != 0:
        print("✗ push 失败：%s" % out[-400:])
        return 3
    print("✓ 已推送到 %s" % a.remote)
    return 0


if __name__ == "__main__":
    sys.exit(main())
