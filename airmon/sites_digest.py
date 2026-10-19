# -*- coding: utf-8 -*-
"""sites_digest —— 推荐站文章档案重建器（data/sites_digest.json）

数据源：jichangtuijian1.com 全量爬取产物（jctj_rows.json，316 行 12 键）。
本模块把源数据重建成白名单脱敏 JSON 供面板 /api/data 透出：
  - 丢弃 subs 字段（公开订阅转储，实测 LEAP 行含 token，绝不进面板）
  - doms 清洗：只留域名形状的 token（woff2/尾类名/价格数字/常见无关域剔除）
  - 全部字段为文章公开信息，无任何账号/订阅机密

用法：
  python -m airmon.sites_digest [--src C:\\...\\jctj_rows.json] [--out data/sites_digest.json]
输出键：name/cat/title/path/date/prices/free/protos/nodes/dom0/doms/related
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tempfile
from pathlib import Path

# 与面板白名单一致的输出键（多一列都不行，负向自检会拦）
OUT_KEYS = ("name", "cat", "title", "path", "date", "prices",
            "free", "protos", "nodes", "dom0", "doms", "related")

# 域名形状：段=字母数字连字符（可含中文），TLD 纯字母 2-24
_DOM_RE = re.compile(
    r"^[a-zA-Z0-9\u4e00-\u9fa5][a-zA-Z0-9\u4e00-\u9fa5\-\.]*\.[a-zA-Z\u4e00-\u9fa5]{2,24}$")
# 明显无关域（搜索引擎/CDN/邮箱等出现在文章里的噪声）
_DOM_BLACK = {"126.com", "163.com", "gmail.com", "gitee.com", "github.com",
              "com.cn", "apple.com", "microsoft.com", "cloudflare.com",
              "npmjs.com", "youtube.com", "t.me"}


def _clean_doms(raw: str) -> list[str]:
    """从文章 doms 长串清洗出真域名（dedupe、≤10 个）。"""
    out: list[str] = []
    if not raw:
        return out
    for tok in re.split(r"[;,\s]+", str(raw)):
        t = tok.strip().strip("./")
        if not (4 <= len(t) <= 80) or t.count(".") < 1 or t.count(".") > 4:
            continue
        if not _DOM_RE.match(t):
            continue
        if t.lower() in _DOM_BLACK:
            continue
        if re.search(r"\.woff2?$|\.css$|\.js$", t, re.I):
            continue
        if re.fullmatch(r"[\d.\-]+", t):  # 价格/版本号
            continue
        if t not in out:
            out.append(t)
        if len(out) >= 10:
            break
    return out


def build(src: str | None = None, out: str | None = None) -> dict:
    src_path = Path(src) if src else Path(tempfile.gettempdir()) / "jctj_rows.json"
    out_path = Path(out) if out else Path(__file__).resolve().parent.parent / "data" / "sites_digest.json"
    if not src_path.exists():
        raise SystemExit(f"源文件不存在: {src_path}")
    rows = json.load(io.open(src_path, encoding="utf-8"))

    digest = []
    for r in rows:
        name = str(r.get("name") or "").strip()[:60]
        if not name:
            continue
        doms = _clean_doms(r.get("doms") or "")
        item = {
            "name": name,
            "cat": str(r.get("cat") or "").strip()[:20],
            "title": str(r.get("title") or "").strip()[:120],
            "path": str(r.get("path") or "").strip()[:80],
            "date": str(r.get("date") or "").strip()[:16],
            "prices": str(r.get("prices") or "").strip()[:160],
            "free": str(r.get("free") or "").strip()[:80],
            "protos": str(r.get("protos") or "").strip()[:80],
            "nodes": str(r.get("nodes") or "").strip()[:40],
            "dom0": doms[0] if doms else "",
            "doms": doms,
            "related": str(r.get("rel") or "未监控").strip()[:80],
        }
        digest.append(item)

    # 散装评测补录（推荐站根路径 slug，316 行全量爬取不含；字面量内置保证跨机重建一致）
    digest += [
        {"name": "云图小镇", "cat": "散装评测", "title": "云图小镇是什么？官网能开，但邀请码三条路全堵死",
         "path": "yuntuxiaozhen", "date": "2026-08-30", "prices": "", "free": "邀请码难求",
         "protos": "", "nodes": "", "dom0": "www.yuntu.eu.org",
         "doms": ["www.yuntu.eu.org", "mirrors.yuntu.eu.org", "image.yuntu.eu.org"], "related": "未监控"},
        {"name": "穿云箭", "cat": "散装评测", "title": "穿云箭跑路了吗?面板已关,同批机器换牌在卖",
         "path": "chuanyunjian", "date": "2026-08-26", "prices": "", "free": "",
         "protos": "", "nodes": "", "dom0": "chuanyunjian.com",
         "doms": ["chuanyunjian.com", "chuanyunjian.cc", "cyj.vp99.top", "cyj.1abc.one"], "related": "未监控（文章警示：面板已关）"},
        {"name": "扑克云", "cat": "散装评测", "title": "扑克云PokerCloud跑路了吗?官网已挂牌出售",
         "path": "pokercloud", "date": "2026-08-26", "prices": "", "free": "",
         "protos": "", "nodes": "", "dom0": "panel.pokeryun.top",
         "doms": ["panel.pokeryun.top", "pkcd.info", "candytally2.com"], "related": "未监控（文章警示：官网挂牌出售）"},
    ]

    # 负向自检：任何一行出现订阅机密形状即中止
    bad = re.compile(r"token=|eyJ|aead|password|sub_url")
    text = json.dumps(digest, ensure_ascii=False)
    hits = bad.findall(text)
    if hits:
        raise SystemExit(f"负向自检命中 {len(hits)} 处机密形状，中止写盘: {set(hits)}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(".json.tmp")
    with io.open(tmp, "w", encoding="utf-8") as f:
        json.dump(digest, f, ensure_ascii=False, indent=1)
    tmp.replace(out_path)
    return {"rows": len(digest), "out": str(out_path),
            "with_doms": sum(1 for d in digest if d["doms"]),
            "monitored": sum(1 for d in digest if d["related"].startswith("已监控"))}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="重建推荐站档案 data/sites_digest.json")
    ap.add_argument("--src", help="jctj_rows.json 路径（默认 %%TEMP%%/jctj_rows.json）")
    ap.add_argument("--out", help="输出路径（默认 data/sites_digest.json）")
    a = ap.parse_args(argv)
    r = build(a.src, a.out)
    print(f"档案 {r['rows']} 行 → {r['out']}（含域名 {r['with_doms']}，命中监控 {r['monitored']}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
