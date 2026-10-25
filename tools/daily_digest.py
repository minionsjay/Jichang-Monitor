"""每日一条「机场状态日报」推到微信（走 airmon.notify）。

用户要的关键信息：
* 今天哪些机场异常（含原因）
* 一共拿到多少节点、多少能导出配置
* 节点分布（协议 / 地区）
* 有没有华为云命中

发送节奏：每 6 小时一轮，但**一天只发一条**
  - 夜间轮（22:00–02:59）第一次收尾时发当天日报；
  - 若超过 28 小时没发过（机器关过、夜间轮挂了），任何轮次都补发一条。

状态记在 data/daily_digest.json：{last_day, last_at}
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

DATA = os.path.join(ROOT, "data")
STATE = os.path.join(DATA, "daily_digest.json")
PANEL = os.path.join(ROOT, "docs", "09-新界面-preview", "app", "data.js")

GEO_CN = {"HK": "香港", "TW": "台湾", "US": "美国", "CN": "中国", "DE": "德国",
          "JP": "日本", "SG": "新加坡", "GB": "英国", "AE": "阿联酋", "CA": "加拿大",
          "AU": "澳大利亚", "KR": "韩国", "FR": "法国", "NL": "荷兰", "RU": "俄罗斯",
          "未知": "未解析"}
PROTO_CN = {"unknown": "未识别(碎片)"}


def _load_state() -> dict:
    try:
        with io.open(STATE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save_state(d: dict) -> None:
    try:
        os.makedirs(DATA, exist_ok=True)
        tmp = STATE + ".tmp"
        with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
        os.replace(tmp, STATE)
    except Exception:
        pass


def load_panel() -> dict:
    try:
        txt = io.open(PANEL, encoding="utf-8").read()
        m = re.search(r"window\.AIRMON\s*=\s*(\{.*\});?\s*$", txt, re.S)
        if not m:
            return {}
        d = json.loads(m.group(1))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _short_reason(r: str) -> str:
    """把长原因压成一句能一眼看懂的话（微信一屏就那几行）。"""
    r = (r or "").replace("\n", " ").strip()
    if not r:
        return "无说明"
    # 套餐过期优先说
    if "过期" in r:
        m = re.search(r"(\d{4})-(\d{2})-(\d{2})", r)
        if m:
            return "套餐 %s-%s 过期" % (m.group(2).lstrip("0"), m.group(3).lstrip("0"))
        return "套餐已过期"
    if "已停用" in r:
        if "过期" in r:
            return "已停用 · 套餐过期"
        m = re.search(r"已停用[：:]\s*([^；;。]{0,10})", r)
        return "已停用 · " + m.group(1).strip() if m else "已停用"
    first = re.split(r"[；;。]", r)[0].strip()
    first = re.sub(r"^订阅(（[^）]*）)?", "", first)
    first = re.sub(r"^(manual-url 路线|server-fetch 路线)", "", first).strip()
    first = first.replace("HTTP ", "").replace(" 网关超时", " 超时")
    return first[:15]


def build(d: dict) -> tuple[str, str]:
    """把 panel 数据拼成（标题, 纯文本正文）—— 目标是「一屏看完、扫一眼知道该干什么」。"""
    t = d.get("totals") or {}
    ap = d.get("airports") or []
    day = time.strftime("%m-%d", time.localtime())
    hw = t.get("hw") or 0
    BAR = "━" * 18

    title = "机场日报 %s · %s家/%s节点%s" % (
        day, t.get("airports") or "?", t.get("nodes") or "?", (" / 华为%d" % hw) if hw else "")

    L = ["📊 机场日报 %s" % day, ""]
    L.append("🟢 可用 %-2s   🟡 异常 %-2s   🔴 断流 %s" % (
        t.get("ok") or 0, t.get("b") or 0, t.get("d") or 0))
    L.append("📦 节点 %s　可导出 %s" % (t.get("nodes") or 0, t.get("exported") or 0))
    extra = []
    if t.get("stale"):
        extra.append("陈旧 %s" % t.get("stale"))
    if t.get("expired"):
        extra.append("过期 %s" % t.get("expired"))
    if extra:
        L.append("⏱ " + "　".join(extra) + " 家")

    # 华为单独一行，最显眼
    if hw:
        L.append("☁️ ⚠ 华为云命中 %d 条 —— 去面板看" % hw)
    else:
        L.append("☁️ 华为云命中 0")

    # 需要处理：只列最关键，一家一行
    bad = [a for a in ap if a.get("state") in ("B", "D")]
    bad.sort(key=lambda x: (x.get("state") != "D", -(x.get("nodes") or 0)))
    if bad:
        L.append("")
        L.append(BAR)
        L.append("❗ 需要处理 %d 家" % len(bad))
        L.append("")
        for a in bad[:7]:
            nm = (a.get("name_cn") or a.get("slug") or "")[:10]
            dot = "🔴" if a.get("state") == "D" else "🟡"
            L.append("%s %s · %s" % (dot, nm, _short_reason(a.get("reason"))))
        if len(bad) > 7:
            L.append("　 …另有 %d 家" % (len(bad) - 7))

    # 协议 / 地区：各一行，Top5
    pr = [(str(k), int(v or 0)) for k, v in (d.get("protos") or []) if str(k) != "unknown"]
    pr.sort(key=lambda x: -x[1])
    _geo: dict = {}
    for k, v in (d.get("geos") or []):
        k = str(k)
        if k == "未知":
            continue
        nmk = GEO_CN.get(k, k)
        _geo[nmk] = _geo.get(nmk, 0) + int(v or 0)
    ge = sorted(_geo.items(), key=lambda x: -x[1])

    if pr or ge:
        L.append("")
        L.append(BAR)
        if pr:
            L.append("🔧 协议　" + " · ".join("%s %d" % (k, v) for k, v in pr[:5]))
        if ge:
            L.append("🌍 地区　" + " · ".join("%s %d" % (k, v) for k, v in ge[:5]))

    L.append("")
    L.append("🔗 http://127.0.0.1:57010")
    return title, "\n".join(L)


def should_send(now: float | None = None, force: bool = False) -> tuple[bool, str]:
    if force:
        return True, "force"
    st = _load_state()
    now = now or time.time()
    lt = time.localtime(now)
    today = time.strftime("%Y%m%d", lt)
    if st.get("last_day") == today:
        return False, "今天已发过（%s）" % st.get("last_at", "")
    last_at = float(st.get("last_at_ts") or 0)
    if last_at and (now - last_at) < 28 * 3600:
        return False, "距上次 %.1f 小时，未到 28 小时" % ((now - last_at) / 3600)
    hour = lt.tm_hour
    if hour in (22, 23, 0, 1, 2):
        return True, "夜间轮"
    if last_at and (now - last_at) >= 28 * 3600:
        return True, "超过 28 小时，补发"
    return False, "非夜间轮且无需补发（hour=%d）" % hour


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="每日机场状态日报推送")
    ap.add_argument("--force", action="store_true", help="忽略节奏判断，立刻发")
    ap.add_argument("--dry", action="store_true", help="只打印不发送")
    a = ap.parse_args(argv)

    ok, why = should_send(force=a.force)
    if not ok:
        print("[日报] 跳过：%s" % why)
        return 0

    d = load_panel()
    if not d:
        print("[日报] 读不到 data.js，跳过")
        return 1
    title, text = build(d)
    if a.dry:
        print("---- 标题 ----")
        print(title)
        print("---- 正文 ----")
        print(text)
        return 0

    from airmon.notify import send
    r = send(title, text)
    if r.get("ok"):
        _save_state({"last_day": time.strftime("%Y%m%d"), "last_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                     "last_at_ts": time.time(), "reason": why})
        print("[日报] 已发送（%s）" % why)
        return 0
    print("[日报] 发送失败：%s" % (r.get("reason") or r.get("results")))
    return 2


if __name__ == "__main__":
    sys.exit(main())
