# -*- coding: utf-8 -*-
"""每轮监控 → 在「机场可用性清单」工作簿里新建一张以时间命名的快照表。

设计：
  * 「机场清单」保持基础信息（A-R 18 列）不动，只作为台账；
  * 每跑一次，新建一张名为「YYYY-MM-DD HH-MM」的表，内含基础信息要点 + 本轮监控状态，
    不再往同一张表上右边加列；
  * 「总览」只留一张，作为历史索引，每次追加一行（时间/家数/节点数）。

数据源：run.log 最近一个已完成轮次、nodes/index.json、data/sub_health.json、data/last_run.json
用法：python -X utf8 tools/update_airport_xlsx.py [--label "2026-10-22 10-28"]
"""
import io
import json
import re
import sys
from collections import Counter

import openpyxl
from openpyxl.styles import Alignment, Font, PatternFill

XLSX = "docs/机场可用性清单-2026-10-17.xlsx"
LOG = "run.log"
BASE_COLS = 18  # 机场清单 A-R 为基础信息，不再加宽

GREEN = PatternFill("solid", fgColor="C6EFCE")
YELLOW = PatternFill("solid", fgColor="FFEB9C")
RED = PatternFill("solid", fgColor="FFC7CE")
GREY = PatternFill("solid", fgColor="E7E6E6")
BOLD = Font(bold=True)


def load(p, d=None):
    try:
        return json.load(io.open(p, encoding="utf-8"))
    except Exception:
        return d


# ---------- 1) run.log 里最近一个已完成轮次 ----------
lines = io.open(LOG, encoding="utf-8", errors="replace").read().splitlines()
starts = [i for i, l in enumerate(lines) if "=== 1/5 拉取所有机场" in l]
starts.append(len(lines))
rounds = []
for a, b in zip(starts, starts[1:]):
    seg = lines[a:b]
    m = next((re.search(r"拉取完成: (\d+)成功 / (\d+)失败", l) for l in seg if "拉取完成" in l), None)
    rounds.append({"seg": seg, "done": bool(m),
                   "ok": int(m.group(1)) if m else None,
                   "fail": int(m.group(2)) if m else None})
done = [r for r in rounds if r["done"]]
if not done:
    print("run.log 里没有已完成的轮次", file=sys.stderr)
    sys.exit(1)
cur = done[-1]

pull_ok, pull_fail, client = set(), {}, {}
for l in cur["seg"]:
    m = re.search(r"\[成功\]\s+(\S+)\s*\(", l)
    if m:
        pull_ok.add(m.group(1))
    m = re.search(r"\[失败\]\s+(\S+?):\s*(.*)$", l)
    if m:
        pull_fail[m.group(1)] = m.group(2).strip()
    m = re.search(r"\[(\S+?)\][^\n]*scan-memory 最终[:：]\s*(\d+)节点", l)
    if m:
        client[m.group(1)] = int(m.group(2))

# ---------- 2) 磁盘产物 ----------
nd = load("nodes/index.json", {}) or {}
node_map = {a["slug"]: a for a in nd.get("airports", [])}
sh = load("data/sub_health.json", {}) or {}
lr = load("data/last_run.json", {}) or {}

# ---------- 3) 人工动作表 ----------
ACTION = {
    "kuainiao": "给新密码（面板报“邮箱或密码错误”）",
    "bywave": "手动拖滑块登录后台，把订阅地址发我",
    "ss-id": "后台重新复制订阅地址发我（403）",
    "qingyunti": "浏览器登录后复制订阅地址发我（面板 403）",
    "xm999": "等机场修（522）或换新域名后给订阅地址",
    "muniu-ninja": "无独立订阅，跟 muniu 一起处理",
    "dovex": "启动 dove-core 客户端并登录",
    "letsvpn": "启动 LetsPRO 保持登录+连接",
    "quqiuquan": "启动 QQT 并登录连接",
    "lingdian": "机场侧 504 整站故障，等修",
    "jsqpro": "过期 22 天：续费或下线",
    "muniu": "过期 97 天：续费或下线",
    "oixcloud": "过期 36 天：续费或下线",
    "qiangda": "过期 26 天：续费或下线",
    "yiyuan": "过期 366 天+流量用尽：建议下线",
    "wandacloud": "客户端 2.2.792 → 3.2.0",
    "velochron": "客户端 1.2.5.3 → 1.3.3.0",
    "hhy": "套餐到期+面板禁客户端：续费",
}

# ---------- 4) 本轮时间标签 ----------
lr_end = (lr.get("ended_at") or "")[:16].replace("T", " ")
run_label = None
for i, a in enumerate(sys.argv):
    if a == "--label" and i + 1 < len(sys.argv):
        run_label = sys.argv[i + 1]
if not run_label:
    # 优先用本轮结束时间（last_run.json 存的是 UTC，+8 转本地）；拿不到再用系统时间
    import datetime
    try:
        t = datetime.datetime.strptime(lr["ended_at"][:19], "%Y-%m-%dT%H:%M:%S")
        run_label = (t + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H-%M")
    except Exception:
        run_label = datetime.datetime.now().strftime("%Y-%m-%d %H-%M")

wb = openpyxl.load_workbook(XLSX)
base = wb["机场清单"]

# 上一版曾往右侧加过 S-W 列，这里退回到 18 列
if base.max_column > BASE_COLS:
    base.delete_cols(BASE_COLS + 1, base.max_column - BASE_COLS)
    print("已移除机场清单里的追加列，恢复 %d 列基础信息" % BASE_COLS)

# ---------- 5) 组装本轮数据 ----------
rows = []
for r in range(2, base.max_row + 1):
    slug = base.cell(row=r, column=1).value
    if not slug:
        continue
    slug = str(slug).strip()
    nai = node_map.get(slug, {})
    disk_nodes = nai.get("nodes", 0) or 0
    exported = nai.get("exported", 0) or 0
    s = sh.get(slug, {})
    state = s.get("state")
    ok = (slug in pull_ok or client.get(slug, 0) > 0) and disk_nodes > 0
    if ok:
        status, fill = "✅ 正常", GREEN
    elif state == "A":
        status, fill = "⏳ 抖动", YELLOW
    else:
        status, fill = "❌ 异常", RED
    reason = (s.get("reason") or pull_fail.get(slug, "") or "").strip()
    if ok:
        reason = "—"
    elif status.startswith("⏳"):
        reason = "订阅成功但本轮没产出节点（瞬时抖动），下轮自动重试"
    action = ACTION.get(slug) or ("—" if (ok or state == "A") else "待排查")
    rows.append({
        "slug": slug,
        "base_status": base.cell(row=r, column=2).value,
        "panel": base.cell(row=r, column=11).value,
        "way": base.cell(row=r, column=13).value,
        "client": base.cell(row=r, column=14).value,
        "expire": base.cell(row=r, column=15).value,
        "status": status, "fill": fill,
        "nodes": disk_nodes, "exported": exported,
        "reason": reason[:150] or "—", "action": action,
    })

n_ok = sum(1 for x in rows if x["status"].startswith("✅"))
n_flap = sum(1 for x in rows if x["status"].startswith("⏳"))
n_bad = sum(1 for x in rows if x["status"].startswith("❌"))
tot_nodes = sum(x["nodes"] for x in rows)
tot_exp = sum(x["exported"] for x in rows)

# ---------- 6) 新建本轮快照表 ----------
sheet_name = run_label[:31]
if sheet_name in wb.sheetnames:
    del wb[sheet_name]
ws = wb.create_sheet(sheet_name, 1)  # 放在总览之后、机场清单之前

heads = ["机场", "基础状态", "面板域名", "获取方式", "客户端版本", "套餐到期",
         "本轮状态", "快照节点", "可导出节点", "卡在哪", "需要你做什么"]
for i, h in enumerate(heads, start=1):
    c = ws.cell(row=1, column=i, value=h)
    c.font = BOLD
    c.alignment = Alignment(horizontal="center", vertical="center")

for idx, x in enumerate(rows):
    r = 2 + idx
    vals = [x["slug"], x["base_status"], x["panel"], x["way"], x["client"], x["expire"],
            x["status"], x["nodes"], x["exported"], x["reason"], x["action"]]
    for i, v in enumerate(vals, start=1):
        ws.cell(row=r, column=i, value=v)
    c = ws.cell(row=r, column=7)
    c.fill = x["fill"]
    c.alignment = Alignment(horizontal="center")
    if x["exported"] == 0:
        ws.cell(row=r, column=9).fill = GREY
    ws.cell(row=r, column=10).alignment = Alignment(wrap_text=True, vertical="top")
    ws.cell(row=r, column=11).alignment = Alignment(wrap_text=True, vertical="top")

for col, w in {"A": 16, "B": 9, "C": 26, "D": 20, "E": 18, "F": 13,
               "G": 10, "H": 9, "I": 11, "J": 46, "K": 34}.items():
    ws.column_dimensions[col].width = w
ws.freeze_panes = "A2"
ws.auto_filter.ref = "A1:K%d" % (len(rows) + 1)

# 表头下方写一行口径说明
note_r = len(rows) + 3
ws.cell(row=note_r, column=1,
        value="说明：快照节点=本轮抓到的全部条目（含只有 IP:端口 的残片）；可导出节点=能生成 Clash/订阅配置的条数。灰底=0 条。").font = Font(italic=True, size=9)

# ---------- 7) 总览：干净的历史索引（每次重建，旧记录保留） ----------
hist_old = []
if "总览" in wb.sheetnames:
    old = wb["总览"]
    for r in range(1, old.max_row + 1):
        v = old.cell(row=r, column=1).value
        if isinstance(v, str) and re.match(r"^\d{4}-\d{2}-\d{2} \d{2}-\d{2}$", v.strip()):
            hist_old.append([old.cell(row=r, column=c).value for c in range(1, 10)])
    del wb["总览"]

ov = wb.create_sheet("总览", 0)
ov["A1"] = "机场监控总览（每次运行追加一行）"
ov["A1"].font = Font(bold=True, size=14)
hist = ["时间", "机场数", "✅正常", "⏳抖动", "❌异常", "快照节点", "可导出", "订阅成功/失败", "耗时(秒)"]
for i, h in enumerate(hist, start=1):
    c = ov.cell(row=3, column=i, value=h)
    c.font = BOLD
    c.alignment = Alignment(horizontal="center")

rec = [run_label, len(rows), n_ok, n_flap, n_bad, tot_nodes, tot_exp,
       "%s/%s" % (lr.get("pull_ok"), lr.get("pull_fail")), lr.get("duration_s")]
allrec = [r for r in hist_old if r and r[0] != run_label] + [rec]
for i, r in enumerate(allrec, start=4):
    for j, v in enumerate(r, start=1):
        ov.cell(row=i, column=j, value=v)
    ov.cell(row=i, column=3).fill = GREEN
    ov.cell(row=i, column=4).fill = YELLOW
    ov.cell(row=i, column=5).fill = RED

for col, w in {"A": 20, "B": 9, "C": 9, "D": 9, "E": 9, "F": 11, "G": 9, "H": 14, "I": 10}.items():
    ov.column_dimensions[col].width = w

r0 = len(allrec) + 6
notes = [
    "怎么读：",
    "1. 每跑一次监控，工作簿里新增一张以「本轮结束时间」命名的表，基础信息+本轮状态都在里面。",
    "2. 「机场清单」只放基础信息（18 列），不再往右加列；本页是历次运行的一行摘要。",
    "3. 快照节点=本轮抓到的全部条目（含只有 IP:端口 的残片）；可导出节点=能生成 Clash/订阅配置的条数。",
    "4. 客户端型机场（fastlink/speedcat/dovex/letsvpn/quqiuquan/lingdian/ssrdog）的节点几小时就轮换，导出配置有保鲜期。",
    "5. 套餐过期后订阅仍可能出节点（qiangda 就是这样），但随时会断。",
]
for i, t in enumerate(notes):
    ov.cell(row=r0 + i, column=1, value=t)

wb.save(XLSX)
print("已新建快照表「%s」| %d 行 | 正常 %d / 抖动 %d / 异常 %d | 快照节点 %d 可导出 %d"
      % (sheet_name, len(rows), n_ok, n_flap, n_bad, tot_nodes, tot_exp))
print("sheets:", wb.sheetnames)
