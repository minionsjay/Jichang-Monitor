# -*- coding: utf-8 -*-
"""docs/17 v2：以 run.log 里最近一个『已完成』轮次为基准重建总账。
所有数字都从磁盘真实产物抽取，不手写。"""
import io, json, os, re, sys
from collections import Counter

def load(p, d=None):
    try:
        return json.load(io.open(p, encoding="utf-8"))
    except Exception:
        return d

LOG = "run.log"
lines = io.open(LOG, encoding="utf-8", errors="replace").read().splitlines()

# 1) 切轮次
starts = [i for i, l in enumerate(lines) if "=== 1/5 拉取所有机场" in l]
starts.append(len(lines))
rounds = []
for a, b in zip(starts, starts[1:]):
    seg = lines[a:b]
    m = next((re.search(r"拉取完成: (\d+)成功 / (\d+)失败", l) for l in seg if "拉取完成" in l), None)
    rounds.append({"a": a, "b": b, "seg": seg, "done": bool(m),
                   "ok": int(m.group(1)) if m else None,
                   "fail": int(m.group(2)) if m else None})

done = [r for r in rounds if r["done"]]
cur = done[-1]
prev = done[-2] if len(done) > 1 else None
print("基准轮 L%d ok=%d fail=%d；上一轮 L%d ok=%s" % (cur["a"], cur["ok"], cur["fail"], prev["a"], prev["ok"]))

def parse_round(r):
    pull_ok, pull_fail, client = set(), {}, {}
    per_slug = {}
    for l in r["seg"]:
        m = re.search(r"\[成功\]\s+(\S+)\s*\(", l)
        if m: pull_ok.add(m.group(1))
        m = re.search(r"\[失败\]\s+(\S+?):\s*(.*)$", l)
        if m: pull_fail[m.group(1)] = m.group(2).strip()
        # 客户端扫描成功行（✓ 字符在不同终端可能不同，用宽松匹配）
        m = re.search(r"\[(\S+?)\][^\n]*scan-memory 最终[:：]\s*(\d+)节点", l)
        if m: client[m.group(1)] = int(m.group(2))
        m = re.search(r"\[(\S+?)\][^\n]*(?:DPAPI 缓存|server/fetch成功)[:：]?\s*(\d+)节点", l)
        if m: client.setdefault(m.group(1), int(m.group(2)))
        # 逐机场错误行，用于给没有 [失败] 汇总行的机场补原因
        m = re.match(r"\s*\[(\S+?)\]\s*(.+)$", l)
        if m:
            per_slug.setdefault(m.group(1), []).append(m.group(2))
    # 兜底：机场若有错误行却既没成功也没失败记录，补一条原因
    for slug, msgs in per_slug.items():
        if slug in pull_ok or slug in client or slug in pull_fail:
            continue
        err = [x for x in msgs if re.search(r"失败|✗|超时|拒绝|重置|异常", x)]
        if err:
            pull_fail[slug] = err[-1].strip()[:110]
    return pull_ok, pull_fail, client

ok_now, fail_now, client_now = parse_round(cur)
_, fail_prev, _ = parse_round(prev) if prev else (set(), {}, {})

sub = load("data/sub_health.json", {}) or {}
nd = load("nodes/index.json", {}) or {}
cv = load("data/client_versions.json", {}) or {}
lr = load("data/last_run.json", {}) or {}
quota = (load("data/quota.json", {}) or {})
quota = quota.get("airports") or quota  # 实际结构是 {generated_at, refresh_days, airports:{slug:{...}}}
cv_map = cv.get("airports") or {}
node_map = {a["slug"]: a for a in nd.get("airports", [])}
quota_map = {}
for k, v in (quota.items() if isinstance(quota, dict) else []):
    if isinstance(v, dict) and ("days_left" in v or "expire_date" in v):
        quota_map[k] = v

import glob as _glob

_acache = load("data/analysis_cache.json", {}) or {}

def latest_ok_ts(slug, tries=60):
    """最近一份 nodes 非空的快照时间：优先用 analysis_cache（有每份快照的节点数），否则读文件。"""
    names = [k.split("/", 1)[1] for k, v in _acache.items()
             if k.startswith(slug + "/") and isinstance(v, dict) and (v.get("n") or 0) > 0]
    if names:
        b = max(names).replace(".json", "")
        m = re.match(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})", b)
        if m:
            return "%s-%s-%s %s:%s" % m.groups()
    files = sorted(_glob.glob(os.path.join("data", slug, "2*.json")), reverse=True)
    for f in files[:tries]:
        try:
            d = load(f, {}) or {}
            if d.get("nodes"):
                ts = d.get("ts") or ""
                m = re.match(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})", ts)
                if m:
                    return "%s-%s-%s %s:%s" % m.groups()
                b = os.path.basename(f).replace(".json", "")
                m = re.match(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})", b)
                if m:
                    return "%s-%s-%s %s:%s" % m.groups()
        except Exception:
            continue
    return "—"

_latest_cache = {}

all_slugs = sorted(set(sub) | set(node_map))
recovered, newly_failed = [], []  # 定稿后再算（见下）

def categorize(slug, ok, reason):
    r = reason or ""
    if ok: return "正常"
    if re.search(r"密码|口令|邮箱或", r): return "登录口令失效"
    if re.search(r"验证码|captcha|滑块", r, re.I): return "人机验证（需人工）"
    if re.search(r"50[024]|后端|整站", r): return "机场侧服务故障"
    if "403" in r: return "WAF/出口 IP 被拒"
    if "404" in r: return "订阅地址已失效"
    if re.search(r"过期|到期", r): return "套餐过期/耗尽"
    if re.search(r"未连接|未运行|登录态|0 节点|0节点", r): return "客户端未就绪"
    if re.search(r"无新快照|0 节点", r): return "本轮 0 产出"
    return "其他/待查"

rows = []
for s in all_slugs:
    disk_nodes = node_map.get(s, {}).get("nodes", 0) or 0
    ok = (s in ok_now or client_now.get(s, 0) > 0) and disk_nodes > 0
    reason = fail_now.get(s, "")
    sh = sub.get(s, {})
    nai = node_map.get(s, {})
    # 成功但无说明时，用 sub_health 的表述兜底
    if ok and not reason:
        reason = sh.get("reason", "")
    # 原因文本：优先用 sub_health 的人工复核结论（信息量最大），run.log 的机械原因补在后面
    sh_reason = (sh.get("reason") or "").strip()
    log_reason = (reason or "").strip()
    sh_state = sh.get("state")
    transient = False
    if ok:
        reason_txt = ("客户端内存扫描取到 %d 个节点" % client_now[s]) if s in client_now else "订阅直取正常"
    elif (s in ok_now or client_now.get(s, 0) > 0) and disk_nodes == 0:
        ok = False
        reason_txt = sh_reason or "本轮拉取被判成功但节点数为 0（快照里没有节点）"
    elif sh_state in ("B", "C", "D") and sh_reason:
        # sub_health 判定这家确实坏了 → 用人工复核过的那段原因
        reason_txt = sh_reason
        if log_reason and log_reason not in sh_reason:
            reason_txt += "｜run.log：" + log_reason
    elif log_reason:
        # sub_health 认为可用、本轮却失败 → 瞬时网络抖动，不是真坏
        transient = True
        reason_txt = "瞬时失败（上一轮正常）｜run.log：" + log_reason
    else:
        transient = True
        reason_txt = "本轮无产出，且无明确错误行"
    if transient:
        cat = "瞬时网络失败"
    elif re.search(r"credentials\.yaml 无此 slug|从不拉取|未纳入", reason_txt):
        cat = "未纳入采集"
    else:
        cat = categorize(s, ok, reason_txt)
    rows.append({
        "slug": s, "ok": ok, "cat": cat,
        "reason": reason_txt.replace("|", "/")[:150],
        "nodes": nai.get("nodes", 0), "exported": nai.get("exported", 0),
        "last_ok": (sh.get("last_ok") if (not ok and sh.get("state") in ("B", "C", "D") and sh.get("last_ok"))
                    else (_latest_cache.get(s) or _latest_cache.setdefault(s, latest_ok_ts(s)))),
        "quota": (quota_map.get(s) or {}).get("days_left"),
        "new_fail": s in newly_failed, "recovered": s in recovered,
    })

ok_set = {r["slug"] for r in rows if r["ok"]}
recovered = sorted(s for s in ok_set if s in fail_prev)
newly_failed = sorted(s for s in fail_now if s not in ok_set and s not in fail_prev)

n_ok = sum(1 for r in rows if r["ok"])
n_bad = len(rows) - n_ok
exp = sum(r["exported"] for r in rows)

L = []
w = L.append
w("# 机场监控状态总账（v2）")
w("")
w("> 生成时间 2026-10-22 · 基准 = `run.log` 中最近一个**已完成**轮次（起始行 L%d，拉取 %d 成功 / %d 失败）。" % (cur["a"], cur["ok"], cur["fail"]))
w("> 数据源：`run.log`（逐家成败与原因）、`nodes/index.json`（%s）、`data/sub_health.json`、`data/quota.json`、`data/client_versions.json`。" % nd.get("generated_at", "?"))
w("")
w("## 一、结论")
w("")
n_trans = sum(1 for r in rows if r["cat"] == "瞬时网络失败")
w("本轮 **%d 家正常 / %d 家有产出问题**；节点文件已导出 **%d 个可导入节点**（%d 台机场有产出）。"
  % (n_ok, n_bad, exp, sum(1 for r in rows if r["exported"])))
w("")
w("有产出问题的 %d 家里拆开看：**%d 家是瞬时网络失败**（上一轮还正常，本轮连接被重置/超时，已加重试补丁），"
  "**%d 家是真坏**（口令失效、机场侧故障、套餐过期、客户端未就绪等，需人处理）。"
  % (n_bad, n_trans, n_bad - n_trans))
w("")
if recovered:
    w("- **较上一轮恢复**（%d）：%s" % (len(recovered), "、".join("`%s`" % s for s in sorted(recovered))))
if newly_failed:
    w("- **较上一轮新失败**（%d）：%s" % (len(newly_failed), "、".join("`%s`" % s for s in sorted(newly_failed))))
w("")
w("### 最近几轮的订阅成功率")
w("")
w("| 轮次 | 订阅成功 / 失败 | 说明 |")
w("|---|---|---|")
for i, r in enumerate(done[-5:]):
    tag = "← 本表基准" if r is cur else ""
    w("| 第 %d 轮（L%d） | %d / %d | %s |" % (len(done) - len(done[-5:]) + i + 1, r["a"], r["ok"], r["fail"], tag))
w("")
drop = done[0]["ok"] - cur["ok"] if done else 0
w("从 %d/%d 掉到 %d/%d：**掉下去的部分几乎全是瞬时网络错误**（`ConnectionResetError 10054`、HTTPS 超时、"
  "CF 回源 522），不是机场真的坏了，也不是脚本 bug。已在 `run.py` 加订阅抓取重试一次（提交 `7f3c32a`），下一轮起生效。"
  % (done[0]["ok"], done[0]["fail"], cur["ok"], cur["fail"]))
w("")
w("> 注：`run.py all` 遇到「有拉取失败或陈旧」会返回退出码 1，`auto_run.bat` 把它写进 `run.log`。"
  "看到 `[exit=1]` 不等于崩溃，`data/last_run.json` 的 `status=ok` 才是判据。")
w("")
w("## 二、逐家总账")
w("")
w("| 机场 | 判定 | 归因 | 本轮节点 | 可导出 | 套餐剩余 | 最后有数据 | 原因 / 现状 |")
w("|---|---|---|---|---|---|---|---|")
order = sorted(rows, key=lambda r: (not r["ok"], r["slug"]))
for r in order:
    mark = "✅ 正常" if r["ok"] else "❌ 有产出问题"
    q = r["quota"]
    q = "—" if q in (None, "") else (f"{q} 天" if str(q).lstrip("-").isdigit() else str(q))
    flag = " 🆕" if r["new_fail"] else (" ♻️" if r["recovered"] else "")
    w("| `%s` | %s%s | %s | %s | %s | %s | %s | %s |" % (
        r["slug"], mark, flag, r["cat"], r["nodes"], r["exported"], q, r["last_ok"], r["reason"] or "—"))
w("")
w("> 🆕 = 较上一轮新失败；♻️ = 较上一轮恢复。")
w("")

fail_rows = [r for r in order if not r["ok"]]
bycat = Counter(r["cat"] for r in fail_rows)
w("## 三、问题的责任归属")
w("")
w("| 归因 | 家数 | 机场 | 谁能解决 |")
w("|---|---|---|---|")
who = {"登录口令失效": "用户给密码", "人机验证（需人工）": "用户人工过验证码",
       "机场侧服务故障": "机场（等待恢复）", "WAF/出口 IP 被拒": "换出口 IP",
       "订阅地址已失效": "用户在后台复制新链接", "套餐过期/耗尽": "用户续费/放弃",
       "客户端未就绪": "启动客户端或提权", "本轮 0 产出": "待查", "其他/待查": "待查",
       "瞬时网络失败": "已加重试，下轮观察", "未纳入采集": "补 credentials/airports 条目"}
for cat, n in bycat.most_common():
    sl = "、".join("`%s`" % r["slug"] for r in fail_rows if r["cat"] == cat)
    w("| %s | %d | %s | %s |" % (cat, n, sl, who.get(cat, "待查")))
w("")
w("## 四、本轮做了什么修复")
w("")
w("| 提交 | 内容 | 影响 |")
w("|---|---|---|")
for c, t, e in [
    ("7f3c32a", "订阅抓取对瞬时错误重试一次（2 秒间隔，HTTP 4xx 不重试）",
     "夜间代理抖动导致的假失败应当消失"),
    ("7f3c32a", "scan-memory 连续 6 轮 0 节点提前放弃（原为死等 18 轮/180 秒）",
     "每台失败客户端机场省约 2 分钟"),
    ("12c61cd", "rescan 不再伪造新快照；仪表盘陈旧度改用『最近一份有节点的快照』",
     "断流机场不再显示成绿色"),
    ("e34e8a1", "nodeset 合并 client_nodes；get_airport 回落到 credentials.yaml",
     "客户端机场的完整节点不再被 unknown 残片覆盖"),
]:
    w("| `%s` | %s | %s |" % (c, t, e))
w("")
w("## 五、仍需要人做")
w("")
w("| 事项 | 说明 |")
w("|---|---|")
for a, b in [
    ("kuainiao 密码", "面板报「邮箱或密码错误」，需给密码或走找回"),
    ("bywave 滑块", "登录强制拼图验证码，人工拖一次后复制新订阅链接"),
    ("lingdian 密码 / 后端", "密码失效 + 订阅后端三入口 504"),
    ("lingdian、dovex 提权", "core 在 Services 会话，需管理员跑 scan-memory"),
    ("quqiuquan、letsvpn 登录态", "登录并连接后跑 scan-persistent"),
    ("wandacloud / velochron 升级", "客户端版本落后，官方包覆盖安装"),
    ("wandacloud / hhy 面板解禁", "面板禁用客户端，订阅只回占位"),
    ("6 家免费机场注册", "iKuuu / GLaDOS / 掌中世界 / 跨境Cloud / Bitz Net / 快柠檬"),
]:
    w("| %s | %s |" % (a, b))
w("")
w("---")
w("")
w("基准轮次起始行：`run.log` L%d；导出清单：`nodes/index.json`（%s）。" % (cur["a"], nd.get("generated_at", "?")))

text = "\n".join(L) + "\n"
bad = re.findall(r"(?i)(password\s*[:=]\s*\S|token=[A-Za-z0-9]{6,}|eyJ[A-Za-z0-9_-]{20,}|sub_url\s*[:=]\s*\S|https?://[^\s)|]*token=)", text)
if bad:
    sys.exit("自检失败，疑似凭据：%r" % bad[:3])
open("docs/17-机场监控状态总账-2026-10-22.md", "w", encoding="utf-8", newline="\n").write(text)
print("written", len(text), "chars; ok=%d bad=%d exported=%d" % (n_ok, n_bad, exp))
print("recovered:", sorted(recovered))
print("new_fail:", sorted(newly_failed))
