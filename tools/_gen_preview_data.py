# -*- coding: utf-8 -*-
"""生成界面预览用数据快照 docs/09-新界面-preview/data.js（脱敏：只出派生数值与状态词）"""
import io, json, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = lambda *p: os.path.join(ROOT, *p)
load = lambda p: json.load(io.open(p, encoding="utf-8"))

CN = {
    "hhy": "好好云", "hsyun": "火烧云", "wdy": "万达云", "wandacloud": "万达云",
    "muniu": "牧牛云", "muniu-ninja": "牧牛·Ninja", "yiyuan": "一元机场", "new-yiyuan": "一元机场",
    "jsqpro": "加速器Pro", "qiangda": "强大", "kuainiao": "快鸟", "qingyunti": "青云梯",
    "speedcat": "闪电猫", "ssrdog": "SS狗", "letsvpn": "LetsVPN", "velochron": "时轮",
    "quqiuquan": "球球圈", "feiniao": "飞鸟云", "feiniao_1": "飞鸟云1", "feiniao_2": "飞鸟云2",
    "mojie": "魔戒", "neko77": "猫七七", "bygcloud": "ByG云", "applegame": "苹果游戏",
    "ayucloud": "Ayu云", "chaoyue": "超越", "cherryvpn": "樱桃", "cloudnx": "CloudNX",
    "dovex": "Dovex", "dualnet": "DualNet", "everlife": "Everlife", "fastlink": "快链",
    "flyint": "FlyInt", "ktm": "KTM云", "liangxin": "良心云", "maxiong": "猫熊",
    "mitce": "Mitce", "no626": "No626", "oixcloud": "OIX云", "pkq": "PKQ",
    "selom": "Selom", "xm999": "XM999", "ss-id": "SS-ID", "dtm": "DTM",
    "jinglingxueyuan": "精灵学院",
}

ni = load(D("nodes", "index.json"))
sh = load(D("data", "sub_health.json"))
qu = load(D("data", "quota.json")).get("airports", {})
an = load(D("data", "analysis.json"))
lr = load(D("data", "last_run.json"))

expired = [x for x in (an.get("expiry") or []) if isinstance(x.get("days_left"), (int, float)) and x["days_left"] < 0]
expiring30 = [x for x in (an.get("expiry") or []) if isinstance(x.get("days_left"), (int, float)) and 0 <= x["days_left"] <= 30]

def via_of(reason):
    r = reason or ""
    if "内存" in r or "客户端" in r: return "客户端内存"
    if "本地" in r or "profile" in r.lower(): return "本地配置"
    if "订阅" in r: return "订阅直取"
    if "API" in r: return "客户端API"
    return "—"

airports = []
for a in ni["airports"]:
    slug = a["slug"]
    h = sh.get(slug) or {}
    q = qu.get(slug) or {}
    airports.append({
        "slug": slug,
        "name": CN.get(slug, slug),
        "state": h.get("state") or "?",
        "nodes": a.get("nodes", 0),
        "exported": a.get("exported", 0),
        "via": via_of(h.get("reason")),
        "days": q.get("days_left") if isinstance(q.get("days_left"), (int, float)) else None,
        "expire": q.get("expire_date"),
        "reason": h.get("reason") or "",
        "action": h.get("action") or "",
    })
airports.sort(key=lambda x: ({"D": 0, "B": 1, "C": 2, "A": 3}.get(x["state"], 4), -x["nodes"]))

states = {}
for a in airports:
    states[a["state"]] = states.get(a["state"], 0) + 1

ts = an.get("timeseries") or {}
tot = ni.get("totals") or {}

data = {
    "meta": {
        "generated": an.get("base_local") or "",
        "days": an.get("days") or 30,
        "run_status": lr.get("status"),
        "run_step": lr.get("step"),
        "run_started": (lr.get("started_at") or "").replace("T", " ").replace("Z", " UTC"),
    },
    "kpis": {
        "airports": len(airports),
        "ok": states.get("A", 0),
        "subfail": states.get("B", 0),
        "clientonly": states.get("C", 0),
        "down": states.get("D", 0),
        "nodes": tot.get("nodes", 0),
        "exported": tot.get("exported", 0),
        "airports_with_nodes": tot.get("airports_ok", 0),
        "expired": len(expired),
        "expiring30": len(expiring30),
        "churn_top": (an.get("churn") or [{}])[0].get("churn", 0),
    },
    "airports": airports,
    "protos": (an.get("proto_global") or [])[:9],
    "geos": (an.get("geo_global") or [])[:7],
    "timeseries": {"dates": ts.get("dates") or [], "totals": ts.get("totals") or []},
    "expiry": [
        {"slug": x["slug"], "name": CN.get(x["slug"], x["slug"]), "days": x["days_left"]}
        for x in (an.get("expiry") or []) if isinstance(x.get("days_left"), (int, float)) and x["days_left"] <= 60
    ],
    "zero": [
        {"slug": x["slug"], "name": CN.get(x["slug"], x["slug"]), "n": x["zero_n"]}
        for x in (an.get("zero_rank") or [])[:5]
    ],
    "churn": [
        {"slug": x["slug"], "name": CN.get(x["slug"], x["slug"]), "n": x["churn"]}
        for x in (an.get("churn") or [])[:5]
    ],
    "stability": [
        {"slug": x["slug"], "name": CN.get(x["slug"], x["slug"]), "pct": x["pct"], "days": x["days"]}
        for x in (an.get("stability") or [])[:6]
    ],
}

out = D("docs", "09-新界面-preview", "data.js")
with io.open(out, "w", encoding="utf-8") as f:
    f.write("window.DATA = ")
    f.write(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
    f.write(";\n")

# 脱敏自检：预览数据不得出现链接/凭据/邮箱
txt = io.open(out, encoding="utf-8").read()
bad = re.findall(r"(password|aead_key|auth_token|sub_url|https?://|[\w.+-]+@[\w-]+\.[A-Za-z]{2,}|eyJ[A-Za-z0-9_-]{10,})", txt, re.I)
print("写出 %s (%d 字节) | 机场 %d | 状态 %s | 泄漏命中 %d" % (out, len(txt.encode()), len(airports), states, len(bad)))
print("样例:", json.dumps(airports[:3], ensure_ascii=False))
