"""把告警推到 IM（微信 / 企业微信 / 任意 webhook）。

为什么不做「微信个人号」：微信没有给个人号开放发消息接口，第三方用
Web 协议登录实现（itchat/wechaty 之类）违反用户协议、随时封号，不做。

实际可用的四种通道，任选其一填进 notify.yaml 就能收到微信通知：
1. wecom      企业微信群机器人（**推荐**：免费、稳定、消息直接进微信「企业微信」应用）
2. serverchan Server酱（微信扫码绑定，个人免费额度每天 5 条）
3. pushplus   PushPlus（微信扫码，免费额度更宽）
4. webhook    自定义（Bark / 飞书 / 钉钉 / n8n 都行，POST JSON）
5. dshim      复用你已经接进 DSH-IM 的机器人（微信/企微/飞书…），走它的主动投递接口
              POST /api/dsh-im/delivery/messages {"botId","targetId","text","format"}
              配置：type: dshim / bot_id: bot_xxx / target_id: airmon-alerts

配置在项目根 notify.yaml（已在 .gitignore，含 token 绝不入库）：
参考 notify.example.yaml。

失败**绝不**影响主流程：所有异常都吞掉并只打印一行。
"""
from __future__ import annotations

import io
import json
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "notify.yaml")
TIMEOUT = 8.0
MAX_BYTES = 3800  # 企业微信 markdown 上限 4096 字节，留余量


def load() -> dict:
    """读配置；不存在或关掉就返回 {enabled: False}。"""
    if not os.path.isfile(CONFIG):
        return {"enabled": False, "channels": [], "reason": "没有 notify.yaml"}
    try:
        import yaml
        with io.open(CONFIG, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except Exception as e:
        return {"enabled": False, "channels": [], "reason": "notify.yaml 解析失败：%s" % e}
    if not isinstance(cfg, dict):
        return {"enabled": False, "channels": [], "reason": "notify.yaml 不是字典"}
    chans = []
    for c in (cfg.get("channels") or []):
        if not isinstance(c, dict):
            continue
        t = str(c.get("type") or "").strip().lower()
        u = str(c.get("url") or "").strip()
        tok = str(c.get("token") or "").strip()
        if not t:
            continue
        if t in ("serverchan", "pushplus") and not (u or tok):
            continue
        if t == "dshim" and not (str(c.get("bot_id") or "").strip() and
                                 str(c.get("target_id") or "").strip()):
            continue
        if t in ("wecom", "webhook") and not u:
            continue
        chans.append({"type": t, "url": u, "token": tok,
                      "bot_id": str(c.get("bot_id") or "").strip(),
                      "target_id": str(c.get("target_id") or "").strip(),
                      "name": str(c.get("name") or t)})
    return {
        "enabled": bool(cfg.get("enabled", True)) and bool(chans),
        "channels": chans,
        "on_huawei": bool(cfg.get("huawei", True)),
        "on_fronting": bool(cfg.get("fronting", False)),
        "on_run_fail": bool(cfg.get("run_fail", False)),
        "reason": "" if chans else "notify.yaml 里没有可用的 channels",
    }


def _post(url: str, payload: dict) -> tuple[bool, str]:
    import requests
    from .netcfg import proxy_dict
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json; charset=utf-8",
               "User-Agent": "airmon-notify/1.0"}
    # 国内 IM 端点通常直连就行；代理可用时也允许走（企业微信必须直连）
    proxies = None if "qq.com" in url else proxy_dict()
    try:
        r = requests.post(url, data=body, headers=headers,
                          timeout=TIMEOUT, proxies=proxies)
        txt = (r.text or "")[:200].replace("\n", " ")
        ok = r.status_code == 200
        if ok:
            try:
                j = r.json()
                if isinstance(j, dict) and j.get("errcode") not in (None, 0):
                    ok = False
            except Exception:
                pass
        return ok, "%s %s" % (r.status_code, txt)
    except Exception as e:
        return False, "%s: %s" % (type(e).__name__, e)


_DSH_PORTS = (13080, 3080, 61405, 19387, 5678)
_dsh_cache: dict = {}


def _dshim_url() -> str:
    """自动找在跑的 DSH Web 端口（逐个探 /api/dsh-im/delivery/messages）。"""
    if _dsh_cache.get("url"):
        return _dsh_cache["url"]
    import socket
    for port in _DSH_PORTS:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.35):
                _dsh_cache["url"] = "http://127.0.0.1:%d/api/dsh-im/delivery/messages" % port
                return _dsh_cache["url"]
        except Exception:
            continue
    return "http://127.0.0.1:13080/api/dsh-im/delivery/messages"


def _to_plain(md: str) -> str:
    """markdown → 纯文本（微信/QQ 这类不渲染 md 的渠道）。"""
    import re as _re
    t = md.replace("\r\n", "\n")
    t = _re.sub(r"^#{1,6}\s*", "", t, flags=_re.M)          # 标题
    t = _re.sub(r"\*\*([^*]+)\*\*", r"\1", t)              # 粗体
    t = _re.sub(r"`([^`]+)`", r"\1", t)                     # 行内代码
    t = _re.sub(r"^\s*[-*]\s+", "· ", t, flags=_re.M)       # 列表
    t = _re.sub(r"^>\s?", "", t, flags=_re.M)               # 引用
    t = _re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


def _trim(md: str) -> str:
    b = md.encode("utf-8")
    if len(b) <= MAX_BYTES:
        return md
    return b[:MAX_BYTES].decode("utf-8", "ignore") + "\n…(截断)"


def _send_one(ch: dict, title: str, md: str) -> dict:
    t = ch["type"]
    md = _trim(md)
    if t == "wecom":
        ok, info = _post(ch["url"], {"msgtype": "markdown",
                                     "markdown": {"content": md}})
    elif t == "serverchan":
        url = ch["url"] or ("https://sctapi.ftqq.com/%s.send" % ch["token"])
        ok, info = _post(url, {"title": title[:32], "desp": md})
    elif t == "pushplus":
        url = ch["url"] or "https://www.pushplus.plus/send"
        ok, info = _post(url, {"token": ch["token"] or ch["url"],
                               "title": title[:100], "content": md,
                               "template": "markdown"})
    elif t == "dshim":
        # DSH-IM 主动投递：复用用户已接入的微信/企微/飞书等机器人。
        # 微信渠道不渲染 markdown，这里转纯文本，免得满屏 ** 和 #
        url = ch["url"] or _dshim_url()
        ok, info = _post(url, {"botId": ch.get("bot_id"), "targetId": ch.get("target_id"),
                               "text": _to_plain(md), "format": "plain"})
    else:  # webhook 自定义
        ok, info = _post(ch["url"], {"title": title, "text": md, "md": md})
    return {"channel": ch.get("name") or t, "ok": ok, "info": info}


def send(title: str, md: str) -> dict:
    """按 notify.yaml 逐个渠道发；没配就静默返回。"""
    cfg = load()
    if not cfg.get("enabled"):
        return {"ok": False, "skipped": True, "reason": cfg.get("reason") or "未启用"}
    results = [_send_one(c, title, md) for c in cfg["channels"]]
    okn = sum(1 for r in results if r["ok"])
    for r in results:
        print("[推送] %-10s %s %s" % (r["channel"], "✓" if r["ok"] else "✗", r["info"]))
    return {"ok": okn > 0, "sent": okn, "total": len(results), "results": results}


def huawei_message(airport: str, findings: list) -> tuple[str, str]:
    """把华为命中拼成标题 + markdown 正文。"""
    n = len(findings)
    title = "⚠ 华为云命中 %d 条 · %s" % (n, airport)
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    lines = ["## 华为云关联命中", "",
             "**机场**：%s" % airport,
             "**时间**：%s" % ts,
             "**条数**：%d" % n, ""]
    for f in findings[:12]:
        dim = getattr(f, "dimension", "")
        rule = getattr(f, "rule", "")
        ev = getattr(f, "evidence", "")
        ctx = getattr(f, "context", "")
        conf = getattr(f, "confidence", "")
        lines.append("- `%s` 规则 **%s**（%s）" % (dim, rule, conf))
        if ev:
            lines.append("  - 证据：`%s`" % str(ev)[:120])
        if ctx:
            lines.append("  - 位置：%s" % str(ctx)[:120])
    if n > 12:
        lines.append("- …另有 %d 条" % (n - 12))
    lines += ["", "> 面板：http://127.0.0.1:57010/index.html#hw"]
    return title, "\n".join(lines)


def notify_findings(airport: str, findings: list) -> dict | None:
    """供 alert.emit 调用：只推华为命中（大厂域前置默认不推，可在 notify.yaml 开）。"""
    try:
        cfg = load()
        if not cfg.get("enabled"):
            return None
        from .detect import HW_DIMS
        hw = [f for f in findings if getattr(f, "dimension", "") in HW_DIMS]
        fr = [f for f in findings if getattr(f, "dimension", "") == "fronting"]
        if hw and cfg.get("on_huawei", True):
            title, md = huawei_message(airport, hw)
            return send(title, md)
        if fr and cfg.get("on_fronting", False):
            title = "大厂域前置 %d 条 · %s" % (len(fr), airport)
            md = "\n".join(["## 大厂域名前置（不算华为云）", "",
                            "**机场**：%s" % airport] +
                           ["- `%s` %s" % (getattr(f, "rule", ""), getattr(f, "evidence", "")[:120]) for f in fr[:10]])
            return send(title, md)
    except Exception as e:
        print("[推送] 跳过（%s: %s）" % (type(e).__name__, e))
    return None


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(description="测试推送通道")
    p.add_argument("--text", default="这是一条测试消息，收到说明通道配好了。")
    a = p.parse_args(argv)
    cfg = load()
    print("enabled=%s channels=%d %s" % (cfg.get("enabled"), len(cfg.get("channels") or []),
                                         cfg.get("reason") or ""))
    if not cfg.get("enabled"):
        return 1
    r = send("airmon 测试推送", "## 测试\n\n%s\n\n时间：%s" % (a.text, time.strftime("%Y-%m-%d %H:%M:%S")))
    return 0 if r.get("ok") else 2


if __name__ == "__main__":
    import sys
    sys.exit(main())
