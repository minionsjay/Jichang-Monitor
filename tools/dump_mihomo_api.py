# -*- coding: utf-8 -*-
"""从 mihomo 系客户端（DOVE / Clash Verge / FlClash 等）的管理 API 取完整节点。

为什么需要它：这类客户端的订阅配置落盘是加密的（DOVE 的
`%APPDATA%\\DOVE.tauri\\DOVE.tauri.dat` 头是 `MHBNDL`），内存扫描也只能捞到
`IP:端口` 碎片（内核里配置已解析成结构体，不再是 JSON 文本）。
但它们都开了 mihomo 的 external-controller —— 那个 REST API 直接给出节点全字段。

做法：
  1. 找到内核进程（默认 dove-core），从 netstat 拿它 LISTENING 的端口；
  2. 逐个端口试 /version（带 `Authorization: Bearer <secret>`）；
  3. 通了就 GET /proxies，滤掉策略组，转成 `data/client_nodes/<slug>.json`
     （airmon/nodeset.py 会读这个文件按 (server,port) 合并进快照）。

secret 与配置文件路径来自 `C:\\ProgramData\\dove-service\\desired-state.json`；
其它客户端可以显式传 --secret / --port。

用法：
    python -X utf8 tools/dump_mihomo_api.py --slug dovex                 # DOVE
    python -X utf8 tools/dump_mihomo_api.py --slug dovex --port 9090 --secret xxx
    python -X utf8 tools/dump_mihomo_api.py --slug dovex --process dove-core --dry-run
"""
from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import time

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "data", "client_nodes")
DESIRED_STATE = r"C:\ProgramData\dove-service\desired-state.json"

# mihomo 里这些 type 是策略组/内置出站，不是真节点
GROUP_TYPES = {
    "selector", "urltest", "fallback", "loadbalance", "relay", "direct", "reject",
    "rejectdrop", "pass", "compatible", "smart", "dns", "chain",
}


def _pids(name: str) -> list[int]:
    """按进程名找 PID（tasklist 输出是 GBK，不能用 text=True）。"""
    try:
        r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                           capture_output=True, timeout=20)
        out = (r.stdout or b"").decode("gbk", "replace")
    except Exception:
        return []
    pids = []
    want = name.lower().replace(".exe", "")
    for line in out.splitlines():
        cells = [c.strip('"') for c in line.split('","')]
        if len(cells) >= 2 and cells[0].strip('"').lower().replace(".exe", "") == want:
            try:
                pids.append(int(cells[1]))
            except ValueError:
                pass
    return pids


def _listen_ports(pid: int) -> list[int]:
    """拿该 PID 正在 LISTENING 的 TCP 端口。"""
    try:
        r = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                           capture_output=True, timeout=25)
        out = (r.stdout or b"").decode("gbk", "replace")
    except Exception:
        return []
    ports = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        if parts[3].upper() != "LISTENING" or parts[4] != str(pid):
            continue
        host, _, port = parts[1].rpartition(":")
        try:
            p = int(port)
        except ValueError:
            continue
        if p not in ports:
            ports.append(p)
    return ports


def _secret_from_desired_state() -> str:
    try:
        with io.open(DESIRED_STATE, encoding="utf-8") as f:
            d = json.load(f)
        return ((d.get("last_clash_config") or {}).get("secret") or "")
    except Exception:
        return ""


def _try_port(port: int, secret: str):
    """返回 (ok, 版本或错因)。"""
    url = "http://127.0.0.1:%d/version" % port
    headers = {"Authorization": "Bearer %s" % secret} if secret else {}
    try:
        r = requests.get(url, headers=headers, timeout=2.5)
    except Exception as e:
        return False, str(e)[:60]
    if r.status_code == 401:
        return False, "401 需要 secret"
    if r.status_code != 200:
        return False, "HTTP %d" % r.status_code
    try:
        return True, (r.json() or {}).get("version") or "ok"
    except Exception:
        return True, "ok"


def fetch_proxies(port: int, secret: str) -> dict:
    headers = {"Authorization": "Bearer %s" % secret} if secret else {}
    r = requests.get("http://127.0.0.1:%d/proxies" % port, headers=headers, timeout=20)
    r.raise_for_status()
    return (r.json() or {}).get("proxies") or {}


def to_client_nodes(proxies: dict) -> list[dict]:
    """mihomo 的 proxy 对象基本就是 clash 配置项，剔除策略组和内置出站。"""
    nodes = []
    for name, p in proxies.items():
        if not isinstance(p, dict):
            continue
        t = (p.get("type") or "").strip()
        if not t or t.lower() in GROUP_TYPES:
            continue
        if not p.get("server") or not p.get("port"):
            continue
        item = dict(p)
        item["name"] = name
        nodes.append(item)
    return nodes


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--slug", required=True, help="机场 slug，写到 data/client_nodes/<slug>.json")
    ap.add_argument("--process", default="", help="内核进程名，默认从 credentials/airports 读 core_process")
    ap.add_argument("--port", type=int, default=0, help="直接指定管理端口，跳过探测")
    ap.add_argument("--secret", default="", help="管理 API 的 secret")
    ap.add_argument("--dry-run", action="store_true", help="只打印，不写文件")
    args = ap.parse_args(argv)

    proc = args.process
    if not proc:
        try:
            import yaml
            for fn, key in (("credentials.yaml", "accounts"), ("airports.yaml", "airports")):
                path = os.path.join(ROOT, fn)
                if not os.path.exists(path):
                    continue
                with io.open(path, encoding="utf-8") as f:
                    doc = yaml.safe_load(f) or {}
                if key == "accounts":
                    c = ((doc.get(key) or {}).get(args.slug) or {}).get("client") or {}
                else:
                    c = {}
                    for e in (doc.get(key) or []):
                        if isinstance(e, dict) and e.get("name") == args.slug:
                            c = e.get("client") or {}
                proc = (c.get("core_process") or "").strip()
                if proc:
                    break
        except Exception:
            proc = ""
    proc = proc or "dove-core"

    pids = _pids(proc)
    print("内核进程 %s: %s" % (proc, pids or "没在运行"), flush=True)
    if not pids:
        print("→ 先在客户端界面里点「连接」（核心才会起来），再跑本脚本")
        return 3

    secret = args.secret or _secret_from_desired_state()
    ports = [args.port] if args.port else []
    for pid in pids:
        for p in _listen_ports(pid):
            if p not in ports:
                ports.append(p)
    if not ports:
        print("→ 该进程没有 LISTENING 端口（管理 API 可能没开）")
        return 4
    print("候选端口:", ports, "| secret:", ("有(%d)" % len(secret)) if secret else "无", flush=True)

    hit = None
    for p in ports:
        ok, info = _try_port(p, secret)
        print("  %-6d %s" % (p, ("OK " + info) if ok else info), flush=True)
        if ok:
            hit = p
            break
    if not hit:
        return 5

    proxies = fetch_proxies(hit, secret)
    nodes = to_client_nodes(proxies)
    from collections import Counter
    print("API %d：条目 %d | 真节点 %d | 协议 %s"
          % (hit, len(proxies), len(nodes), dict(Counter(n.get("type") for n in nodes))), flush=True)
    for n in nodes[:3]:
        print("   ·", n.get("name"), "|", n.get("type"), "|",
              "%s:%s" % (n.get("server"), n.get("port")), flush=True)

    out = {"extracted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "slug": args.slug, "source": "mihomo-api:%s@%d" % (proc, hit), "nodes": nodes}
    if args.dry_run:
        print("(dry-run，未写盘)")
        return 0
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, "%s.json" % args.slug)
    tmp = path + ".tmp"
    with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)
    print("written", path, os.path.getsize(path), "字节")
    print("下一步：python -m airmon.nodeset && python -X utf8 tools/gen_panel_data.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
