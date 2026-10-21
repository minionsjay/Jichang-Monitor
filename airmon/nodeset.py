"""节点分文件导出：每台机场一个可直接用的节点文件（Clash 订阅 + base64 订阅体）。

产物（默认 nodes/，可用 --out 覆盖；随 run.py all 每 3h 自动刷新）：
  nodes/<slug>.yaml   Clash / mihomo proxy-provider 可直接引用的 proxies 列表
  nodes/<slug>.txt    base64 订阅体（每行一条 vmess:// vless:// ss:// trojan://
                      hysteria2:// anytls://，可直接粘进 v2rayN / nekoray）
  nodes/index.json    {generated_at, totals, airports:[{slug, nodes, exported,
                      skipped, protos, snapshot_protos, source_snapshot, ok, note}]}

口径（两个数字分工明确，避免自欺）：
  nodes    = 该机场最新快照里的节点总数 —— 与 data/nodes_export.csv 的行数同口径，
             便于和既有 CSV 对账（CSV 也是「最新快照全量节点」）
  exported = 真正写进 <slug>.yaml / <slug>.txt 的节点数
  skipped  = nodes - exported（协议没有 Clash 标准映射，或快照里缺必需字段）

设计原则：
1. 只写真实存在的字段：每个协议一张白名单（_FIELDS），raw 里有什么写什么，
   raw 里没有的键一律不写 —— 不补默认值、不猜 sniff/sni/alpn。
2. 必需字段缺失就跳过该节点并记原因（宁可少一个节点，也不导出连不上的假节点）。
3. 原子写：临时文件 + os.replace，避免面板/调度器读到写一半的 yaml。
4. nodes/ 含真实连接凭据 → 已写进 .gitignore，绝不入库。

用法：
  python -m airmon.nodeset                       # 全部机场 → nodes/
  python -m airmon.nodeset --out D:/tmp/nodes    # 换输出目录
  python -m airmon.nodeset --only hhy,fastlink   # 只导这两台
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
from collections import Counter
from urllib.parse import quote

import yaml

from . import store
from .store import DATA_DIR, _ts_of

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(_HERE, "nodes")

# slug 只允许字母数字开头，防路径穿越/怪字符（机场名都是英文短名）
_SLUG_RE = re.compile(r"^[A-Za-z0-9][\w.\-]{0,39}$")

# 每个协议允许落进 Clash 配置的字段白名单（均为 mihomo 认的标准键）
_FIELDS: dict[str, tuple[str, ...]] = {
    "ss": ("cipher", "password", "plugin", "plugin-opts", "udp"),
    "vmess": ("uuid", "alterId", "cipher", "tls", "servername", "network",
              "ws-opts", "skip-cert-verify", "client-fingerprint", "alpn", "udp"),
    "vless": ("uuid", "flow", "tls", "servername", "network", "ws-opts",
              "reality-opts", "client-fingerprint", "skip-cert-verify", "alpn",
              "packet-encoding", "encryption", "ech-opts", "udp"),
    "trojan": ("password", "sni", "skip-cert-verify", "network", "ws-opts",
               "client-fingerprint", "alpn", "udp"),
    "hysteria2": ("password", "sni", "skip-cert-verify", "obfs", "obfs-password",
                  "alpn", "fingerprint", "up", "down", "ports", "udp"),
    "anytls": ("password", "sni", "skip-cert-verify", "client-fingerprint",
               "alpn", "udp"),
}

# 少一行就连不上/客户端拒绝加载的字段
_REQUIRED: dict[str, tuple[str, ...]] = {
    "ss": ("cipher", "password"),
    "vmess": ("uuid",),
    "vless": ("uuid",),
    "trojan": ("password",),
    "hysteria2": ("password",),
    "anytls": ("password",),
}

# 协议友好名（打印/注释用）
_CN = {"ss": "SS", "vmess": "VMess", "vless": "VLESS", "trojan": "Trojan",
       "hysteria2": "Hysteria2", "anytls": "AnyTLS"}

_EMPTY = (None, "", [], {})


# ---------------------------------------------------------------- 基础工具

def _write_atomic(path: str, text: str) -> None:
    """临时文件 + os.replace 原子替换（同目录，保证同盘 rename 原子）。"""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _b64url_nopad(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("ascii").rstrip("=")


def _rel(path: str) -> str:
    """相对仓库根的 POSIX 路径（index.json 里用正斜杠，跨平台可读）。"""
    try:
        return os.path.relpath(path, _HERE).replace("\\", "/")
    except ValueError:
        return path.replace("\\", "/")


def _q(v) -> str:
    return quote(str(v), safe="")


def _unique(name: str, seen: set[str]) -> str:
    """同名节点会让 mihomo 报 duplicate proxy name，这里加后缀去重（原名不动）。"""
    base = name
    i = 2
    while name in seen:
        name = f"{base} #{i}"
        i += 1
    seen.add(name)
    return name


# ---------------------------------------------------------------- 节点 → Clash

def _proxy_of(node: dict) -> tuple[dict | None, str]:
    """把快照里的一个节点映射成 Clash proxy dict。

    返回 (proxy, "") 或 (None, 跳过原因)。只拷贝 _FIELDS 里的键，值原样照抄。
    """
    proto = (node.get("protocol") or "").strip()
    raw = node.get("raw") or {}
    if proto not in _FIELDS:
        return None, f"协议 {proto or '未知'} 无 Clash 映射"
    server = node.get("server") or raw.get("server")
    port = node.get("port") or raw.get("port")
    if not server or not port:
        return None, "缺 server/port"
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None, "port 非数字"

    raw = dict(raw)
    # Hysteria2：部分快照把同一个凭据写成 auth，统一收敛到标准键 password
    if proto == "hysteria2" and raw.get("password") in (None, "") and raw.get("auth"):
        raw["password"] = raw["auth"]

    miss = [k for k in _REQUIRED[proto] if raw.get(k) in (None, "")]
    if miss:
        return None, "缺必需字段 " + "/".join(miss)

    name = str(node.get("name") or raw.get("name") or f"{server}:{port}").strip()
    p: dict = {"name": name, "type": proto, "server": str(server), "port": port}
    for k in _FIELDS[proto]:
        v = raw.get(k)
        if v in _EMPTY:
            continue
        if k == "tls" and isinstance(v, int):      # 快照里 tls 有 1/0，Clash 要 bool
            v = bool(v)
        p[k] = v

    # 旧版 parse 只留了 ws-path/ws-headers（值是真值）：折叠成标准的 ws-opts
    if "ws-opts" not in p and proto in ("vmess", "vless", "trojan"):
        path, headers = raw.get("ws-path"), raw.get("ws-headers")
        if path not in (None, "") or headers not in (None, "", {}):
            opts: dict = {}
            if path not in (None, ""):
                opts["path"] = path
            if headers not in (None, "", {}):
                opts["headers"] = headers
            p["ws-opts"] = opts
    return p, ""


def _clash_text(slug: str, proxies: list[dict], gen: str,
                n_snap: int, skipped: Counter) -> str:
    head = [
        f"# airmon nodeset · {slug} · 生成于 {gen}",
        f"# 节点 {len(proxies)}/{n_snap} 个（跳过 {n_snap - len(proxies)} 个：协议无 Clash 映射或快照缺字段）",
        "# mihomo proxy-provider 用法：proxy-providers: {"
        f"{slug}: {{type: file, path: ./nodes/{slug}.yaml}}}}",
    ]
    if not proxies:
        why = "、".join(f"{k}×{v}" for k, v in skipped.most_common()) or "无节点"
        head.append(f"# 本机场没有可导出的节点（{why}），proxies 留空，等机场换协议/换订阅")
    body = yaml.safe_dump({"proxies": proxies}, allow_unicode=True, sort_keys=False,
                          default_flow_style=False, width=1 << 20)
    return "\n".join(head) + "\n" + body


# ---------------------------------------------------------------- Clash → 链接

def _link(p: dict) -> str:
    """把 Clash proxy dict 还原成一条分享链接（字段照样取自 proxy，不额外猜）。"""
    t, server, port = p["type"], p["server"], p["port"]
    name = _q(p["name"])

    if t == "ss":
        userinfo = _b64url_nopad(f"{p['cipher']}:{p['password']}")
        return f"ss://{userinfo}@{server}:{port}#{name}"

    if t == "vmess":
        opts = p.get("ws-opts") or {}
        heads = opts.get("headers") or {}
        host = heads.get("Host") or p.get("servername") or ""
        tls = bool(p.get("tls"))
        obj = {"v": "2", "ps": p["name"], "add": server, "port": str(port),
               "id": p["uuid"], "aid": str(p.get("alterId", 0)),
               "net": p.get("network") or "tcp", "type": "none",
               "host": host, "path": opts.get("path") or "",
               "tls": "tls" if tls else "", "sni": p.get("servername") or ""}
        if p.get("cipher"):
            obj["scy"] = p["cipher"]
        return "vmess://" + _b64(json.dumps(obj, ensure_ascii=False))

    if t == "vless":
        qs: list[tuple[str, str]] = [("encryption", p.get("encryption") or "none")]
        if p.get("flow"):
            qs.append(("flow", p["flow"]))
        ro = p.get("reality-opts") or {}
        if ro:
            qs.append(("security", "reality"))
            if ro.get("public-key"):
                qs.append(("pbk", ro["public-key"]))
            if ro.get("short-id"):
                qs.append(("sid", ro["short-id"]))
        elif p.get("tls"):
            qs.append(("security", "tls"))
        else:
            qs.append(("security", "none"))
        if p.get("servername"):
            qs.append(("sni", p["servername"]))
        if p.get("client-fingerprint"):
            qs.append(("fp", p["client-fingerprint"]))
        if p.get("alpn"):
            qs.append(("alpn", ",".join(p["alpn"]) if isinstance(p["alpn"], list) else p["alpn"]))
        opts = p.get("ws-opts") or {}
        if p.get("network"):
            qs.append(("type", p["network"]))
        if opts.get("path"):
            qs.append(("path", opts["path"]))
        heads = opts.get("headers") or {}
        if heads.get("Host"):
            qs.append(("host", heads["Host"]))
        if p.get("skip-cert-verify"):
            qs.append(("allowInsecure", "1"))
        return f"vless://{p['uuid']}@{server}:{port}?{'&'.join(f'{k}={_q(v)}' for k, v in qs)}#{name}"

    if t == "trojan":
        qs = [("security", "tls")]
        if p.get("sni"):
            qs.append(("sni", p["sni"]))
        opts = p.get("ws-opts") or {}
        if p.get("network"):
            qs.append(("type", p["network"]))
        if opts.get("path"):
            qs.append(("path", opts["path"]))
        heads = opts.get("headers") or {}
        if heads.get("Host"):
            qs.append(("host", heads["Host"]))
        if p.get("skip-cert-verify"):
            qs.append(("allowInsecure", "1"))
        return f"trojan://{_q(p['password'])}@{server}:{port}?{'&'.join(f'{k}={_q(v)}' for k, v in qs)}#{name}"

    if t == "hysteria2":
        qs = []
        if p.get("sni"):
            qs.append(("sni", p["sni"]))
        if p.get("skip-cert-verify"):
            qs.append(("insecure", "1"))
        if p.get("obfs"):
            qs.append(("obfs", p["obfs"]))
        if p.get("obfs-password"):
            qs.append(("obfs-password", p["obfs-password"]))
        if p.get("alpn"):
            qs.append(("alpn", ",".join(p["alpn"]) if isinstance(p["alpn"], list) else p["alpn"]))
        if p.get("ports"):
            qs.append(("mport", p["ports"]))
        tail = f"?{'&'.join(f'{k}={_q(v)}' for k, v in qs)}" if qs else ""
        return f"hysteria2://{_q(p['password'])}@{server}:{port}{tail}#{name}"

    if t == "anytls":
        qs = []
        if p.get("sni"):
            qs.append(("sni", p["sni"]))
        if p.get("skip-cert-verify"):
            qs.append(("insecure", "1"))
        if p.get("client-fingerprint"):
            qs.append(("fp", p["client-fingerprint"]))
        if p.get("alpn"):
            qs.append(("alpn", ",".join(p["alpn"]) if isinstance(p["alpn"], list) else p["alpn"]))
        tail = f"?{'&'.join(f'{k}={_q(v)}' for k, v in qs)}" if qs else ""
        return f"anytls://{_q(p['password'])}@{server}:{port}{tail}#{name}"

    return ""


# ---------------------------------------------------------------- 单机场导出

def _snapshots(slug: str) -> list[str]:
    """该机场按时间排序的快照（用 store 的路径规则，跳过 rdap_cache.json 这类非快照 json）。"""
    return [p for p in store.list_snapshots(slug) if _ts_of(p) is not None]


def _slugs(only: list[str] | None) -> list[str]:
    if only:
        return sorted({s.strip() for s in only if s.strip()})
    out = []
    try:
        names = sorted(os.listdir(DATA_DIR))
    except OSError:
        return out
    for name in names:
        if name.startswith((".", "_")) or not _SLUG_RE.match(name):
            continue
        if not os.path.isdir(os.path.join(DATA_DIR, name)):
            continue
        if _snapshots(name):
            out.append(name)
    return out


def _drop(out_dir: str, slug: str) -> None:
    """机场这轮导不出东西时清掉旧文件，避免留下过期凭据冒充新数据。"""
    for ext in (".yaml", ".txt"):
        path = os.path.join(out_dir, slug + ext)
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


def _client_nodes(slug: str) -> list[dict]:
    """读 data/client_nodes/<slug>.json（客户端内存捞到的**完整**节点），转成快照节点形状。

    背景：`run.py all` 的 scan-memory 每轮都会用「只有 server:port、protocol=unknown」
    的快照覆盖同一机场的最新快照。若只看最新快照，客户端机场的完整节点会被瞬间吃掉
    （ssrdog 实测发生过：36 个 AnyTLS 变 0 个可导出）。所以导出时把 client_nodes
    作为一等节点来源，再与快照按 (server,port) 合并。
    """
    path = os.path.join(DATA_DIR, "client_nodes", slug + ".json")
    if not os.path.isfile(path):
        return []
    try:
        d = json.load(open(path, encoding="utf-8"))
    except Exception:                                         # noqa: BLE001
        return []
    out: list[dict] = []
    for p in d.get("nodes") or []:
        if not isinstance(p, dict):
            continue
        proto = str(p.get("type") or "").strip()
        server, port = p.get("server"), p.get("port")
        if not proto or not server or not port:
            continue
        raw = {k: v for k, v in p.items() if k not in ("name", "type", "server", "port")}
        out.append({"name": p.get("name") or f"{server}:{port}",
                    "protocol": proto, "server": str(server), "port": port, "raw": raw})
    return out


def _merge_nodes(snap_nodes: list[dict], client_nodes: list[dict]) -> tuple[list[dict], str]:
    """按 (server,port) 合并两个来源：能导出的优先，同能导出时以快照（更新）为准。"""
    if not client_nodes:
        return snap_nodes, "snapshot"
    if not snap_nodes:
        return client_nodes, "client_nodes"

    def key(n):
        return (str(n.get("server") or (n.get("raw") or {}).get("server")),
                str(n.get("port") or (n.get("raw") or {}).get("port")))

    merged: dict[tuple, dict] = {}
    for n in client_nodes:
        merged[key(n)] = n
    used_client = 0
    for n in snap_nodes:
        k = key(n)
        old = merged.get(k)
        if old is None:
            merged[k] = n
            continue
        if _proxy_of(n)[0] is not None:
            merged[k] = n                     # 快照这份也能导出 → 用更新的快照
        elif _proxy_of(old)[0] is not None:
            used_client += 1                  # 快照只是 raw-only 的残片 → 保留客户端完整版
        else:
            merged[k] = n
    return list(merged.values()), ("client_nodes+snapshot" if used_client else "snapshot")


def _export_one(slug: str, out_dir: str, gen: str) -> dict:
    entry: dict = {"slug": slug, "nodes": 0, "exported": 0, "skipped": 0,
                   "protos": {}, "snapshot_protos": {}, "source_snapshot": "",
                   "node_source": "", "ok": False}
    if not _SLUG_RE.match(slug):
        entry["note"] = "非法 slug"
        return entry
    snaps = _snapshots(slug)
    client = _client_nodes(slug)
    if not snaps and not client:
        entry["note"] = "无快照"
        _drop(out_dir, slug)
        return entry
    snap_nodes: list[dict] = []
    if snaps:
        path = snaps[-1]
        entry["source_snapshot"] = _rel(path)
        try:
            snap = store.load(path)
            snap_nodes = snap.get("nodes") or []
        except Exception as e:                                # noqa: BLE001
            entry["note"] = f"快照读取失败: {e}"
            if not client:
                _drop(out_dir, slug)
                return entry

    nodes, src = _merge_nodes(snap_nodes, client)
    entry["node_source"] = src
    entry["nodes"] = len(nodes)
    entry["snapshot_protos"] = dict(Counter(str(n.get("protocol") or "?") for n in nodes))
    if not nodes:
        entry["note"] = "最新快照无节点"
        _drop(out_dir, slug)
        return entry

    proxies: list[dict] = []
    skipped: Counter = Counter()
    seen: set[str] = set()
    for n in nodes:
        p, why = _proxy_of(n)
        if p is None:
            skipped[why] += 1
            continue
        p["name"] = _unique(p["name"], seen)
        proxies.append(p)

    entry["exported"] = len(proxies)
    entry["skipped"] = len(nodes) - len(proxies)
    entry["protos"] = dict(Counter(p["type"] for p in proxies))
    entry["ok"] = True
    if skipped:
        entry["note"] = "跳过 " + "；".join(f"{k} ×{v}" for k, v in skipped.most_common())

    yaml_text = _clash_text(slug, proxies, gen, len(nodes), skipped)
    links = [ln for ln in (_link(p) for p in proxies) if ln]
    txt_text = _b64("\n".join(links) + ("\n" if links else ""))
    _write_atomic(os.path.join(out_dir, slug + ".yaml"), yaml_text)
    _write_atomic(os.path.join(out_dir, slug + ".txt"), txt_text)
    return entry


# ---------------------------------------------------------------- 入口

def export(out_dir: str | None = None, only: list[str] | None = None) -> dict:
    """导出全部（或 only 指定的）机场，返回写进 index.json 的完整字典。"""
    out = os.path.abspath(out_dir or OUT_DIR)
    os.makedirs(out, exist_ok=True)
    gen = store.now_iso()
    entries = [_export_one(slug, out, gen) for slug in _slugs(only)]

    tot_protos: Counter = Counter()
    for e in entries:
        tot_protos.update(e["protos"])
    idx = {
        "generated_at": gen,
        "tool": "airmon.nodeset",
        "out_dir": _rel(out),
        "totals": {
            "airports": len(entries),
            "airports_ok": sum(1 for e in entries if e["ok"]),
            "airports_exported": sum(1 for e in entries if e["exported"]),
            "nodes": sum(e["nodes"] for e in entries),
            "exported": sum(e["exported"] for e in entries),
            "skipped": sum(e["skipped"] for e in entries),
            "protos": dict(tot_protos.most_common()),
        },
        "airports": entries,
    }
    _write_atomic(os.path.join(out, "index.json"),
                  json.dumps(idx, ensure_ascii=False, indent=2) + "\n")
    return idx


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="airmon.nodeset",
                                description="节点分文件导出（每机场一个 Clash 订阅 + base64 订阅体）")
    p.add_argument("--out", default=None, help=f"输出目录（默认 {OUT_DIR}）")
    p.add_argument("--only", default="", help="逗号分隔 slug 列表，只要这几台")
    a = p.parse_args(argv)
    only = [s.strip() for s in a.only.split(",") if s.strip()] or None
    idx = export(a.out, only)
    t = idx["totals"]
    print(f"节点分文件 → {idx['out_dir']}"
          f"（{t['airports']} 机场 / {t['nodes']} 节点，导出 {t['exported']} 个，"
          f"跳过 {t['skipped']} 个；有可导出节点的机场 {t['airports_exported']} 台）")
    if t["protos"]:
        print("  协议分布：" + "、".join(f"{_CN.get(k, k)} {v}" for k, v in t["protos"].items()))
    empty = [e["slug"] for e in idx["airports"] if e["ok"] and not e["exported"]]
    if empty:
        print(f"  无可导出节点：{len(empty)} 台（{'、'.join(empty[:8])}"
              f"{' 等' if len(empty) > 8 else ''}）→ 原因见 index.json 的 note")
    bad = [(e["slug"], e.get("note", "")) for e in idx["airports"] if not e["ok"]]
    if bad:
        print(f"  无可用快照：{len(bad)} 台（{'、'.join(s for s, _ in bad[:8])}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
