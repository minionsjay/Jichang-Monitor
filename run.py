#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""airmon CLI —— 机场订阅监控 + 华为关联检测。

  python3 run.py scan-existing <csv>            在现有 CSV 上验证华为检测引擎
  python3 run.py collect --airport <name>       采集直连型机场订阅
  python3 run.py ingest-profile --airport <name> --file <profile.yaml>
                                                摄入客户端锁定型机场落盘 profile
  python3 run.py diff --airport <name>          对比最近两次快照
  python3 run.py list                           列出注册机场

  --- Windows 客户端型（配置加密的 FlClash 变种）---
  python3 run.py scan-win-client --airport <name> --dir <AppData目录> [--app-dir <安装目录>]
                                                扫描 Windows 客户端数据目录（提取订阅URL/API域名/账号）
  python3 run.py scan-memory --airport <name> [--client <客户端名>] [--pid <PID>]
                                                从 Clash 内核进程内存提取节点（需管理员权限）
  python3 run.py monitor-net --airport <name> [--client <客户端名>] [--pid <PID>] [--watch] [--interval 5]
                                                监控客户端 TCP 连接提取代理 IP:端口
"""
from __future__ import annotations

import argparse
import io
import sys

import csv
import glob
import os

from airmon import store
from airmon.alert import emit
from airmon.collect import (collect_direct, collect_profile, collect_login,
                            collect_from_url, collect_page, collect_node_pages,
                            collect_client, collect_server_fetch)
from airmon.config import load_airports, get_airport, load_credentials, seed_domains
from airmon.detect import Detector, count_huawei, HW_DIMS
from airmon.login import LoginError, detect_panel, discover_panel
from airmon.recon import recon_airport, load_seeds, to_host, _dig
from airmon import report as report_mod
from airmon.rescan import rescan_airport, unresolved_stats
from airmon.scan_csv import scan_csv


def cmd_scan_existing(args):
    findings = scan_csv(args.csv)
    if not findings:
        print("未命中任何华为签名。")
        return
    findings = [f for f in findings if f.dimension in HW_DIMS]
    print(f"华为关联命中 {len(findings)} 条：\n")
    for f in findings:
        print("  " + f.line())

def cmd_list(args):
    airports = load_airports()
    creds = {}
    try:
        creds = load_credentials()
    except Exception:
        pass
    # 把credentials里有但airports.yaml没有的机场也加上
    for slug in creds:
        if slug not in airports:
            airports[slug] = {'name': slug, 'display': slug, 'type': 'direct', 'enabled': True}
    # 加载最新快照
    import glob, json
    latest = {}
    for d in glob.glob(os.path.join(store.DATA_DIR, "*/")):
        slug = os.path.basename(d.rstrip("/").rstrip("\\"))
        snaps = sorted(glob.glob(os.path.join(d, "*.json")))
        if snaps:
            s = store.load(snaps[-1])
            latest[slug] = {"nodes": len(s.get("nodes", [])),
                            "findings": len(s.get("findings", [])),
                            "ts": os.path.basename(snaps[-1]).replace(".json", "")}

    print(f"共 {len(airports)} 个机场\n")
    print(f"{'状态':4} {'机场':15} {'类型':8} {'采集方式':16} {'节点':5} {'华为':4} {'最近采集':16} {'panel域名':25} {'显示名'}")
    print("-" * 120)
    for name, a in airports.items():
        enabled = a.get("enabled")
        flag = "[on] " if enabled else "[off]"
        atype = a.get("type", "direct")
        cred = creds.get(name, {})
        if atype == "client":
            method = "scan-memory"
        elif cred.get("sub_url"):
            method = "sub_url直抓"
        elif cred.get("email") or cred.get("panel"):
            method = "API登录"
        else:
            method = "-"
        d = latest.get(name, {"nodes": 0, "findings": 0, "ts": ""})
        hw = f"{d['findings']}" if d["findings"] else "-"
        ts = d["ts"][:16] if d["ts"] else "-"
        display = a.get("display", "")
        # 显示panel来源
        panel = cred.get("panel") or a.get("panel") or ""
        if not panel:
            # 看最新快照的source里有没有域名线索
            pass
        panel_short = panel.replace("https://", "").replace("http://", "")[:24] if panel else "-"
        print(f"{flag} {name:15} {atype:8} {method:16} {d['nodes']:5} {hw:4} {ts:16} {panel_short:25} {display}")
    
    total_nodes = sum(d["nodes"] for d in latest.values())
    total_hw = sum(d["findings"] for d in latest.values())
    active = sum(1 for d in latest.values() if d["nodes"] > 0)
    print(f"\n有数据: {active}个机场  总节点: {total_nodes}  华为命中: {total_hw}")

def cmd_collect(args):
    airport = get_airport(args.airport)
    if airport.get("type") != "direct":
        print(f"注意：{args.airport} 是 {airport.get('type')} 型；"
              f"客户端锁定型请用 ingest-profile。", file=sys.stderr)
    snap = collect_direct(airport, Detector())
    path = store.save(snap)
    print(f"采集完成：{len(snap.nodes)} 节点，{count_huawei(snap.findings)} 华为命中 → {path}")
    changes = store.diff_latest(args.airport)
    emit(args.airport, snap.findings, changes)

def cmd_ingest_profile(args):
    airport = get_airport(args.airport)
    snap = collect_profile(airport, args.file, Detector(), index_path=args.index)
    path = store.save(snap)
    print(f"摄入完成：{len(snap.nodes)} 节点，{count_huawei(snap.findings)} 华为命中 → {path}")
    changes = store.diff_latest(args.airport)
    emit(args.airport, snap.findings, changes)

def cmd_diff(args):
    d = store.diff_latest(args.airport)
    if not d:
        print("快照不足两次，无法 diff。")
        return
    print(f"prev={d['prev']}\ncur ={d['cur']}")
    print(f"新增 {len(d['added'])} / 消失 {len(d['removed'])}")
    for n in d["added"]:
        print(f"  + {n.get('name')} {n.get('server')}:{n.get('port')}")
    for n in d["removed"]:
        print(f"  - {n.get('name')} {n.get('server')}:{n.get('port')}")

def _resolve_panel(slug: str, given: str | None) -> tuple[str | None, str | None]:
    """如果给了panel直接用；否则从seeds.txt逐个测试域名找面板。"""
    if given:
        return given, None
    return _resolve_from_seeds(slug)


def _resolve_from_seeds(slug: str) -> tuple[str | None, str | None]:
    """从seeds.txt逐个解析域名，探测v2board/SSPanel面板。"""
    hosts = []
    for d in seed_domains().get(slug, []):
        _disp, ascii_h = to_host(d)
        if _dig(ascii_h, "A"):
            hosts.append(ascii_h)
    hit = detect_panel(hosts)
    if hit:
        return hit
    hit = discover_panel(hosts)
    if hit:
        return hit
    return None, None


def _try_all_panels(slug: str, cred: dict) -> tuple[str | None, str]:
    """尝试所有可能的panel：给定的→seeds里的每个域名→discover。
    
    返回 (panel_url, source) 或 (None, reason)。
    给定的panel如果登录失败，回退到seeds逐个试。"""
    from airmon.login import smart_login, LoginError

    email = cred.get("email")
    password = cred.get("password")
    if not email or not password:
        return None, "无凭证"

    # 1. 先试给定的panel
    given = cred.get("panel")
    if given:
        print(f"    [{slug}] 尝试 panel: {given} ...", flush=True)
        try:
            smart_login(given, email, password, cred.get("type", "auto"))
            print(f"    [{slug}] ✓ 登录成功: {given}")
            return given, "given"
        except LoginError as e:
            print(f"    [{slug}] ✗ 登录失败({str(e)[:50]})，尝试其他域名 ...")

    # 2. 试seeds.txt里的每个域名
    seeds = seed_domains().get(slug, [])
    tried = set()
    if given:
        tried.add(given.replace("https://","").replace("http://","").rstrip("/"))
    
    for i, d in enumerate(seeds, 1):
        _disp, ascii_h = to_host(d)
        if ascii_h in tried:
            continue
        # DNS解析
        ips = _dig(ascii_h, "A")
        if not ips:
            if VERBOSE:
                print(f"    [{slug}] {i}/{len(seeds)} {ascii_h} → 无DNS解析，跳过", flush=True)
            continue
        tried.add(ascii_h)
        print(f"    [{slug}] {i}/{len(seeds)} {ascii_h} → IP:{ips[0]}，探测面板...", flush=True)
        # 探测是否是面板
        hit = detect_panel([ascii_h])
        if not hit:
            if VERBOSE:
                print(f"    [{slug}]   非面板，跳过")
            continue
        print(f"    [{slug}]   探测到面板({hit[1]})，尝试登录...", flush=True)
        try:
            smart_login(hit[0], email, password, hit[1])
            print(f"    [{slug}] ✓ 登录成功: {hit[0]}")
            return hit[0], f"seeds:{ascii_h}"
        except LoginError as e:
            print(f"    [{slug}]   ✗ 登录失败({str(e)[:40]})")
            continue

    # 3. discover_panel（抓官网HTML找后台域名）
    print(f"    [{slug}] seeds域名全部失败，尝试从官网HTML发现后台...", flush=True)
    hosts = []
    for d in seeds:
        _disp, ascii_h = to_host(d)
        if _dig(ascii_h, "A"):
            hosts.append(ascii_h)
    hit = discover_panel(hosts)
    if hit:
        print(f"    [{slug}] 发现后台: {hit[0]}，尝试登录...", flush=True)
        try:
            smart_login(hit[0], email, password, hit[1])
            print(f"    [{slug}] ✓ 登录成功: {hit[0]}")
            return hit[0], f"discover:{hit[0]}"
        except LoginError as e:
            print(f"    [{slug}]   ✗ 登录失败({str(e)[:40]})")

    return None, "所有域名都失败"

VERBOSE = False


def _get_client_config(slug: str) -> dict | None:
    """从 credentials.yaml 或 airports.yaml 获取客户端配置。"""
    # 先从 credentials.yaml
    try:
        creds = load_credentials()
        if slug in creds and creds[slug].get("client"):
            return creds[slug]["client"]
    except Exception:
        pass
    # 再从 airports.yaml
    try:
        apt = get_airport(slug)
        return apt.get("client")
    except Exception:
        return None


def _merge_client_nodes(slug: str, snap):
    """把 data/client_nodes/<slug>.json 里的**完整节点**并入内存扫描快照。

    内存扫描只能给出 server:port（protocol=unknown，无 password/uuid），而客户端 core 进程的
    运行期配置里其实有完整字段（t11 实测：ssrdog AnyTLS / speedcat VLESS / fastlink VLESS）。
    不合并的话，每轮 scan-memory 都会用残片覆盖掉完整节点，导出与面板同时退化。
    这里只做「同名 server:port 补字段」，不引入 harvested 里多出来的旧节点（避免复活死节点）。
    """
    try:
        import json as _json
        p = os.path.join(store.DATA_DIR, "client_nodes", slug + ".json")
        if not os.path.isfile(p):
            return snap
        d = _json.load(open(p, encoding="utf-8"))
        full = {}
        for n in d.get("nodes") or []:
            if not isinstance(n, dict):
                continue
            k = (str(n.get("server") or ""), str(n.get("port") or ""))
            if k[0] and k[1]:
                full[k] = n
        if not full:
            return snap
        fixed = 0
        for node in snap.nodes:
            k = (str(node.server or ""), str(node.port or ""))
            src = full.get(k)
            if not src:
                continue
            want = str(src.get("type") or "").strip()
            if not want or (node.protocol or "").lower() == want.lower():
                continue
            node.protocol = want
            for kk, vv in src.items():
                if kk in ("name", "type", "server", "port"):
                    continue
                if vv not in (None, "", [], {}):
                    node.raw[kk] = vv
            fixed += 1
        if fixed:
            print(f"    [{slug}] 内存快照已补全 {fixed} 个节点的协议字段（来自 client_nodes）",
                  flush=True)
    except Exception as e:                                    # noqa: BLE001
        print(f"    [{slug}] client_nodes 合并失败（忽略）: {e}", flush=True)
    return snap


def _nodes_from_bundle(slug: str, r: dict, detector: Detector):
    """把「离线解包的客户端配置」写成一份快照，走与内存扫描相同的落盘链路。

    解出来的节点带全字段（type/server/port/uuid/servername/reality-opts/dialer-proxy），
    所以 raw 里整份塞进去：nodeset 导出时按协议能不能转来决定「可导出」，
    面板的节点表也能直接读 uuid 之类（展示时按白名单，不会把密码吐出去）。
    """
    import json as _json
    from airmon.models import Node as _Node, Snapshot as _Snapshot
    from airmon.collect import _enrich_and_detect as _enrich

    nodes = []
    with io.open(r["path"], encoding="utf-8") as f:
        j = _json.load(f)
    for p in (j.get("nodes") or []):
        if not isinstance(p, dict):
            continue
        srv = (p.get("server") or "").strip()
        try:
            port = int(p.get("port") or 0)
        except Exception:
            port = 0
        raw = {k: v for k, v in p.items() if k not in ("name", "type", "server", "port")}
        raw["source"] = r.get("source") or "dove-bundle"
        raw["_complete"] = True
        nodes.append(_Node(name=(p.get("name") or "node-%s" % port),
                           protocol=(p.get("type") or "unknown"),
                           server=srv, port=port, raw=raw))
    if not nodes:
        return False
    # service.internal 这类内网名解析不了，enrich 会快速失败；4 个入口是真域名，能查 RDAP
    try:
        _enrich(slug, nodes, detector)
    except Exception as e:  # noqa: BLE001
        print(f"    [{slug}] 富化跳过（{str(e)[:50]}）", flush=True)
    snap = _Snapshot(airport=slug, ts=store.now_iso(),
                     source=r.get("snapshot_source")
                     or "bundle:%s" % os.path.basename(r.get("dat") or "DOVE.tauri.dat"),
                     nodes=nodes, findings=[], meta={"bundle_name": r.get("bundle_name") or ""})
    _finish(slug, snap, r.get("finish_tag") or "bundle:dove")
    return True


def _guess_client_exe(install_dir, client_cfg):
    """package 名拼出的 exe 不存在时，按内核名前缀在安装目录里找主程序。

    典型场景：letsvpn 的主程序叫 LetsPRO.exe，而 package 缺省时会去拼
    Letsvpn.exe；这里按 core_process（LetsPRO）前缀兜底，避开安装器类 exe。
    """
    try:
        names = os.listdir(install_dir)
    except OSError:
        return ""
    skip = ("uninst", "update", "ndp", "tapinstall", "letsgoogle", "vc_redist", "setup")
    cands = [f for f in names
             if f.lower().endswith(".exe") and not f.lower().startswith(skip)]
    if not cands:
        return ""
    pref = str(client_cfg.get("core_process") or "").strip().lower()
    if pref:
        for f in cands:
            if f.lower().startswith(pref[:6]):
                return os.path.join(install_dir, f)
    return ""

def _do_scan_memory(slug: str, client_cfg: dict, detector: Detector):
    """自动启动客户端 → 等待 → scan-memory → keep_alive控制关闭。

    例外：DOVE 这类把整份配置加密落盘的客户端，先试**离线解包**——不启动客户端、
    不需要管理员权限，还能拿到带 uuid/reality-opts 的完整节点（内存扫描只能捞到
    IP:端口 碎片）。解包不成就退回原来的内存扫描。
    """
    import subprocess as _sp
    import time as _time

    # 优先级 0：离线解包（DOVE 的 DOVE.tauri.dat）
    try:
        from airmon import dovex as _dovex
        if _dovex.available(client_cfg, slug):
            print(f"    [{slug}] 先试离线解包 DOVE.tauri.dat（不用启动客户端）...", flush=True)
            _r = _dovex.extract(slug, client_cfg)
            if _r.get("ok") and _r.get("count"):
                print(f"    [{slug}] 解包成功：{_r['count']} 节点 {_r['protos']}，bundle={_r['bundle_name']}",
                      flush=True)
                if _nodes_from_bundle(slug, _r, detector):
                    return
            else:
                print(f"    [{slug}] 离线解包失败（{_r.get('error', '')[:60]}），改用内存扫描", flush=True)
    except Exception as _e:  # noqa: BLE001
        print(f"    [{slug}] 离线解包异常（{str(_e)[:60]}），改用内存扫描", flush=True)

    # 优先级 0.5：抓包缓存（青云梯这类把整份配置从管道交给内核的客户端）。
    # 抓包结果在 客户端逆向/青云梯-极速版/工具/qyt_config.json，带 uuid/flow/servername，
    # 比读进程内存完整；既然手上有就不必再提权读内存（SNI 会随订阅轮换，久了要重抓）。
    try:
        from airmon import qingyunti as _qyt
        if _qyt.available(slug, client_cfg):
            print(f"    [{slug}] 抓取青云梯配置（约 40 秒：拉起客户端 → 拦截内核配置 → 自动收尾）…",
                  flush=True)
            _r2 = _qyt.prepare(slug, client_cfg)
            if _r2.get("ok") and _r2.get("count"):
                _via = "实时抓取" if _r2.get("via") == "capture" else "抓包缓存"
                if _r2.get("via") == "cache-fallback":
                    print(f"    [{slug}] ⚠ 实时抓取失败（{str(_r2.get('capture_error'))[:70]}），"
                          f"退回旧缓存 —— 这些节点的 SNI 可能已过期，需要点一次「获取节点」重抓",
                          flush=True)
                print(f"    [{slug}] 用{_via}：{_r2['count']} 节点，抓于 "
                      f"{_r2['captured_at']}（{_r2['age_hours']} 小时前）"
                      + ("，已超 %d 小时建议重抓" % _qyt.STALE_HOURS if _r2.get("stale") else ""),
                      flush=True)
                if _nodes_from_bundle(slug, _r2, detector):
                    return
    except Exception as _e:  # noqa: BLE001
        print(f"    [{slug}] 抓包缓存不可用（{str(_e)[:60]}），继续内存扫描", flush=True)

    # 优先级 0.6：wandacloud / 万达云（含 wdy）YAML 解析入口 dump（约 45-60 秒，免提权）
    try:
        from airmon import wandacloud as _wd
        if _wd.available(slug, client_cfg):
            print(f"    [{slug}] 抓取万达云配置（约 45-60 秒：Frida 截内核 YAML 解析入参）…",
                  flush=True)
            _rd = _wd.prepare(slug, client_cfg)
            if _rd.get("ok") and _rd.get("count"):
                _vd = "实时抓取" if _rd.get("via") == "capture" else "抓包缓存"
                if _rd.get("via") == "cache-fallback":
                    print(f"    [{slug}] \u26a0 实时抓取失败（{str(_rd.get('capture_error'))[:70]}），"
                          f"退回旧缓存", flush=True)
                print(f"    [{slug}] 用{_vd}：{_rd['count']} 节点，抓于 "
                      f"{_rd['captured_at']}（{_rd['age_hours']} 小时前）", flush=True)
                if _nodes_from_bundle(slug, _rd, detector):
                    return
    except Exception as _e:  # noqa: BLE001
        print(f"    [{slug}] 万达云抓取不可用（{str(_e)[:60]}），继续内存扫描", flush=True)

    # 优先级 0.55：hhy（好好云）本地 RPC 抓取（约 2-3 秒，免提权）
    try:
        from airmon import hhy as _hhy
        if _hhy.available(slug, client_cfg):
            print(f"    [{slug}] 抓取好好云配置（约 2-3 秒：Frida 截内核 RPC 帧 → 自动收尾）…",
                  flush=True)
            _r3 = _hhy.prepare(slug, client_cfg)
            if _r3.get("ok") and _r3.get("count"):
                _v3 = "实时抓取" if _r3.get("via") == "capture" else "抓包缓存"
                if _r3.get("via") == "cache-fallback":
                    print(f"    [{slug}] ⚠ 实时抓取失败（{str(_r3.get('capture_error'))[:70]}），"
                          f"退回旧缓存", flush=True)
                print(f"    [{slug}] 用{_v3}：{_r3['count']} 节点，抓于 "
                      f"{_r3['captured_at']}（{_r3['age_hours']} 小时前）", flush=True)
                if _nodes_from_bundle(slug, _r3, detector):
                    return
    except Exception as _e:  # noqa: BLE001
        print(f"    [{slug}] 好好云抓包不可用（{str(_e)[:60]}），继续内存扫描", flush=True)

    core_process = client_cfg.get("core_process", "")
    if not core_process:
        return

    def _find_pid(proc_name):
        try:
            # tasklist 输出是 GBK；不能用 text=True（本机 utf-8 模式会 UnicodeDecodeError）
            r = _sp.run(["tasklist", "/FI", f"IMAGENAME eq {proc_name}.exe",
                         "/FO", "CSV", "/NH"],
                        capture_output=True, timeout=10)
            out = (r.stdout or b"").decode("gbk", "replace")
            for line in out.strip().split("\n"):
                parts = line.strip('"').split('","')
                if len(parts) >= 2 and parts[0].lower() == f"{proc_name}.exe".lower():
                    return int(parts[1])
        except Exception:
            pass
        return None

    pid = _find_pid(core_process)
    auto_started = False
    if not pid:
        install_dir = client_cfg.get("install_dir", "")
        if not install_dir or not os.path.exists(install_dir):
            return
        gui_name = client_cfg.get("package", slug)
        exe_name = gui_name + ".exe"
        exe_path = os.path.join(install_dir, exe_name)
        if not os.path.exists(exe_path):
            exe_path = os.path.join(install_dir, exe_name[0].upper() + exe_name[1:])
        if not os.path.exists(exe_path):
            exe_path = _guess_client_exe(install_dir, client_cfg) or exe_path
        if not os.path.exists(exe_path):
            return
        print(f"    [{slug}] 启动客户端: {exe_path}", flush=True)
        _sp.Popen([exe_path], cwd=install_dir)
        for _ in range(30):
            _time.sleep(2)
            pid = _find_pid(core_process)
            if pid:
                break
        if not pid:
            print(f"    [{slug}] 客户端未启动，跳过scan-memory")
            return
        auto_started = True

    # 等待客户端自动登录+拉订阅+连接代理
    # 每10秒扫一次，直到节点数稳定（连续3轮与上一轮相差≤2）或达到上限180秒
    print(f"    [{slug}] 等待客户端{'自动登录+' if auto_started else ''}连接代理（最多180秒）...", flush=True)

    from airmon.memsan import collect_memory_scan
    best_snap = None
    last_n = None
    stable_count = 0
    for wait_round in range(18):
        _time.sleep(10)
        try:
            snap = collect_memory_scan(slug, client_name=core_process,
                                        pid=pid, detector=detector)
            n = len(snap.nodes)
            if n > 0:
                if best_snap is None or n > len(best_snap.nodes):
                    best_snap = snap
                if last_n is not None and abs(n - last_n) <= 2:
                    stable_count += 1
                else:
                    stable_count = 0
                last_n = n
                print(f"    [{slug}] scan-memory 第{wait_round+1}轮: {n}节点（稳定{stable_count}/3）", flush=True)
                if stable_count >= 3:
                    break
            else:
                print(f"    [{slug}] scan-memory 第{wait_round+1}轮: {n}节点", flush=True)
                # 连续 6 轮（约 60 秒）一个节点都没抽到，说明客户端没登录/没连接
                # （或 core 在 Services 会话需提权），继续等满 180 秒纯属浪费。
                if wait_round >= 5 and best_snap is None:
                    print(f"    [{slug}] 连续 6 轮 0 节点，提前放弃等待", flush=True)
                    break
        except Exception:
            pass
    if best_snap is not None:
        _merge_client_nodes(slug, best_snap)
        store.save(best_snap)
        print(f"    [{slug}] ✓ scan-memory 最终: {len(best_snap.nodes)}节点, {count_huawei(best_snap.findings)}华为", flush=True)
    else:
        print(f"    [{slug}] scan-memory: 0节点（客户端可能未连接代理）", flush=True)

    # 关闭客户端 — 可通过 YAML 配置 keep_alive: true 保持客户端运行
    # 适用场景: QQT等需要保持登录态的客户端, 扫描后不关闭, 下次直接读内存
    if client_cfg.get("keep_alive"):
        print(f"    [{slug}] keep_alive=true, 保持客户端运行(不关闭)", flush=True)
    elif not auto_started:
        # 客户端本来就是用户开着的：只读内存，不要把人家的客户端关掉
        print(f"    [{slug}] 客户端由用户启动，扫描后保持运行", flush=True)
    else:
        try:
            _sp.run(["taskkill", "/F", "/IM", f"{core_process}.exe"],
                     capture_output=True, timeout=10)
            gui_name = client_cfg.get("package", slug)
            _sp.run(["taskkill", "/F", "/IM", f"{gui_name}.exe"],
                     capture_output=True, timeout=10)
        except Exception:
            pass


def _clear_closed(slug: str):
    """这一轮拉成功了，就把 sub_closed.json 里的关闭标记删掉。"""
    import json as _json
    path = os.path.join(store.DATA_DIR, "sub_closed.json")
    if not os.path.exists(path):
        return
    try:
        with io.open(path, encoding="utf-8") as fh:
            cur = _json.load(fh)
        if isinstance(cur, dict) and slug in cur:
            cur.pop(slug, None)
            with io.open(path, "w", encoding="utf-8") as fh:
                fh.write(_json.dumps(cur, ensure_ascii=False, indent=1))
    except Exception:
        pass


def _record_closed(slug: str, msg: str):
    """把「订阅开关关闭」这种非故障状态记到 data/sub_closed.json。

    它不进 failed 统计：机场没坏、脚本没坏，只是订阅处在关闭窗口里。
    面板读这个文件，把卡片标成「订阅关闭中 · 去面板开启」。
    """
    import json as _json
    from datetime import datetime as _dt
    path = os.path.join(store.DATA_DIR, "sub_closed.json")
    try:
        with io.open(path, encoding="utf-8") as fh:
            cur = _json.load(fh)
    except Exception:
        cur = {}
    if not isinstance(cur, dict):
        cur = {}
    cur[slug] = {"at": _dt.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"), "reason": msg[:200]}
    try:
        with io.open(path, "w", encoding="utf-8") as fh:
            fh.write(_json.dumps(cur, ensure_ascii=False, indent=1))
    except Exception:
        pass


def _finish(slug: str, snap, kind: str):
    from collections import Counter
    _clear_closed(slug)
    path = store.save(snap)
    print(f"[成功] {slug} ({kind}): {len(snap.nodes)} 节点, "
          f"{count_huawei(snap.findings)} 华为命中")
    if not snap.nodes:
        print(f"    ⚠ 0 节点：订阅链接可能失效/token 错误/被反爬挡了，请核对")
    if VERBOSE and snap.nodes:
        protos = Counter(n.protocol for n in snap.nodes)
        vend = Counter(); resolved = 0
        for n in snap.nodes:
            ips = n.raw.get("_resolved_ips") or []
            if ips:
                resolved += 1
            for ip in ips:
                info = (n.raw.get("_rdap") or {}).get(ip)
                if info and not (info[1] or info[0] or "").startswith("n/a"):
                    vend[(info[1] or info[0])[:24]] += 1
        print(f"    协议: {' '.join(f'{k}×{v}' for k,v in protos.most_common(4))}")
        print(f"    落地: {'; '.join(f'{o}×{c}' for o,c in vend.most_common(3)) or '(server未解析)'}"
              f"  | 解析 {resolved}/{len(snap.nodes)}")
        for n in snap.nodes[:3]:
            print(f"      · {n.name[:22]:<24} {n.protocol} {n.server}:{n.port}")
        if snap.findings:
            for f in snap.findings:
                print(f"    ⚠️华为: {f.dimension}={f.rule} | {f.evidence} | {f.context}")
    emit(slug, snap.findings, store.diff_latest(slug))

def _pull_one(slug: str, cred: dict, detector: Detector):
    # 优先级 -2: Velochron 无客户端 API 路线 (2026-09-17 逆向: 登录→getSubscribe→AES-GCM解密)
    # 完全复刻客户端协议, 无需启动客户端/DPAPI/内存扫描
    if cred.get("type") == "velochron-api" or slug == "velochron":
        try:
            from airmon.velo_api import collect_velo_api
            email = cred.get("email") or load_credentials().get("defaults", {}).get("email")
            password = cred.get("password") or load_credentials().get("defaults", {}).get("password")
            if email and password:
                print(f"    [{slug}] 尝试无客户端API路线 (velo_api)...", flush=True)
                snap = collect_velo_api(slug, email, password, detector)
                if snap.nodes:
                    print(f"    [{slug}] ✓ 无客户端API: {len(snap.nodes)}节点")
                    _finish(slug, snap, "velo-api")
                    return
                print(f"    [{slug}] velo_api 0 节点, 继续其他方式")
        except Exception as e:
            print(f"    [{slug}] velo_api 失败({str(e)[:60]}), 继续其他方式")

    # 优先级 -1.5: 持久化扫描 — 客户端常驻运行, 直接读内存(不启动/不关闭)
    # YAML配置: client.persistent: true + client.core_process: 进程名
    client_cfg = cred.get("client") or _get_client_config(slug) or {}
    if client_cfg.get("persistent"):
        proc = client_cfg.get("core_process", "")
        if proc:
            try:
                from airmon.persistent import find_process_pid, scan_persistent
                if find_process_pid(proc):
                    snap = scan_persistent(slug, detector, process_name=proc)
                    if snap and snap.nodes:
                        _finish(slug, snap, 'persistent-scan')
                        return
                else:
                    print(f"    [{slug}] {proc}.exe未运行 — 请手动启动", flush=True)
                    return
            except Exception as e:
                print(f"    [{slug}] persistent异常: {e}")
                return

    # 优先级 -1: DPAPI 订阅缓存解密（Velochron 等设备认证锁订阅的客户端）
    # server/fetch 只给节点元数据、subscribe_url 对非认证客户端 404，
    # 但客户端本机 DPAPI 缓存里有完整节点配置，同用户可直接解密。
    dpapi_cfg = (cred.get("client") or {}).get("dpapi_file") or \
                (_get_client_config(slug) or {}).get("dpapi_file")
    if dpapi_cfg:
        try:
            from airmon.dpapi import collect_dpapi
            client_cfg = cred.get("client") or _get_client_config(slug)
            print(f"    [{slug}] 尝试 DPAPI 订阅缓存: {dpapi_cfg} ...", flush=True)
            snap = collect_dpapi(slug, client_cfg, detector)
            if snap.nodes:
                print(f"    [{slug}] ✓ DPAPI 缓存: {len(snap.nodes)}节点")
                _finish(slug, snap, "dpapi-cache")
                return
            print(f"    [{slug}] DPAPI 缓存 0 节点，继续其他方式")
        except Exception as e:
            print(f"    [{slug}] DPAPI 缓存失败({str(e)[:60]})，继续其他方式")

    # 优先级 0: v2board server/fetch（仅对v2board/auto类型，跳过sspanel/whmcs）
    cred_type = cred.get("type", "auto")
    if cred_type in ("v2board", "auto", None):
        panel = cred.get("panel") or _resolve_panel(slug, None)[0]
        if not (panel and cred.get("email") and cred.get("password")):
            print(f"    [{slug}] 未填面板地址/账号，跳过 server/fetch（走订阅或客户端）")
        else:
            print(f"    [{slug}] 尝试 server/fetch API: {panel} ...", flush=True)
            from airmon.collect import collect_server_fetch
            try:
                snap = collect_server_fetch(slug, panel, cred["email"],
                                            cred["password"], detector)
                if snap.nodes:
                    print(f"    [{slug}] ✓ server/fetch成功: {len(snap.nodes)}节点")
                    _finish(slug, snap, "server-fetch")
                    return
                else:
                    print(f"    [{slug}] server/fetch返回0节点，尝试其他方式")
            except Exception as e:
                print(f"    [{slug}] server/fetch失败({str(e)[:50]})，尝试其他方式")

    # 优先级 1: sub_url直抓（成功就用它，失败继续走登录/客户端兜底）
    if cred.get("sub_url"):
        print(f"    [{slug}] 抓取订阅: {cred['sub_url'][:60]} ...", flush=True)
        # 瞬时网络错误（连接重置/超时/分块截断）重试一次：夜间代理抖动时这类失败
        # 会把本可成功的机场误判成失败，实测每轮额外损失 5~7 家。
        import time as _time
        import requests as _rq
        transient_types = (getattr(_rq.exceptions, "ConnectionError", ()),
                           getattr(_rq.exceptions, "Timeout", ()),
                           getattr(_rq.exceptions, "ChunkedEncodingError", ()))
        snap = None
        last_err = None
        from airmon.login import SubscriptionClosed as _SubClosed
        closed = False
        opened = False
        for attempt in (1, 2):
            try:
                snap = collect_from_url(slug, cred["sub_url"], detector,
                                        cred.get("user_agent", "clash.meta"))
                break
            except _SubClosed as e:
                # 限时订阅开关（如 ss-id）：链接默认关闭、开启后 10 分钟有效，但 token 不变，
                # 所以只要用面板的 auth_token 把开关打开，原链接立刻能拉。开一次就够，不反复试。
                last_err = e
                if not opened:
                    opened = True
                    try:
                        from airmon.subopen import open_for as _open_sub
                        _ok, _msg, _ = _open_sub(slug, cred)
                    except Exception as _oe:
                        _ok, _msg, _ = False, str(_oe)[:60]
                    if _ok:
                        print(f"    [{slug}] 订阅是限时开关，已自动开启（{_msg}），立刻重拉", flush=True)
                        continue
                    print(f"    [{slug}] 订阅关闭，自动开启失败：{_msg}", flush=True)
                closed = True
                break
            except Exception as e:
                last_err = e
                transient = isinstance(e, transient_types) if transient_types != ((),) else False
                if attempt == 1 and transient:
                    print(f"    [{slug}] 订阅瞬时失败({str(e)[:40]})，2秒后重试一次", flush=True)
                    _time.sleep(2)
                    continue
                break
        if snap is not None:
            _finish(slug, snap, "manual-url")
            return  # sub_url成功就结束，不需要再启动客户端
        if closed:
            print(f"    [{slug}] 订阅关闭中（面板上的订阅开关限时，需重新开启），跳过登录尝试")
            _record_closed(slug, str(last_err))
            return
        print(f"    [{slug}] 订阅URL失败({str(last_err)[:50]})，尝试面板登录...")
        # 继续走下面的登录流程

    # 优先级 2: cookie遍历节点页
    if cred.get("cookie"):
        base = cred.get("base") or cred.get("panel") or _resolve_panel(slug, None)[0]
        if not base:
            print(f"[跳过] {slug}: 有 cookie 但缺 base（填该机场后台域名）")
            return
        print(f"    [{slug}] cookie遍历节点页: {base} ...", flush=True)
        try:
            snap = collect_node_pages(slug, base, cred["cookie"], detector,
                                      max_id=cred.get("max_id", 300))
        except Exception as e:
            print(f"[失败] {slug} cookie节点页: {e}")
            return
        if not snap.nodes:
            print(f"[失败] {slug}: cookie 没抽到节点")
            return
        _finish(slug, snap, "node-page-cookie")
        return

    # 优先级 3: email+password登录（含seeds域名回退）
    if not cred.get("email") or not cred.get("password"):
        print(f"[跳过] {slug}: 无 sub_url 且缺 email/password")
        # 如果有client配置，走scan-memory兜底
        client_cfg = cred.get("client") or _get_client_config(slug)
        if client_cfg:
            print(f"    [{slug}] 尝试客户端scan-memory兜底...")
            _do_scan_memory(slug, client_cfg, detector)
        return
    print(f"    [{slug}] email+pass登录，探测可用面板...", flush=True)
    panel, source = _try_all_panels(slug, cred)
    if not panel:
        print(f"[跳过] {slug}: {source}（在 credentials.yaml 指定 panel 或 sub_url）")
        # 如果有client配置，走scan-memory兜底
        client_cfg = cred.get("client") or _get_client_config(slug)
        if client_cfg:
            print(f"    [{slug}] 尝试客户端scan-memory兜底...")
            _do_scan_memory(slug, client_cfg, detector)
        return
    detected_type = cred.get("type")
    if not detected_type or detected_type == "auto":
        detected_type = None
    print(f"    [{slug}] 抓取订阅节点: {panel} ...", flush=True)
    try:
        snap, sub_url, kind = collect_login(slug, panel, cred["email"],
                                            cred["password"], detector, detected_type or "auto")
    except LoginError as e:
        print(f"[失败] {slug} @ {panel}: {e}（反爬/验证码机场可在 credentials.yaml 填 sub_url 兜底）")
        # 如果有client配置，走scan-memory兜底
        client_cfg = cred.get("client") or _get_client_config(slug)
        if client_cfg:
            print(f"    [{slug}] 尝试客户端scan-memory兜底...")
            _do_scan_memory(slug, client_cfg, detector)
        return
    except Exception as e:
        print(f"[失败] {slug} @ {panel}: 登录后抓订阅出错: {e}")
        # 如果有client配置，走scan-memory兜底
        client_cfg = cred.get("client") or _get_client_config(slug)
        if client_cfg:
            print(f"    [{slug}] 尝试客户端scan-memory兜底...")
            _do_scan_memory(slug, client_cfg, detector)
        return
    _finish(slug, snap, kind)

def cmd_pull(args):
    global VERBOSE
    VERBOSE = getattr(args, "verbose", False)
    try:
        creds = load_credentials()
    except FileNotFoundError as e:
        print(e)
        return
    detector = Detector()
    # 支持一个或多个机场（逗号分隔）
    if args.airport:
        slugs = [s.strip() for s in args.airport.split(",") if s.strip()]
        unknown = [s for s in slugs if s not in creds]
        if unknown:
            print(f"credentials.yaml 里没有: {', '.join(unknown)}")
            return
        total = len(slugs)
        for i, slug in enumerate(slugs, 1):
            print(f"[{i}/{total}] 正在拉取 {slug} ...", flush=True)
            _pull_one(slug, creds[slug], detector)
    else:
        import threading
        total = len(creds)
        for i, (slug, cred) in enumerate(creds.items(), 1):
            print(f"[{i}/{total}] 正在拉取 {slug} ...", flush=True)
            t = threading.Thread(target=_pull_one, args=(slug, cred, detector),
                                 daemon=True)
            t.start()
            t.join(300)
            if t.is_alive():
                print(f"[跳过] {slug}: 超时(>300s)，跳过（该机场服务器无响应）")

def cmd_ingest_page(args):
    with open(args.file, encoding="utf-8", errors="replace") as f:
        text = f.read()
    snap = collect_page(args.airport, text, Detector())
    if not snap.nodes:
        print(f"[失败] {args.airport}: 页面里没抽到节点")
        return
    store.save(snap)
    _finish(args.airport, snap, "node-page")

def cmd_scan_client(args):
    snap, sub_urls = collect_client(args.airport, args.dir, Detector())
    if sub_urls:
        print(f"  发现内嵌订阅链接 {len(sub_urls)} 条：")
        for u in sub_urls:
            print(f"    {u}")
    if not snap.nodes:
        print(f"[失败] {args.airport}: 数据目录里没解析到节点"
              f"（确认 --dir 指向客户端数据目录，且客户端已拉过订阅）")
        return
    store.save(snap)
    _finish(args.airport, snap, "client-dir")

def cmd_ingest_cookie(args):
    cookie = args.cookie
    if args.cookie_file:
        with open(args.cookie_file, encoding="utf-8") as f:
            cookie = f.read().strip()
    if not cookie:
        print("需要 --cookie 或 --cookie-file")
        return
    snap = collect_node_pages(args.airport, args.base, cookie, Detector(),
                              max_id=args.max_id)
    if not snap.nodes:
        print(f"[失败] {args.airport}: 没抽到节点")
        return
    store.save(snap)
    _finish(args.airport, snap, "node-page-cookie")

def cmd_watch(args):
    import time
    airport = get_airport(args.airport)
    detector = Detector()
    last = 0.0
    print(f"[watch] 监视 {args.file}，每 {args.interval}s 检查一次，Ctrl-C 停止")
    checks = 0
    while True:
        try:
            m = os.path.getmtime(args.file)
        except OSError:
            m = 0.0
        if m and m != last:
            last = m
            try:
                snap = collect_profile(airport, args.file, detector, index_path=args.index)
                store.save(snap)
                print(f"[watch] {time.strftime('%H:%M:%S')} 检测到更新 → "
                      f"{len(snap.nodes)} 节点, {count_huawei(snap.findings)} 华为命中")
                emit(args.airport, snap.findings, store.diff_latest(args.airport))
            except Exception as e:
                print(f"[watch] 摄入出错: {e}")
        checks += 1
        if args.max_checks and checks >= args.max_checks:
            break
        time.sleep(args.interval)

# ---- Windows 客户端型新命令 ----

def cmd_scan_win_client(args):
    """扫 Windows 客户端数据目录：提取订阅URL/API域名/账号，尝试抓节点。"""
    from airmon.winclient import collect_win_client
    detector = Detector()
    snap, meta = collect_win_client(args.airport, args.dir, detector,
                                     app_dir=args.app_dir)
    # 输出元数据
    if meta.get("sub_urls"):
        print(f"发现订阅链接 {len(meta['sub_urls'])} 条：")
        for u in meta["sub_urls"]:
            print(f"  {u}")
    if meta.get("api_urls"):
        print(f"发现 API 域名 {len(meta['api_urls'])} 条：")
        for u in set(meta["api_urls"]):
            print(f"  {u}")
    if meta.get("email"):
        print(f"账号: {meta['email']}")
    if meta.get("config_encrypted") is not None:
        print(f"配置文件: {'加密' if meta.get('config_encrypted') else '明文'}, "
              f"大小 {meta.get('config_size', 0)} bytes")
    if meta.get("profiles"):
        print(f"数据库 profiles: {len(meta['profiles'])} 条")
        for p in meta["profiles"]:
            print(f"  id={p['id']} url={p.get('url', '')[:80]}")

    if snap.nodes:
        store.save(snap)
        _finish(args.airport, snap, "win-client")
    else:
        print(f"[提示] {args.airport}: 未直接获取到节点")
        if meta.get("config_encrypted"):
            print("  配置文件已加密，建议：")
            print(f"  1. python3 run.py scan-memory --airport {args.airport} "
                  f"--client {args.airport.replace('wdy','wandacloud')}")
            print(f"  2. python3 run.py monitor-net --airport {args.airport} "
                  f"--client {args.airport.replace('wdy','wandacloud')} --watch")
        elif meta.get("sub_urls"):
            print("  有订阅链接但抓取失败，可能被反爬，建议：")
            print(f"  python3 run.py collect --airport {args.airport}")
        store.save(snap)

def cmd_scan_persistent(args):
    """持久化扫描: qqt.exe常驻运行, 只读内存不启动/不关闭客户端。
    适用于部署到监控机: 手动登录一次QQT, 之后全自动。"""
    from airmon.persistent import scan_persistent
    detector = Detector()
    snap = scan_persistent(args.airport, detector)
    if snap and snap.nodes:
        path = store.save(snap)
        print(f"[成功] {args.airport} (persistent): {len(snap.nodes)} 节点 → {path}")
        emit(args.airport, snap.findings, store.diff_latest(args.airport))
    else:
        print(f"[提示] {args.airport}: 持久化扫描未获取到节点")
        print("  确认: 1)qqt.exe正在运行  2)已登录  3)已连接任意节点")


def cmd_scan_clients(args):
    """只扫有客户端配置的机场（scan-memory），跳过pull登录。需管理员权限。"""
    global VERBOSE
    VERBOSE = getattr(args, "verbose", False)
    detector = Detector()
    creds = load_credentials()
    
    # 收集有client配置的机场
    targets = []
    if args.airport:
        for slug in args.airport.split(","):
            slug = slug.strip()
            if not slug: continue
            client_cfg = creds.get(slug, {}).get("client") or _get_client_config(slug)
            if client_cfg:
                targets.append((slug, client_cfg))
            else:
                print(f"[跳过] {slug}: 无client配置")
    else:
        checked = set()
        for slug, cred in creds.items():
            if slug in checked: continue
            checked.add(slug)
            client_cfg = cred.get("client") or _get_client_config(slug)
            if client_cfg and client_cfg.get("core_process"):
                targets.append((slug, client_cfg))
        from airmon.config import load_airports
        apts = load_airports()
        for slug, apt in apts.items():
            if slug in checked: continue
            if apt.get("type") != "client" or not apt.get("enabled"):
                continue
            client_cfg = apt.get("client")
            if client_cfg and client_cfg.get("core_process"):
                targets.append((slug, client_cfg))
    
    print(f"客户端型机场: {len(targets)}个\n")
    for i, (slug, cfg) in enumerate(targets, 1):
        print(f"[{i}/{len(targets)}] {slug} (core={cfg.get('core_process','')})")
        _do_scan_memory(slug, cfg, detector)
    print(f"\n完成: 扫了{len(targets)}个客户端型机场")


def cmd_scan_memory(args):
    """从 Clash 内核进程内存扫描提取节点（需管理员权限）。

    自动流程：查找进程 → 不在则自动启动客户端 → 等待连接 → 扫描 → 关闭。
    """
    from airmon.memsan import collect_memory_scan
    import subprocess as _sp
    import time as _time
    detector = Detector()
    client_name = args.client or args.airport

    # 优先级 0：离线解包（DOVE 的 DOVE.tauri.dat）。
    # 不用启动客户端、不需要管理员权限，还能拿到带 uuid/reality-opts 的完整节点；
    # 内存扫描对这类客户端只能捞到 IP:端口 碎片。解包不成就照旧往下走。
    try:
        from airmon import dovex as _dovex
        _cfg = {}
        try:
            _cfg = (get_airport(args.airport) or {}).get("client") or {}
        except Exception:
            _cfg = {}
        if _dovex.available(_cfg, args.airport):
            print("先试离线解包 DOVE.tauri.dat（不用启动客户端）...", flush=True)
            _r = _dovex.extract(args.airport, _cfg)
            if _r.get("ok") and _r.get("count"):
                print(f"解包成功：{_r['count']} 节点 {_r['protos']}，bundle={_r['bundle_name']}", flush=True)
                if _nodes_from_bundle(args.airport, _r, detector):
                    return
            else:
                print(f"离线解包失败（{_r.get('error', '')[:60]}），改用内存扫描", flush=True)
    except Exception as _e:  # noqa: BLE001
        print(f"离线解包异常（{str(_e)[:60]}），改用内存扫描", flush=True)

    # 优先级 0.5：抓包缓存（青云梯）
    try:
        from airmon import qingyunti as _qyt
        if _qyt.available(args.airport, _cfg):
            print("抓取青云梯配置（约 40 秒：拉起客户端 → 拦截内核配置 → 自动收尾）…",
                  flush=True)
            _r2 = _qyt.prepare(args.airport, _cfg)
            if _r2.get("ok") and _r2.get("count"):
                _via = "实时抓取" if _r2.get("via") == "capture" else "抓包缓存"
                if _r2.get("via") == "cache-fallback":
                    print(f"⚠ 实时抓取失败（{str(_r2.get('capture_error'))[:70]}），"
                          f"退回旧缓存 —— 这些节点的 SNI 可能已过期", flush=True)
                print(f"用{_via}：{_r2['count']} 节点，抓于 {_r2['captured_at']}"
                      f"（{_r2['age_hours']} 小时前）"
                      + ("，已超 %d 小时建议重抓" % _qyt.STALE_HOURS if _r2.get("stale") else ""),
                      flush=True)
                if _nodes_from_bundle(args.airport, _r2, detector):
                    return
    except Exception as _e:  # noqa: BLE001
        print(f"抓包缓存不可用（{str(_e)[:60]}），继续内存扫描", flush=True)

    # 优先级 0.6：wandacloud / 万达云（含 wdy）YAML 解析入口 dump（约 45-60 秒，免提权）
    try:
        from airmon import wandacloud as _wd
        if _wd.available(args.airport, _cfg):
            print("抓取万达云配置（约 45-60 秒：Frida 截内核 YAML 解析入参）…", flush=True)
            _rd2 = _wd.prepare(args.airport, _cfg)
            if _rd2.get("ok") and _rd2.get("count"):
                _vd2 = "实时抓取" if _rd2.get("via") == "capture" else "抓包缓存"
                if _rd2.get("via") == "cache-fallback":
                    print(f"\u26a0 实时抓取失败（{str(_rd2.get('capture_error'))[:70]}），退回旧缓存",
                          flush=True)
                print(f"用{_vd2}：{_rd2['count']} 节点，抓于 {_rd2['captured_at']}"
                      f"（{_rd2['age_hours']} 小时前）", flush=True)
                if _nodes_from_bundle(args.airport, _rd2, detector):
                    return
    except Exception as _e:  # noqa: BLE001
        print(f"万达云抓取不可用（{str(_e)[:60]}），继续内存扫描", flush=True)

    # 优先级 0.55：hhy（好好云）本地 RPC 抓取（约 2-3 秒，免提权）
    try:
        from airmon import hhy as _hhy
        if _hhy.available(args.airport, _cfg):
            print("抓取好好云配置（约 2-3 秒：Frida 截内核 RPC 帧 → 自动收尾）…",
                  flush=True)
            _r3 = _hhy.prepare(args.airport, _cfg)
            if _r3.get("ok") and _r3.get("count"):
                _v3 = "实时抓取" if _r3.get("via") == "capture" else "抓包缓存"
                if _r3.get("via") == "cache-fallback":
                    print(f"⚠ 实时抓取失败（{str(_r3.get('capture_error'))[:70]}），退回旧缓存",
                          flush=True)
                print(f"用{_v3}：{_r3['count']} 节点，抓于 {_r3['captured_at']}"
                      f"（{_r3['age_hours']} 小时前）", flush=True)
                if _nodes_from_bundle(args.airport, _r3, detector):
                    return
    except Exception as _e:  # noqa: BLE001
        print(f"好好云抓包不可用（{str(_e)[:60]}），继续内存扫描", flush=True)

    def _find_pid(proc_name):
        try:
            # tasklist 输出是 GBK；不能用 text=True（本机 utf-8 模式会 UnicodeDecodeError）
            r = _sp.run(["tasklist", "/FI", f"IMAGENAME eq {proc_name}.exe",
                         "/FO", "CSV", "/NH"],
                        capture_output=True, timeout=10)
            out = (r.stdout or b"").decode("gbk", "replace")
            for line in out.strip().split("\n"):
                parts = line.strip('"').split('","')
                if len(parts) >= 2 and parts[0].lower() == f"{proc_name}.exe".lower():
                    return int(parts[1])
        except Exception:
            pass
        return None

    # 确定 core_process 名
    core_process = client_name
    if not args.pid:
        try:
            apt = get_airport(args.airport)
            core_process = apt.get("client", {}).get("core_process", client_name)
        except Exception:
            pass

    pid = args.pid

    # 没有PID → 查找进程 → 不在则自动启动
    if not pid:
        pid = _find_pid(core_process)

    if not pid:
        # 从 airports.yaml 找 install_dir 自动启动
        try:
            apt = get_airport(args.airport)
            install_dir = apt.get("client", {}).get("install_dir", "")
            gui_name = apt.get("client", {}).get("package", args.airport)
        except Exception:
            install_dir = ""
            gui_name = args.airport

        if install_dir and os.path.exists(install_dir):
            exe_name = gui_name + ".exe"
            exe_path = os.path.join(install_dir, exe_name)
            if not os.path.exists(exe_path):
                exe_path = os.path.join(install_dir, exe_name[0].upper() + exe_name[1:])
            if not os.path.exists(exe_path):
                exe_path = _guess_client_exe(install_dir, {"core_process": core_process}) or exe_path

            if os.path.exists(exe_path):
                print(f"启动客户端: {exe_path}")
                launched_by_us = True
                _sp.Popen([exe_path], cwd=install_dir)
                print(f"等待 {core_process} 启动（最多60秒）...")
                for _ in range(30):
                    _time.sleep(2)
                    pid = _find_pid(core_process)
                    if pid:
                        print(f"{core_process}.exe PID={pid}")
                        break
                if not pid:
                    print(f"[失败] {args.airport}: {core_process} 60秒内未启动")
                    return
                # 等待连接代理
                print("等待客户端连接代理（10秒）...")
                _time.sleep(10)
            else:
                print(f"[失败] {args.airport}: 找不到 {exe_path}")
                return
        else:
            print(f"[失败] {args.airport}: 未找到 {core_process} 进程，且 install_dir 不可用")
            print(f"  请手动启动客户端后重试，或指定 --pid")
            return

    print(f"扫描 {core_process}.exe (PID {pid}) 内存...")
    try:
        snap = collect_memory_scan(args.airport, client_name=core_process,
                                    pid=pid, detector=detector)
    except RuntimeError as e:
        print(f"[失败] {args.airport}: {e}")
        return

    # 输出扫描元数据
    for proc in snap.meta.get("processes", []):
        if "error" in proc:
            print(f"  {proc['name']} (PID {proc['pid']}): {proc['error']}")
        else:
            print(f"  {proc['name']} (PID {proc['pid']}): "
                  f"{proc.get('regions', 0)} regions, {proc.get('total_mb', 0)} MB, "
                  f"{proc.get('items_found', 0)} items found")

    if snap.nodes:
        store.save(snap)
        _finish(args.airport, snap, "memory-scan")
    else:
        print(f"[失败] {args.airport}: 内存中未提取到节点")
        print("  可能原因：")
        print("  1. 需要管理员权限运行（OpenProcess error 5）")
        print("  2. 客户端未连接代理（启动客户端并点连接后重试）")
        print("  3. 节点格式未被搜索模式匹配（检查客户端类型）")
        print("  建议：python3 run.py monitor-net --airport", args.airport,
              "--client", core_process, "--watch")

    # 自动关闭客户端：**仅**当它是由本命令启动的。用户自己开着的别杀。
    if not args.pid and locals().get("launched_by_us"):
        try:
            _sp.run(["taskkill", "/F", "/IM", f"{core_process}.exe"],
                     capture_output=True, timeout=10)
            _gui = locals().get("gui_name", args.airport)
            _sp.run(["taskkill", "/F", "/IM", f"{_gui}.exe"],
                     capture_output=True, timeout=10)
            print(f"已关闭 {_gui} + {core_process}")
        except Exception:
            pass

def cmd_monitor_net(args):
    """监控客户端 TCP 连接提取代理 IP:端口。"""
    from airmon.netmon import collect_network_scan, watch_network
    detector = Detector()
    client_name = args.client or args.airport

    if args.watch:
        watch_network(args.airport, client_name=client_name, pid=args.pid,
                      interval=args.interval, max_scans=args.max_scans,
                      detector=detector)
    else:
        try:
            snap = collect_network_scan(args.airport, client_name=client_name,
                                        pid=args.pid, detector=detector)
        except RuntimeError as e:
            print(f"[失败] {args.airport}: {e}")
            return

        if snap.nodes:
            store.save(snap)
            _finish(args.airport, snap, "network-monitor")
        else:
            print(f"[失败] {args.airport}: 未捕获到代理连接")
            print("  请确认客户端已启动并连接代理")
            print(f"  或使用 --watch 持续监控: python3 run.py monitor-net "
                  f"--airport {args.airport} --client {client_name} --watch")

def cmd_auto_scan(args):
    """一键采集：数据目录扫描 + 网络监控 + 内存扫描 + 富化 + 保存。"""
    from airmon.autoscan import cmd_auto_scan as _do_auto_scan
    _do_auto_scan(args)


def cmd_report(args):
    if args.pull:
        creds = load_credentials()
        detector = Detector()
        import threading
        for slug, cred in creds.items():
            t = threading.Thread(target=_pull_one, args=(slug, cred, detector), daemon=True)
            t.start(); t.join(300)
            if t.is_alive():
                print(f"[跳过] {slug}: 超时")
        for slug in [os.path.basename(d.rstrip("/").rstrip("\\")) for d in
                     __import__("glob").glob(os.path.join(store.DATA_DIR, "*/"))]:
            snap = rescan_airport(slug, detector)
            if snap:
                store.save(snap)
    path = report_mod.generate(args.out)
    print(f"报告已生成 → {path}")

def _latest_snap_name(slug: str):
    """该机场最新快照文件名（判「本轮是否落地新数据」用）；无快照返回 None。"""
    snaps = sorted(glob.glob(os.path.join(store.DATA_DIR, slug, "*.json")))
    return os.path.basename(snaps[-1]) if snaps else None


def _pid_alive(pid: int) -> bool:
    """Windows 安全探活：绝不能用 os.kill(pid, 0)（Windows 语义=TerminateProcess，会把对方杀掉）。"""
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        try:
            code = ctypes.c_ulong()
            if k32.GetExitCodeProcess(h, ctypes.byref(code)):
                return code.value == 259  # STILL_ACTIVE
            return True
        finally:
            k32.CloseHandle(h)
    except Exception:
        return False


def _acquire_run_lock(lock_path: str, started_iso: str):
    """单实例锁：调度器每 3h 的 all 与手动/面板触发不得并发（store.save 非原子，双写互相踩）。
    返回 True=拿到锁，False=已有实例在跑（本轮应直接退出）。"""
    import json as _json
    if os.path.exists(lock_path):
        prev = {}
        try:
            with open(lock_path, encoding="utf-8") as f:
                prev = _json.load(f)
        except Exception:
            prev = {}
        pid = prev.get("pid")
        if pid and _pid_alive(pid):
            print(f"[跳过] 已有 run.py all 在跑（pid={pid}，起于 {prev.get('at')}）→ 本轮退出，避免并发写坏快照")
            return False
        print(f"[提示] 清理残留锁（pid={pid} 已不在）")
    try:
        with open(lock_path, "w", encoding="utf-8") as f:
            _json.dump({"pid": os.getpid(), "at": started_iso}, f)
    except Exception as e:
        print(f"[锁写入失败，忽略] {e}")
    return True


def _pull_one_safe(slug: str, cred: dict, detector: Detector, box: dict):
    """线程目标包装：异常落 box 而不是被 threading 吞掉（统计失真修复的一半）。"""
    try:
        _pull_one(slug, cred, detector)
    except Exception as e:
        box["err"] = f"{type(e).__name__}: {e}"


# ── 轮次心跳：给看门狗/面板用（last_run.json 只在起手和收尾写，中间被杀就看不出来） ──
_HB_STATE = {"step": None, "done": None, "total": None, "airport": None, "started": None, "epoch": 0.0}


def _heartbeat(step=None, done=None, total=None, airport=None, force=False):
    """把当前轮次进度写进 data/run_heartbeat.json（节流 5 秒）。

    为什么单独一个文件：last_run.json 只在起手/收尾写，进程被硬杀时它永远停在
    status=running，看不出「死在哪一步、多久没动了」。心跳每步/每机场更新，
    外部（tools/watchdog.py、面板 /api/status）超过 90 分钟没见更新即可判定卡死。
    """
    import json as _json
    import time as _time
    try:
        now = _time.time()
        if not force and now - _HB_STATE.get("epoch", 0.0) < 5:
            return
        _HB_STATE["epoch"] = now
        if step is not None:
            _HB_STATE["step"] = step
        if done is not None:
            _HB_STATE["done"] = done
        if total is not None:
            _HB_STATE["total"] = total
        if airport is not None:
            _HB_STATE["airport"] = airport
        if not _HB_STATE.get("started"):
            _HB_STATE["started"] = store.now_iso()
        payload = {
            "pid": os.getpid(),
            "started_at": _HB_STATE["started"],
            "updated_at": store.now_iso(),
            "epoch": int(now),
            "step": _HB_STATE.get("step"),
            "done": _HB_STATE.get("done"),
            "total": _HB_STATE.get("total"),
            "airport": _HB_STATE.get("airport"),
        }
        path = os.path.join(store.DATA_DIR, "run_heartbeat.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            _json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception:
        pass


def _heartbeat_done():
    """本轮正常收尾：删掉心跳文件（存在=还在跑，不存在=没在跑）。"""
    try:
        path = os.path.join(store.DATA_DIR, "run_heartbeat.json")
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def _append_run_history(last: dict, keep: int = 60) -> None:
    """把本轮摘要追加到 data/runs.json（面板「运行记录」读它）。

    为什么另开一个文件：last_run.json 每次覆盖，只能看见最后一轮；
    用户要看的是「几点跑的、跑成什么样、最近几轮的趋势」。
    """
    import json  # run.py 顶层没有 import json（只在 cmd_all 内部局部导入过）
    try:
        p = os.path.join(store.DATA_DIR, "runs.json")
        hist = []
        if os.path.exists(p):
            try:
                with open(p, encoding="utf-8") as f:
                    hist = json.load(f) or []
                if not isinstance(hist, list):
                    hist = []
            except (OSError, ValueError):
                hist = []
        item = {
            "started_at": last.get("started_at"),
            "ended_at": last.get("ended_at"),
            "duration_s": last.get("duration_s"),
            "status": last.get("status"),
            "pull_ok": last.get("pull_ok"),
            "pull_fail": last.get("pull_fail"),
            "client_scanned": last.get("client_scanned"),
            "airports_active": last.get("airports_active"),
            "nodes_total": last.get("nodes_total"),
            "hw_findings": last.get("hw_findings"),
            "stale_n": len(last.get("stale_over_6h") or []),
            "failed": (last.get("failed") or [])[:60],
            "trigger": last.get("trigger") or "scheduled",
            "note": last.get("note"),
        }
        # 同 started_at 覆盖（重跑/补写时不产生两条）
        hist = [h for h in hist if h.get("started_at") != item["started_at"]]
        hist.append(item)
        hist = hist[-keep:]
        with open(p, "w", encoding="utf-8") as f:
            json.dump(hist, f, ensure_ascii=False, indent=2)
    except Exception as _e:  # noqa: BLE001
        print(f"[runs.json 写入失败，忽略] {_e}")


def cmd_all(args):
    global VERBOSE
    VERBOSE = getattr(args, "verbose", False)
    import threading, glob, json, time as _time
    from collections import Counter
    started_iso = store.now_iso()
    t0 = _time.time()
    # 起手即刻写 running 心跳：若本轮崩溃/被杀，last_run.json 至少留下 status=running 的指纹，
    # 不会再出现「任务每 3h 触发、面板数据停在几天前、却无任何失败痕迹」的假绿。
    _ledger = os.path.join(store.DATA_DIR, "last_run.json")
    try:
        with open(_ledger, "w", encoding="utf-8") as _f:
            json.dump({"status": "running", "started_at": started_iso,
                       "pid": os.getpid(), "step": "1/5 拉取"}, _f,
                      ensure_ascii=False, indent=2)
    except Exception:
        pass
    _lock = os.path.join(store.DATA_DIR, "run.lock")
    if not _acquire_run_lock(_lock, started_iso):
        return 0
    creds = load_credentials()
    detector = Detector()
    total = len(creds)
    _heartbeat(step="1/5 拉取订阅", done=0, total=total, force=True)
    print(f"=== 1/5 拉取所有机场 (共{total}个) ===")
    ok, fail = 0, 0
    failed: list[tuple[str, str]] = []
    for i, (slug, cred) in enumerate(creds.items(), 1):
        print(f"[{i}/{total}] 正在拉取 {slug} ...", flush=True)
        _heartbeat(step="1/5 拉取订阅", done=i - 1, total=total, airport=slug, force=True)
        before = _latest_snap_name(slug)
        box: dict = {}
        t = threading.Thread(target=_pull_one_safe, args=(slug, cred, detector, box), daemon=True)
        t.start(); t.join(300)
        after = _latest_snap_name(slug)
        if t.is_alive():
            print(f"[跳过] {slug}: 超时")
            fail += 1; failed.append((slug, "timeout(300s)"))
        elif box.get("err"):
            print(f"[失败] {slug}: {box['err']}")
            fail += 1; failed.append((slug, str(box['err'])[:120]))
        elif after and after != before:
            ok += 1
        else:
            print(f"[失败] {slug}: 无新快照落地")
            fail += 1; failed.append((slug, "no-new-snapshot"))
    print(f"\n  拉取完成: {ok}成功 / {fail}失败")

    # 2/5: 客户端型机场 — 自动启动客户端 → 等待连接 → scan-memory → 关闭
    _heartbeat(step="2/5 客户端内存扫描", force=True)
    print("\n=== 2/5 客户端型机场内存扫描 ===")
    client_scanned = 0
    # 从 credentials.yaml 和 airports.yaml 收集所有有client配置的机场
    checked = set()
    for slug, cred in creds.items():
        if slug in checked:
            continue
        checked.add(slug)
        client_cfg = cred.get("client") or _get_client_config(slug)
        if not client_cfg or not client_cfg.get("core_process"):
            continue
        _heartbeat(step="2/5 客户端内存扫描", airport=slug, force=True)
        _do_scan_memory(slug, client_cfg, detector)
        client_scanned += 1
    # 也检查 airports.yaml 里 enabled 的 client 类型
    from airmon.config import load_airports
    apts = load_airports()
    for slug, apt in apts.items():
        if slug in checked:
            continue
        if apt.get("type") != "client" or not apt.get("enabled"):
            continue
        client_cfg = apt.get("client")
        if not client_cfg or not client_cfg.get("core_process"):
            continue
        checked.add(slug)
        _heartbeat(step="2/5 客户端内存扫描", airport=slug, force=True)
        _do_scan_memory(slug, client_cfg, detector)
        client_scanned += 1

    if client_scanned:
        print(f"  客户端扫描完成: {client_scanned}个机场")
    else:
        print("  (无客户端型机场可扫描)")

    _heartbeat(step="3/5 补全落地归属", force=True)
    print("\n=== 3/5 补全落地IP归属 (rescan) ===")
    for slug in [os.path.basename(d.rstrip("/").rstrip("\\")) for d in
                 glob.glob(os.path.join(store.DATA_DIR, "*/"))
                 if os.path.basename(d.rstrip("/").rstrip("\\"))
                 and not os.path.basename(d.rstrip("/").rstrip("\\")).startswith(("_", "."))]:
        _heartbeat(step="3/5 补全落地归属", airport=slug)
        snap = rescan_airport(slug, detector)
        if snap:
            store.save(snap)
    _heartbeat(step="4/5 导出 CSV", force=True)
    print("\n=== 4/5 导出 CSV ===")
    cmd_export(argparse.Namespace(airport=None, out=args.out))
    _heartbeat(step="5/5 生成报告", force=True)
    print("=== 5/5 生成报告 ===")
    report_path = report_mod.generate(None)
    print(f"报告 → {report_path}")

    # 汇总：节点数+华为命中
    tot = aps = 0
    hw_findings = []
    fronting_n = 0
    for d in glob.glob(os.path.join(store.DATA_DIR, "*/")):
        slug = os.path.basename(d.rstrip("/").rstrip("\\"))
        snaps = sorted(glob.glob(os.path.join(d, "*.json")))
        if not snaps:
            continue
        s = store.load(snaps[-1])
        n = len(s.get("nodes", []))
        if n:
            aps += 1; tot += n
        for f in s.get("findings", []):
            dim = f.get("dimension", "") if isinstance(f, dict) else getattr(f, "dimension", "")
            if dim == "fronting":
                fronting_n += 1
                continue
            if dim in HW_DIMS:
                hw_findings.append((slug, f))

    print(f"\n===== 完成：{aps} 个机场，共 {tot} 个节点 =====")
    if hw_findings:
        print(f"\n★★★ 华为关联命中 {len(hw_findings)} 条 ★★★")
        for slug, f in hw_findings:
            if isinstance(f, dict):
                print(f"  [{slug}] {f.get('dimension','')}={f.get('rule','')} | {f.get('evidence','')} | {f.get('context','')}")
            else:
                print(f"  [{slug}] {f.dimension}={f.rule} | {f.evidence} | {f.context}")
    else:
        print("\n华为关联命中：0 条")
    if fronting_n:
        print(f"（另有 {fronting_n} 条「借大厂域名做前置」，不算华为云，单列不计数）")

    # 5.4/5 套餐数据刷新（离线收割新快照的 subscription-userinfo；数据>7天旧才在线补拉。best-effort）
    try:
        _heartbeat(step="5.4 套餐刷新", force=True)
        from airmon.quota import main as _quota_main
        _quota_main([])
    except Exception as _e:
        print(f"[套餐数据刷新失败，忽略] {_e}")

    # 5.5/5 仪表盘（best-effort，失败不影响主流程与退出码）
    try:
        _heartbeat(step="5.5 仪表盘", force=True)
        from airmon.dashboard import generate
        print(f"仪表盘 → {generate()}")
    except Exception as _e:
        print(f"[仪表盘生成失败，忽略] {_e}")

    # 5.6/5 机场分析预计算（增量缓存，日常增量很快；best-effort）
    try:
        _heartbeat(step="5.6 分析预计算", force=True)
        from airmon.analyze import build as _analyze_build
        _analyze_build()
        print("分析数据 → data\\analysis.json")
    except Exception as _e:
        print(f"[分析预计算失败，忽略] {_e}")

    # 5.7/5 陈旧度告警 + 运行台账 last_run.json（假绿修复：退出码+台账让调度器/面板都能看见失败）
    stale: list[str] = []
    try:
        from airmon.alert import stale_report
        stale = stale_report(6.0)
    except Exception as _e:
        print(f"[陈旧度巡检失败，忽略] {_e}")
    try:
        _ended = store.now_iso()
        last = {
            "status": "ok",
            "started_at": started_iso,
            "ended_at": _ended,
            "last_ok_at": _ended,
            "duration_s": round(_time.time() - t0, 1),
            "pull_ok": ok, "pull_fail": fail,
            "failed": [{"slug": s, "reason": r} for s, r in failed],
            "client_scanned": client_scanned,
            "airports_active": aps, "nodes_total": tot,
            "hw_findings": len(hw_findings),
            "stale_over_6h": stale,
            "trigger": (getattr(args, "trigger", None)
                        or os.environ.get("AIRMON_TRIGGER") or "manual"),
        }
        with open(os.path.join(store.DATA_DIR, "last_run.json"), "w", encoding="utf-8") as f:
            json.dump(last, f, ensure_ascii=False, indent=2)
        print(f"运行台账 → data\\last_run.json（成功{ok}/失败{fail}，陈旧{len(stale)}）")
        _append_run_history(last)
    except Exception as _e:
        print(f"[last_run.json 写入失败，忽略] {_e}")

    # 5.8/5 节点抽样探活（TCP 握手测延迟；best-effort，结果进 data/probe.json）
    try:
        from airmon.probe import probe as _probe
        _r = _probe()
        _s = _r["summary"]
        print(f"探活 → data\\probe.json（{_s['airports']} 机场 {_s['probes']} 探针，通 {_s['ok_probes']}）")
    except Exception as _e:
        print(f"[节点探活失败，忽略] {_e}")

    # 5.9/5 基建画像（纯离线四指标；结果进 data/idc_profile.json）
    try:
        from airmon.idc_profile import main as _idc_main
        _idc_main([])
    except Exception as _e:
        print(f"[基建画像失败，忽略] {_e}")

    # 5.10/5 节点分文件导出（每机场一个 Clash 订阅 + base64 订阅体；best-effort）
    # 产物在 nodes/（含真实凭据，已在 .gitignore），随本轮快照一起刷新
    try:
        _heartbeat(step="5.10 节点分文件", force=True)
        from airmon.nodeset import export as _nodeset_export
        _nt = _nodeset_export()["totals"]
        print(f"节点分文件 → nodes\\（{_nt['airports']} 机场 / {_nt['nodes']} 节点，"
              f"可导出 {_nt['exported']} 个 → {_nt['airports_exported']} 台机场）")
    except Exception as _e:
        print(f"[节点分文件导出失败，忽略] {_e}")
    # 5.11/5 机场状态台账（在 docs/机场可用性清单-*.xlsx 里新增一张以「本轮结束时间」命名的表）
    # 依赖 openpyxl：本进程没有就找 DSH 自带 python 跑；都不可用则跳过，不影响主流程
    try:
        _heartbeat(step="5.11 状态台账", force=True)
        _tool = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "update_airport_xlsx.py")
        if os.path.exists(_tool):
            _ran = False
            try:
                import openpyxl  # noqa: F401
                import importlib.util as _ilu
                _spec = _ilu.spec_from_file_location("_airport_xlsx", _tool)
                _mod = _ilu.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)
                _ran = True
            except ImportError:
                _roots = [os.environ.get("DSH_HOME") or "",
                          os.path.expandvars(r"%USERPROFILE%\.dsh"),
                          os.path.expandvars(r"%LOCALAPPDATA%\.dsh")]
                _cand = []
                for _rt in [r for r in _roots if r]:
                    _cand += glob.glob(os.path.join(_rt, "dsh-runtimes", "*", "dependencies", "python", "python.exe"))
                if _cand:
                    import subprocess as _sp
                    _r = _sp.run([_cand[0], "-X", "utf8", _tool], cwd=os.path.dirname(_tool) + os.sep + "..",
                                 capture_output=True, text=True, timeout=240)
                    _tail = [x for x in (_r.stdout or "").strip().splitlines() if x]
                    print(_tail[-1] if _tail else "[状态表] 无输出")
                    if _r.returncode != 0:
                        print(f"[状态表退出码 {_r.returncode}] {( _r.stderr or '')[-180:]}")
                    _ran = True
            if not _ran:
                print("[状态表] 本机没有 openpyxl，本轮跳过")
    except Exception as _e:
        print(f"[状态表生成失败，忽略] {_e}")
    # 5.14/5 微信日报（一天一条；夜间轮发当天，超 28 小时没发过则补发）
    try:
        _h14(step="5.14 微信日报")
        _r14 = subprocess.run([sys.executable, "-X", "utf8",
                               os.path.join(_root, "tools", "daily_digest.py")],
                              cwd=_root, capture_output=True, timeout=180)
        _o14 = (_r14.stdout or b"").decode("utf-8", "replace").strip()
        if _o14:
            print("[5.14] " + _o14.replace("\n", " | ")[:300])
    except Exception as _e14:  # noqa: BLE001
        print("[5.14] 微信日报失败（忽略）：%s: %s" % (type(_e14).__name__, _e14))

    # 5.13/5 每日同步（日报 + 节点清单 → Git；含凭据的配置默认不推）
    try:
        import time as _t13
        _md13 = os.path.join(_root, "docs", "每日摘要", _t13.strftime("%Y%m%d") + ".md")
        _fresh13 = os.path.isfile(_md13) and (_t13.time() - os.path.getmtime(_md13)) < 12 * 3600
        if _fresh13:
            print("[5.13] 每日同步：今天已同步过，跳过")
        else:
            _h13(step="5.13 每日同步")
            _r13 = subprocess.run([sys.executable, "-X", "utf8",
                                   os.path.join(_root, "tools", "sync_daily.py")],
                                  cwd=_root, capture_output=True, timeout=300)
            _o13 = (_r13.stdout or b"").decode("utf-8", "replace")
            for _ln in _o13.strip().splitlines()[-3:]:
                print("[5.13] " + _ln.strip())
    except Exception as _e13:  # noqa: BLE001
        print("[5.13] 每日同步失败（忽略）：%s: %s" % (type(_e13).__name__, _e13))

    # 5.12/5 面板数据（docs/09-新界面-preview/app/data.js）
    # 少了这一步，定时轮跑完只有 runs.json 更新了，面板读的还是旧 data.js ——
    # 用户会以为「这一轮根本没跑」。必须每轮重生成，运行记录/总览才会一起换新。
    try:
        _heartbeat(step="5.12 面板数据", force=True)
        import subprocess as _sp2
        import sys as _sys2
        _root = os.path.dirname(os.path.abspath(__file__))
        _gen = os.path.join(_root, "tools", "gen_panel_data.py")
        if os.path.exists(_gen):
            _g = _sp2.run([_sys2.executable, "-X", "utf8", _gen], cwd=_root,
                          capture_output=True, timeout=600)
            _go = (_g.stdout or b"").decode("utf-8", "replace")
            _gl = [x for x in _go.splitlines() if x.startswith("airports ")]
            if _g.returncode == 0:
                print("面板数据 → data.js 已刷新（%s）" % (_gl[0] if _gl else "ok"))
            else:
                _ge = (_g.stderr or b"").decode("utf-8", "replace")[-200:]
                print("[面板数据生成失败 rc=%d] %s" % (_g.returncode, _ge))
    except Exception as _e:
        print(f"[面板数据生成失败，忽略] {_e}")
    _heartbeat_done()
    try:
        os.remove(_lock)
    except Exception:
        pass
    # 退出码语义（2026-10-24 修）：只有「整轮崩了」或「一半以上机场失败」才算失败。
    # 少数机场挂是常态（过期/跑路/被墙），不该让计划任务 LastTaskResult=1 —— 那会让
    # 看门狗和用户以为整轮没跑成功，实际 status=ok、节点也采到了。
    _tried = ok + fail
    if _tried and fail / _tried >= 0.5:
        return 2
    return 0

def cmd_export(args):
    import glob
    detector = Detector()
    out = args.out or os.path.join(store.DATA_DIR, "nodes_export.csv")
    slugs = [args.airport] if args.airport else \
        [os.path.basename(d.rstrip("/").rstrip("\\")) for d in
         sorted(glob.glob(os.path.join(store.DATA_DIR, "*/")))]
    rows = []
    for slug in slugs:
        snaps = store.list_snapshots(slug)
        if not snaps:
            continue
        s = store.load(snaps[-1])
        for n in s.get("nodes", []):
            ips = n["raw"].get("_resolved_ips") or []
            rd = n["raw"].get("_rdap") or {}
            owners, nets, ctys, hw = [], [], [], ""
            for ip in ips:
                info = rd.get(ip)
                if not info:
                    continue
                nets.append(info[0]); owners.append(info[1]); ctys.append(info[2])
                if detector.scan_ip_record(slug, ip=ip, netname=info[0],
                                           owner=info[1], asn=info[3]):
                    hw = "华为"
            if not hw and detector.check_domain(n["server"]):
                hw = "华为"
            rows.append([slug, n["name"], n["protocol"], n["server"], n["port"],
                         "|".join(ips), "|".join(dict.fromkeys(owners)),
                         "|".join(dict.fromkeys(nets)),
                         "|".join(dict.fromkeys(c for c in ctys if c)), hw])
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        w = __import__("csv").writer(f)
        w.writerow(["机场", "节点名", "协议", "server", "端口",
                    "落地IP", "归属owner", "netname", "国家", "华为"])
        w.writerows(rows)
    hw_n = sum(1 for r in rows if r[-1])
    print(f"已导出 {len(rows)} 个节点 → {out}（华为标记 {hw_n} 个）")


def cmd_add_airport(args):
    """一条命令注册新机场：写 airports.yaml + credentials.yaml + seeds.txt。"""
    import yaml as _yaml
    from airmon.config import DEFAULT_REGISTRY
    _HERE = os.path.dirname(DEFAULT_REGISTRY)
    cred_path = os.path.join(_HERE, "credentials.yaml")
    seeds_path = os.path.join(_HERE, "seeds.txt")

    slug = args.name
    # 1. airports.yaml
    with open(DEFAULT_REGISTRY, encoding="utf-8") as f:
        ap = _yaml.safe_load(f)
    if any(a["name"] == slug for a in ap.get("airports", [])):
        print(f"[跳过] {slug} 已在 airports.yaml 中")
    else:
        entry = {
            "name": slug,
            "display": args.display or slug,
            "type": "direct" if args.type in ("auto", "v2board", "sspanel") else args.type,
            "enabled": True,
        }
        if args.url:
            entry["subscription"] = {"url": args.url, "user_agent": "clash.meta"}
        if args.domains:
            entry["domains"] = [d.strip() for d in args.domains.split(";") if d.strip()]
        ap["airports"].append(entry)
        with open(DEFAULT_REGISTRY, "w", encoding="utf-8") as f:
            _yaml.dump(ap, f, allow_unicode=True, default_flow_style=False)
        print(f"[airports.yaml] 已添加 {slug}")

    # 2. credentials.yaml
    with open(cred_path, encoding="utf-8") as f:
        cred = _yaml.safe_load(f) or {}
    if "accounts" not in cred:
        cred["accounts"] = {}
    if slug in cred["accounts"] and cred["accounts"][slug]:
        print(f"[跳过] {slug} 已在 credentials.yaml 中")
    else:
        acct = {}
        if args.sub_url:
            acct["sub_url"] = args.sub_url
        if args.panel:
            acct["panel"] = args.panel
        if args.email:
            acct["email"] = args.email
        if args.password:
            acct["password"] = args.password
        if args.type != "auto":
            acct["type"] = args.type
        cred["accounts"][slug] = acct
        with open(cred_path, "w", encoding="utf-8") as f:
            _yaml.dump(cred, f, allow_unicode=True, default_flow_style=False)
        print(f"[credentials.yaml] 已添加 {slug}")

    # 3. seeds.txt
    if args.domains:
        existing = ""
        if os.path.exists(seeds_path):
            with open(seeds_path, encoding="utf-8") as f:
                existing = f.read()
        if slug in existing:
            print(f"[跳过] {slug} 已在 seeds.txt 中")
        else:
            line = f"{slug:<13} | {args.display or slug:<14} | {args.domains}\n"
            with open(seeds_path, "a", encoding="utf-8") as f:
                f.write(line)
            print(f"[seeds.txt] 已添加 {slug}")

    print(f"\n完成！现在可以测试：python3 run.py pull --airport {slug}")


def cmd_set_sub(args):
    """给已有机场设置/更新订阅链接（不需要手动编辑 yaml）。"""
    import yaml as _yaml
    from airmon.config import DEFAULT_REGISTRY
    _HERE = os.path.dirname(DEFAULT_REGISTRY)
    cred_path = os.path.join(_HERE, "credentials.yaml")

    with open(cred_path, encoding="utf-8") as f:
        cred = _yaml.safe_load(f) or {}
    if "accounts" not in cred:
        cred["accounts"] = {}
    
    slug = args.airport
    if slug not in cred["accounts"] or not cred["accounts"][slug]:
        cred["accounts"][slug] = {}
    
    acct = cred["accounts"][slug]
    acct["sub_url"] = args.sub_url
    if args.panel:
        acct["panel"] = args.panel
    if args.email:
        acct["email"] = args.email
    if args.password:
        acct["password"] = args.password
    
    with open(cred_path, "w", encoding="utf-8") as f:
        _yaml.dump(cred, f, allow_unicode=True, default_flow_style=False)
    
    print(f"[credentials.yaml] {slug} sub_url 已更新")
    print(f"  sub_url: {args.sub_url[:60]}")
    if args.panel:
        print(f"  panel: {args.panel}")
    print(f"\n测试: python run.py pull --airport {slug} -v")


def cmd_set_client(args):
    """给已有机场设置客户端配置（用于scan-memory自动启动+扫描）。"""
    import yaml as _yaml
    from airmon.config import DEFAULT_REGISTRY
    _HERE = os.path.dirname(DEFAULT_REGISTRY)
    cred_path = os.path.join(_HERE, "credentials.yaml")

    with open(cred_path, encoding="utf-8") as f:
        cred = _yaml.safe_load(f) or {}
    if "accounts" not in cred:
        cred["accounts"] = {}

    slug = args.airport
    if slug not in cred["accounts"] or not cred["accounts"][slug]:
        cred["accounts"][slug] = {}

    pkg = args.package or args.core_process.replace("Core", "").replace("core", "")
    client_cfg = {
        "package": pkg,
        "install_dir": args.install_dir,
        "core_process": args.core_process,
    }
    if args.data_dir:
        client_cfg["data_dir"] = args.data_dir

    cred["accounts"][slug]["client"] = client_cfg

    with open(cred_path, "w", encoding="utf-8") as f:
        _yaml.dump(cred, f, allow_unicode=True, default_flow_style=False)

    print(f"[credentials.yaml] {slug} 客户端配置已更新")
    print(f"  package: {pkg}")
    print(f"  install_dir: {args.install_dir}")
    print(f"  core_process: {args.core_process}")
    if args.data_dir:
        print(f"  data_dir: {args.data_dir}")
    print(f"\n测试: python run.py scan-memory --airport {slug}")
    print(f"  或: python run.py pull --airport {slug} -v")


def cmd_rescan(args):
    detector = Detector()
    slugs = [args.airport] if args.airport else \
        [os.path.basename(d.rstrip("/").rstrip("\\")) for d in
         sorted(__import__("glob").glob(os.path.join(store.DATA_DIR, "*/")))]
    for slug in slugs:
        before = unresolved_stats(slug)
        if before[0] == 0:
            continue
        snap = rescan_airport(slug, detector)
        if not snap:
            continue
        store.save(snap)
        after = unresolved_stats(slug)
        print(f"[rescan] {slug}: {len(snap.nodes)}节点, 未分类IP {before[2]}→{after[2]}, "
              f"华为命中 {len(snap.findings)}")
        if snap.findings:
            emit(slug, snap.findings, None)

def cmd_recon(args):
    detector = Detector()
    seeds = load_seeds(args.seeds)
    if args.airport:
        seeds = [s for s in seeds if s[0] == args.airport]
    out_csv = args.out or os.path.join(store.DATA_DIR, "recon.csv")
    os.makedirs(store.DATA_DIR, exist_ok=True)
    all_findings = []
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["airport", "domain", "status", "ips", "cnames",
                    "rdap_netname", "rdap_owner", "country", "huawei"])
        for slug, display, domains in seeds:
            res = recon_airport(slug, display, domains, detector)
            hw_hosts = {fi.context.split(" [")[0] for fi in res.get("findings", [])}
            print(f"\n=== {slug} ({display}) — {len(domains)}域名, "
                  f"{len(res['findings'])}华为命中 ===")
            for r in res["rows"]:
                rd = next(iter(r["rdap"].values()), ("", "", "", ""))
                hw = "华为" if r["host"] in hw_hosts else ""
                flag = "  <==华为" if hw else ""
                print(f"  {r['status']:12} {r['host']:32} "
                      f"{','.join(r['real'][:2]) or '-':32} {rd[0]}{flag}")
                w.writerow([slug, r["host"], r["status"], "|".join(r["ips"]),
                            "|".join(r["cnames"]), rd[0], rd[1], rd[2], hw])
            all_findings += res.get("findings", [])
    print(f"\n===== 华为关联汇总：{len(all_findings)} 条 =====")
    for fi in all_findings:
        print("  " + fi.line())
    print(f"\nCSV → {out_csv}")

def main():
    # 代理自动纠偏：脚本里写死 7890 但机器上开的是 v2rayN 10808 时，
    # 不纠正就会一路 ProxyError / 超时，表现为「代理明明开着却说没开」。
    try:
        from airmon.netcfg import apply_env as _apply_proxy_env
        _pu = _apply_proxy_env()
        if _pu and os.environ.get("AIRMON_PROXY_QUIET") != "1":
            print(f"[代理] 使用 {_pu}")
    except Exception:  # noqa: BLE001
        pass

    # 华为云 IP 前缀表：每天从 stat.ripe.net 刷新一次（AS55990/136907/137876）。
    # 静态 huawei.yaml 只有 17 段，靠它兜底会漏掉转售/二次分配的华为云 IP。
    try:
        import json as _json
        from airmon import hwprefix as _hwpf
        if _hwpf.should_refresh():
            _hwpf.refresh()
            print("[前缀] 华为云 ASN 前缀表已刷新 %s" % _json.dumps(_hwpf.summary(), ensure_ascii=False))
        else:
            _sh = _hwpf.summary()
            print("[前缀] 华为云 ASN 前缀表 %.1fh 前更新（%d 段 v4 / %d 段 v6）"
                  % (_sh.get("age_h") or 0, _sh.get("v4_spans") or 0, _sh.get("v6_spans") or 0))
    except Exception as _e:
        print("[前缀] 前缀表刷新失败（沿用缓存）：%s" % _e)
    # Windows下强制UTF-8输出，避免GBK编码错误
    import sys as _sys
    if _sys.platform == "win32":
        try:
            _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    p = argparse.ArgumentParser(description="airmon —— 机场监控 + 华为检测")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan-existing", help="在现有 CSV 上验证华为检测")
    s.add_argument("csv")
    s.set_defaults(func=cmd_scan_existing)

    s = sub.add_parser("list", help="列出注册机场")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("collect", help="采集直连型订阅")
    s.add_argument("--airport", required=True)
    s.set_defaults(func=cmd_collect)

    s = sub.add_parser("ingest-profile", help="摄入客户端落盘 profile")
    s.add_argument("--airport", required=True)
    s.add_argument("--file", required=True)
    s.add_argument("--index", default=None,
                   help="客户端 profiles.yaml（账号索引，含 regip）；默认自动探测")
    s.set_defaults(func=cmd_ingest_profile)

    s = sub.add_parser("diff", help="对比最近两次快照")
    s.add_argument("--airport", required=True)
    s.set_defaults(func=cmd_diff)

    s = sub.add_parser("pull", help="凭证自动登录取订阅→抓节点→查华为")
    s.add_argument("--airport", default=None, help="只拉某个 slug；多个用逗号分隔(如 a,b,c)；不填=全部")
    s.add_argument("-v", "--verbose", action="store_true", help="每个机场拉完即显示协议/落地/华为详情")
    s.set_defaults(func=cmd_pull)

    s = sub.add_parser("ingest-page", help="从另存的/user/node页面抽节点（无订阅链接机场）")
    s.add_argument("--airport", required=True)
    s.add_argument("--file", required=True, help="另存的页面 HTML 或复制的节点文本")
    s.set_defaults(func=cmd_ingest_page)

    s = sub.add_parser("scan-client", help="扫客户端数据目录抽节点（下软件登录型机场）")
    s.add_argument("--airport", required=True)
    s.add_argument("--dir", required=True, help="客户端数据目录（含配置/profiles）")
    s.set_defaults(func=cmd_scan_client)

    s = sub.add_parser("ingest-cookie", help="cookie遍历/user/node/<id>抽全部节点（JS渲染节点页）")
    s.add_argument("--airport", required=True)
    s.add_argument("--base", required=True, help="机场后台域名，如 https://ayucloud.nl")
    s.add_argument("--cookie", default=None, help="浏览器已登录请求里的 Cookie 串")
    s.add_argument("--cookie-file", default=None, help="或从文件读 Cookie")
    s.add_argument("--max-id", type=int, default=300, help="遍历的最大节点ID，默认300")
    s.set_defaults(func=cmd_ingest_cookie)

    s = sub.add_parser("watch", help="盯客户端落盘profile自动摄入（客户端锁定型自动化）")
    s.add_argument("--airport", required=True)
    s.add_argument("--file", required=True, help="要监视的 profile 文件（客户端落盘的节点yaml）")
    s.add_argument("--index", default=None, help="profiles.yaml 账号索引（含 regip）")
    s.add_argument("--interval", type=int, default=60, help="检查间隔秒，默认60")
    s.add_argument("--max-checks", type=int, default=0, help="最多检查几次（0=一直跑）")
    s.set_defaults(func=cmd_watch)

    # ---- Windows 客户端型新命令 ----

    s = sub.add_parser("scan-win-client", help="扫Windows客户端数据目录（提取订阅URL/API域名/账号）")
    s.add_argument("--airport", required=True)
    s.add_argument("--dir", required=True, help="客户端 AppData 数据目录")
    s.add_argument("--app-dir", default=None, help="客户端安装目录（含 data/app.so，用于二进制扫描）")
    s.set_defaults(func=cmd_scan_win_client)

    s = sub.add_parser("scan-clients", help="只扫所有有客户端配置的机场（需管理员权限）")
    s.add_argument("--airport", default=None, help="只扫指定机场（逗号分隔），不填=全部客户端型")
    s.set_defaults(func=cmd_scan_clients)

    s = sub.add_parser("scan-persistent", help="QQT持久化扫描：客户端常驻运行,只读内存,不启动/不关闭")
    s.add_argument("--airport", default="quqiuquan", help="机场slug（默认quqiuquan）")
    s.set_defaults(func=cmd_scan_persistent)

    s = sub.add_parser("scan-memory", help="从Clash内核进程内存提取节点（需管理员权限）")
    s.add_argument("--airport", required=True)
    s.add_argument("--client", default=None, help="客户端名称（默认=airport slug）")
    s.add_argument("--pid", type=int, default=None, help="直接指定进程 PID")
    s.set_defaults(func=cmd_scan_memory)

    s = sub.add_parser("monitor-net", help="监控客户端TCP连接提取代理IP:端口")
    s.add_argument("--airport", required=True)
    s.add_argument("--client", default=None, help="客户端名称（默认=airport slug）")
    s.add_argument("--pid", type=int, default=None, help="直接指定进程 PID")
    s.add_argument("--watch", action="store_true", help="持续监控模式")
    s.add_argument("--interval", type=int, default=5, help="扫描间隔秒（watch模式），默认5")
    s.add_argument("--max-scans", type=int, default=0, help="最多扫描几次（0=一直跑）")
    s.set_defaults(func=cmd_monitor_net)

    s = sub.add_parser("auto-scan", help="一键采集：数据目录+网络监控+内存扫描+富化+保存")
    s.add_argument("--airport", required=True)
    s.add_argument("--client", default=None, help="客户端名称（默认=airport slug）")
    s.add_argument("--data-dir", default=None, help="客户端 AppData 数据目录")
    s.add_argument("--app-dir", default=None, help="客户端安装目录（含 data/app.so）")
    s.add_argument("--pid", type=int, default=None, help="直接指定进程 PID")
    s.add_argument("--net-only", action="store_true", help="只做网络监控（不需要管理员）")
    s.add_argument("--watch", action="store_true", help="持续网络监控模式")
    s.add_argument("--interval", type=int, default=5, help="扫描间隔秒（watch模式）")
    s.add_argument("--max-scans", type=int, default=0, help="最多扫描几次（0=一直跑）")
    s.set_defaults(func=cmd_auto_scan)

    s = sub.add_parser("all", help="一条命令跑完：拉所有机场+补落地+导CSV+出报告")
    s.add_argument("--out", default=None, help="CSV 输出路径，默认 data/nodes_export.csv")
    s.add_argument("-v", "--verbose", action="store_true", help="每个机场拉完即显示协议/落地/华为详情")
    s.add_argument("--trigger", default=None, help="本轮触发来源（scheduled/manual），写进 runs.json")
    s.set_defaults(func=cmd_all)

    s = sub.add_parser("report", help="汇总所有机场→生成节点分析报告(Markdown)")
    s.add_argument("--out", default=None, help="报告输出路径，默认 data/report.md")
    s.add_argument("--pull", action="store_true", help="先 pull 全部机场+rescan 再出报告(全流程)")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("export", help="把所有机场最新快照的节点拍平成 CSV")
    s.add_argument("--airport", default=None, help="只导某个 slug；不填=全部")
    s.add_argument("--out", default=None, help="输出 CSV 路径")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("rescan", help="对已抓快照补查落地IP+重跑华为检测（离线）")
    s.add_argument("--airport", default=None, help="只重扫某个 slug；不填=全部")
    s.set_defaults(func=cmd_rescan)

    s = sub.add_parser("recon", help="域名基础设施+华为侦察（不需账号）")
    s.add_argument("--seeds", default="seeds.txt")
    s.add_argument("--airport", default=None, help="只跑某个 slug")
    s.add_argument("--out", default=None, help="输出 CSV 路径")
    s.set_defaults(func=cmd_recon)

    s = sub.add_parser("add-airport", help="注册新机场到 airports.yaml + credentials.yaml + seeds.txt")
    s.add_argument("--name", required=True, help="机场 slug（英文，如 flyint）")
    s.add_argument("--display", default=None, help="显示名（如 飞数FlyInt）")
    s.add_argument("--url", default=None, help="官网/订阅 URL")
    s.add_argument("--email", default=None, help="登录邮箱")
    s.add_argument("--password", default=None, help="登录密码")
    s.add_argument("--panel", default=None, help="后台面板地址（如 https://xxx.com）")
    s.add_argument("--sub-url", default=None, help="手动获取的订阅链接（跳过登录）")
    s.add_argument("--type", default="auto", choices=["auto", "direct", "client", "v2board", "sspanel", "whmcs"])
    s.add_argument("--domains", default=None, help="域名种子，分号分隔（如 a.com;b.com）")
    s.set_defaults(func=cmd_add_airport)

    s = sub.add_parser("set-sub", help="给已有机场设置/更新订阅链接")
    s.add_argument("--airport", required=True, help="机场 slug")
    s.add_argument("--sub-url", required=True, help="订阅链接")
    s.add_argument("--panel", default=None, help="同时更新面板地址（可选）")
    s.add_argument("--email", default=None, help="同时更新邮箱（可选）")
    s.add_argument("--password", default=None, help="同时更新密码（可选）")
    s.set_defaults(func=cmd_set_sub)

    s = sub.add_parser("set-client", help="给已有机场设置客户端配置（用于scan-memory）")
    s.add_argument("--airport", required=True, help="机场 slug")
    s.add_argument("--install-dir", required=True, help="客户端安装目录（如 E:\\\\Hermes-Agent\\\\Jichang-Monitor\\\\jichang-ruanjian\\\\SpeedCat）")
    s.add_argument("--core-process", required=True, help="内核进程名（如 SpeedCatCore）")
    s.add_argument("--package", default=None, help="客户端包名/GUI进程名（默认同core去掉Core）")
    s.add_argument("--data-dir", default=None, help="AppData数据目录（可选）")
    s.set_defaults(func=cmd_set_client)

    args = p.parse_args()
    try:
        rc = args.func(args)
    except Exception:
        import traceback as _tb
        _err = _tb.format_exc()
        print(_err, file=sys.stderr)
        if getattr(args, "func", None) is cmd_all:
            try:
                import json as _json
                with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "data", "last_run.json"), "w", encoding="utf-8") as _f:
                    _json.dump({"status": "crashed", "ended_at": store.now_iso(),
                                "error": _err.strip().splitlines()[-1][:300],
                                "traceback": _err[-2000:]}, _f,
                               ensure_ascii=False, indent=2)
            except Exception:
                pass
        sys.exit(1)
    if isinstance(rc, int) and rc:
        sys.exit(rc)


if __name__ == "__main__":
    main()
