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
import sys

import csv
import os

from airmon import store
from airmon.alert import emit
from airmon.collect import (collect_direct, collect_profile, collect_login,
                            collect_from_url, collect_page, collect_node_pages,
                            collect_client, collect_server_fetch)
from airmon.config import load_airports, get_airport, load_credentials, seed_domains
from airmon.detect import Detector
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
    print(f"采集完成：{len(snap.nodes)} 节点，{len(snap.findings)} 华为命中 → {path}")
    changes = store.diff_latest(args.airport)
    emit(args.airport, snap.findings, changes)

def cmd_ingest_profile(args):
    airport = get_airport(args.airport)
    snap = collect_profile(airport, args.file, Detector(), index_path=args.index)
    path = store.save(snap)
    print(f"摄入完成：{len(snap.nodes)} 节点，{len(snap.findings)} 华为命中 → {path}")
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


def _do_scan_memory(slug: str, client_cfg: dict, detector: Detector):
    """自动启动客户端 → 等待 → scan-memory → keep_alive控制关闭。"""
    import subprocess as _sp
    import time as _time
    core_process = client_cfg.get("core_process", "")
    if not core_process:
        return

    def _find_pid(proc_name):
        try:
            r = _sp.run(["tasklist", "/FI", f"IMAGENAME eq {proc_name}.exe",
                         "/FO", "CSV", "/NH"],
                        capture_output=True, text=True, timeout=10)
            for line in r.stdout.strip().split("\n"):
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
        except Exception:
            pass
    if best_snap is not None:
        store.save(best_snap)
        print(f"    [{slug}] ✓ scan-memory 最终: {len(best_snap.nodes)}节点, {len(best_snap.findings)}华为", flush=True)
    else:
        print(f"    [{slug}] scan-memory: 0节点（客户端可能未连接代理）", flush=True)

    # 关闭客户端 — 可通过 YAML 配置 keep_alive: true 保持客户端运行
    # 适用场景: QQT等需要保持登录态的客户端, 扫描后不关闭, 下次直接读内存
    if client_cfg.get("keep_alive"):
        print(f"    [{slug}] keep_alive=true, 保持客户端运行(不关闭)", flush=True)
    else:
        try:
            _sp.run(["taskkill", "/F", "/IM", f"{core_process}.exe"],
                     capture_output=True, timeout=10)
            gui_name = client_cfg.get("package", slug)
            _sp.run(["taskkill", "/F", "/IM", f"{gui_name}.exe"],
                     capture_output=True, timeout=10)
        except Exception:
            pass


def _finish(slug: str, snap, kind: str):
    from collections import Counter
    path = store.save(snap)
    print(f"[成功] {slug} ({kind}): {len(snap.nodes)} 节点, "
          f"{len(snap.findings)} 华为命中")
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
        if panel and cred.get("email") and cred.get("password"):
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
        try:
            snap = collect_from_url(slug, cred["sub_url"], detector,
                                    cred.get("user_agent", "clash.meta"))
            _finish(slug, snap, "manual-url")
            return  # sub_url成功就结束，不需要再启动客户端
        except Exception as e:
            print(f"    [{slug}] 订阅URL失败({str(e)[:50]})，尝试面板登录...")
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
                      f"{len(snap.nodes)} 节点, {len(snap.findings)} 华为命中")
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

    def _find_pid(proc_name):
        try:
            r = _sp.run(["tasklist", "/FI", f"IMAGENAME eq {proc_name}.exe",
                         "/FO", "CSV", "/NH"],
                        capture_output=True, text=True, timeout=10)
            for line in r.stdout.strip().split("\n"):
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

            if os.path.exists(exe_path):
                print(f"启动客户端: {exe_path}")
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

    # 自动关闭客户端（如果是本命令启动的）
    if not args.pid:
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

def cmd_all(args):
    global VERBOSE
    VERBOSE = getattr(args, "verbose", False)
    import threading, glob, json
    from collections import Counter
    creds = load_credentials()
    detector = Detector()
    total = len(creds)
    print(f"=== 1/5 拉取所有机场 (共{total}个) ===")
    ok, fail = 0, 0
    for i, (slug, cred) in enumerate(creds.items(), 1):
        print(f"[{i}/{total}] 正在拉取 {slug} ...", flush=True)
        t = threading.Thread(target=_pull_one, args=(slug, cred, detector), daemon=True)
        t.start(); t.join(300)
        if t.is_alive():
            print(f"[跳过] {slug}: 超时")
            fail += 1
        else:
            ok += 1
    print(f"\n  拉取完成: {ok}成功 / {fail}超时")

    # 2/5: 客户端型机场 — 自动启动客户端 → 等待连接 → scan-memory → 关闭
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
        _do_scan_memory(slug, client_cfg, detector)
        client_scanned += 1

    if client_scanned:
        print(f"  客户端扫描完成: {client_scanned}个机场")
    else:
        print("  (无客户端型机场可扫描)")

    print("\n=== 3/5 补全落地IP归属 (rescan) ===")
    for slug in [os.path.basename(d.rstrip("/").rstrip("\\")) for d in
                 glob.glob(os.path.join(store.DATA_DIR, "*/"))
                 if os.path.basename(d.rstrip("/").rstrip("\\"))]:
        snap = rescan_airport(slug, detector)
        if snap:
            store.save(snap)
    print("\n=== 4/5 导出 CSV ===")
    cmd_export(argparse.Namespace(airport=None, out=args.out))
    print("=== 5/5 生成报告 ===")
    report_path = report_mod.generate(None)
    print(f"报告 → {report_path}")

    # 汇总：节点数+华为命中
    tot = aps = 0
    hw_findings = []
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
    args.func(args)


if __name__ == "__main__":
    main()
