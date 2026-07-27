#!/usr/bin/env python3
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
                            collect_client)
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
    for name, a in load_airports().items():
        flag = "on " if a.get("enabled") else "off"
        print(f"[{flag}] {name:10} {a.get('type'):7} {a.get('display','')}")

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
    if given:
        return given, None
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

VERBOSE = False

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
    if cred.get("sub_url"):
        try:
            snap = collect_from_url(slug, cred["sub_url"], detector,
                                    cred.get("user_agent", "clash.meta"))
        except Exception as e:
            print(f"[失败] {slug} 手动订阅URL: {e}")
            return
        _finish(slug, snap, "manual-url")
        return
    if cred.get("cookie"):
        base = cred.get("base") or cred.get("panel") or _resolve_panel(slug, None)[0]
        if not base:
            print(f"[跳过] {slug}: 有 cookie 但缺 base（填该机场后台域名）")
            return
        try:
            snap = collect_node_pages(slug, base, cred["cookie"], detector,
                                      max_id=cred.get("max_id", 300))
        except Exception as e:
            print(f"[失败] {slug} cookie节点页: {e}")
            return
        if not snap.nodes:
            print(f"[失败] {slug}: cookie 没抽到节点（确认 base 域名、cookie 是否过期）")
            return
        _finish(slug, snap, "node-page-cookie")
        return
    if not cred.get("email") or not cred.get("password"):
        print(f"[跳过] {slug}: 无 sub_url 且缺 email/password")
        return
    panel, detected_type = _resolve_panel(slug, cred.get("panel"))
    if not panel:
        print(f"[跳过] {slug}: 未探测到可登录后台（在 credentials.yaml 指定 panel 或 sub_url）")
        return
    explicit = cred.get("type")
    ptype = explicit if explicit and explicit != "auto" else (detected_type or "auto")
    try:
        snap, sub_url, kind = collect_login(slug, panel, cred["email"],
                                            cred["password"], detector, ptype)
    except LoginError as e:
        print(f"[失败] {slug} @ {panel}: {e}（反爬/验证码机场可在 credentials.yaml 填 sub_url 兜底）")
        return
    except Exception as e:
        print(f"[失败] {slug} @ {panel}: 登录后抓订阅出错: {e}")
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
    if args.airport:
        if args.airport not in creds:
            print(f"credentials.yaml 里没有 {args.airport}")
            return
        _pull_one(args.airport, creds[args.airport], detector)
    else:
        import threading
        total = len(creds)
        for i, (slug, cred) in enumerate(creds.items(), 1):
            print(f"[{i}/{total}] 正在拉取 {slug} ...", flush=True)
            t = threading.Thread(target=_pull_one, args=(slug, cred, detector),
                                 daemon=True)
            t.start()
            t.join(180)
            if t.is_alive():
                print(f"[跳过] {slug}: 超时(>180s)，跳过（该机场服务器无响应）")

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

def cmd_scan_memory(args):
    """从 Clash 内核进程内存扫描提取节点（需管理员权限）。"""
    from airmon.memsan import collect_memory_scan
    detector = Detector()
    client_name = args.client or args.airport
    try:
        snap = collect_memory_scan(args.airport, client_name=client_name,
                                   pid=args.pid, detector=detector)
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
              "--client", client_name, "--watch")

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
            t.start(); t.join(180)
            if t.is_alive():
                print(f"[跳过] {slug}: 超时")
        for slug in [os.path.basename(d.rstrip("/")) for d in
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
    creds = load_credentials()
    detector = Detector()
    total = len(creds)
    print(f"=== 1/4 拉取所有机场 (共{total}个) ===")
    for i, (slug, cred) in enumerate(creds.items(), 1):
        print(f"[{i}/{total}] 正在拉取 {slug} ...", flush=True)
        t = threading.Thread(target=_pull_one, args=(slug, cred, detector), daemon=True)
        t.start(); t.join(180)
        if t.is_alive():
            print(f"[跳过] {slug}: 超时")
    print("\n=== 2/4 补全落地IP归属 (rescan) ===")
    for slug in [os.path.basename(d.rstrip("/")) for d in
                 glob.glob(os.path.join(store.DATA_DIR, "*/"))]:
        snap = rescan_airport(slug, detector)
        if snap:
            store.save(snap)
    print("\n=== 3/4 导出 CSV ===")
    cmd_export(argparse.Namespace(airport=None, out=args.out))
    print("=== 4/4 生成报告 ===")
    print(f"报告 → {report_mod.generate(None)}")
    tot = aps = 0
    for d in glob.glob(os.path.join(store.DATA_DIR, "*/")):
        snaps = sorted(glob.glob(os.path.join(d, "*.json")))
        if snaps:
            n = len(json.load(open(snaps[-1], encoding="utf-8"))["nodes"])
            if n:
                aps += 1; tot += n
    print(f"\n===== 完成：{aps} 个机场，共 {tot} 个节点 → data/nodes_export.csv =====")

def cmd_export(args):
    import glob
    detector = Detector()
    out = args.out or os.path.join(store.DATA_DIR, "nodes_export.csv")
    slugs = [args.airport] if args.airport else \
        [os.path.basename(d.rstrip("/")) for d in
         sorted(glob.glob(os.path.join(store.DATA_DIR, "*/")))]
    rows = []
    for slug in slugs:
        snaps = store.list_snapshots(slug)
        if not snaps:
            continue
        s = store.load(snaps[-1])
        for n in s["nodes"]:
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

def cmd_rescan(args):
    detector = Detector()
    slugs = [args.airport] if args.airport else \
        [os.path.basename(d.rstrip("/")) for d in
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
            hw_hosts = {fi.context.split(" [")[0] for fi in res["findings"]}
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
            all_findings += res["findings"]
    print(f"\n===== 华为关联汇总：{len(all_findings)} 条 =====")
    for fi in all_findings:
        print("  " + fi.line())
    print(f"\nCSV → {out_csv}")

def main():
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
    s.add_argument("--airport", default=None, help="只拉某个 slug；不填=全部")
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

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
