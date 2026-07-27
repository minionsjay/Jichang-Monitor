#!/usr/bin/env python3
"""一键自动化采集脚本 — 针对需要运行客户端软件才能获取节点的机场。

流程：
  1. 扫描客户端数据目录（提取订阅URL/API/账号）
  2. 网络连接监控（抓代理IP，不需要管理员）
  3. 进程内存扫描（提取完整节点配置，需要管理员）
  4. RDAP富化 + 华为检测
  5. 保存快照 + 导出CSV + 告警

用法：
  # 万达云（需要管理员权限运行，且客户端已启动并连接）
  python3 run.py auto-scan --airport wdy --client wandacloud \
    --data-dir "C:\\Users\\minions\\AppData\\Roaming\\wandacloud\\wandacloud" \
    --app-dir "E:\\梯子工具\\wandacloud"

  # SpeedCat
  python3 run.py auto-scan --airport speedcat --client SpeedCat \
    --data-dir "C:\\Users\\minions\\AppData\\Roaming\\SpeedCat\\SpeedCat" \
    --app-dir "E:\\梯子工具\\SpeedCat"

  # 只做网络监控（不需要管理员）
  python3 run.py auto-scan --airport speedcat --client SpeedCat --net-only

  # 持续网络监控模式
  python3 run.py auto-scan --airport speedcat --client SpeedCat --watch
"""
from __future__ import annotations

import argparse
import os
import sys
import time


def cmd_auto_scan(args):
    """一键采集：数据目录扫描 + 网络监控 + 内存扫描 + 富化 + 保存。"""
    from airmon.detect import Detector
    from airmon import store
    from airmon.alert import emit

    detector = Detector()
    slug = args.airport
    client = args.client or slug
    all_nodes = []
    meta = {}
    source_parts = []

    print(f"=== 自动采集: {slug} ({client}) ===")
    print(f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Step 1: 扫描数据目录（提取订阅URL/API/账号）
    if args.data_dir and not args.net_only:
        print("[1/4] 扫描数据目录...")
        try:
            from airmon.winclient import collect_win_client
            snap, win_meta = collect_win_client(slug, args.data_dir, detector,
                                                app_dir=args.app_dir)
            if win_meta.get("sub_urls"):
                print(f"  订阅链接: {len(win_meta['sub_urls'])} 条")
                for u in win_meta["sub_urls"][:3]:
                    print(f"    {u}")
            if win_meta.get("email"):
                print(f"  账号: {win_meta['email']}")
            if win_meta.get("config_encrypted") is not None:
                print(f"  配置文件: {'加密' if win_meta.get('config_encrypted') else '明文'}")
            if snap.nodes:
                all_nodes.extend(snap.nodes)
                source_parts.append("win_client")
                meta.update({k: v for k, v in win_meta.items()
                            if k in ("sub_urls", "api_urls", "email", "config_encrypted")})
                print(f"  节点: {len(snap.nodes)} 个")
            else:
                print("  未获取到节点（配置可能加密，需内存扫描）")
        except Exception as e:
            print(f"  错误: {e}")

    # Step 2: 网络连接监控
    print()
    print("[2/4] 网络连接监控...")
    try:
        from airmon.netmon import collect_network_scan, find_client_pids
        pids = find_client_pids(client)
        if pids:
            print(f"  进程 PID: {pids}")
            if args.watch:
                # 持续监控模式
                print(f"  持续监控模式（每 {args.interval}s 扫描一次，Ctrl-C 停止）")
                from airmon.netmon import watch_network
                watch_network(slug, client_name=client, pid=args.pid,
                             interval=args.interval, max_scans=args.max_scans,
                             detector=detector)
                return
            else:
                snap = collect_network_scan(slug, client_name=client,
                                            pid=args.pid, detector=detector)
                if snap.nodes:
                    all_nodes.extend(snap.nodes)
                    source_parts.append("net_monitor")
                    print(f"  节点: {len(snap.nodes)} 个")
                else:
                    print("  未捕获到代理连接")
        else:
            print(f"  未找到 {client} 进程（请先启动客户端并连接）")
    except Exception as e:
        print(f"  错误: {e}")

    # Step 3: 进程内存扫描（需要管理员）
    if not args.net_only:
        print()
        print("[3/4] 进程内存扫描...")
        try:
            from airmon.memsan import collect_memory_scan
            snap = collect_memory_scan(slug, client_name=client,
                                       pid=args.pid, detector=detector)
            for proc in snap.meta.get("processes", []):
                if "error" in proc:
                    print(f"  {proc['name']} (PID {proc['pid']}): {proc['error']}")
                else:
                    print(f"  {proc['name']}: {proc.get('regions', 0)} regions, "
                          f"{proc.get('total_mb', 0)} MB, "
                          f"{proc.get('items_found', 0)} items")
            if snap.nodes:
                all_nodes.extend(snap.nodes)
                source_parts.append("memory_scan")
                print(f"  节点: {len(snap.nodes)} 个")
            else:
                print("  未提取到节点")
        except RuntimeError as e:
            print(f"  {e}")
        except Exception as e:
            print(f"  错误: {e}")

    # Step 4: 合并 + 去重 + 保存
    print()
    print("[4/4] 合并 + 保存快照...")
    # 去重
    seen = {}
    for n in all_nodes:
        key = n.key()
        if key not in seen:
            seen[key] = n
    nodes = list(seen.values())

    source = "+".join(source_parts) if source_parts else "auto_scan"
    snap = store.Snapshot(
        airport=slug,
        ts=store.now_iso(),
        source=source,
        nodes=nodes,
        findings=[],
        meta=meta,
    )

    # 富化 + 检测
    if nodes:
        from airmon.collect import _enrich_and_detect
        snap.findings = _enrich_and_detect(slug, nodes, detector)

    path = store.save(snap)
    print(f"  快照: {len(nodes)} 节点, {len(snap.findings)} 华为命中 → {path}")

    # 告警
    changes = store.diff_latest(slug)
    emit(slug, snap.findings, changes)

    if snap.findings:
        print(f"\n  ⚠️ 华为命中:")
        for f in snap.findings:
            print(f"    {f.line()}")
    if changes:
        print(f"  变更: 新增 {len(changes['added'])} / 消失 {len(changes['removed'])}")

    print(f"\n=== 完成: {slug} {len(nodes)} 节点 ===")
    print(f"  查看CSV: python3 run.py export --airport {slug}")
    print(f"  查看diff: python3 run.py diff --airport {slug}")
