"""网络连接监控采集器 — 监控 Clash 内核进程的 TCP 连接，提取代理服务器 IP:端口。

不需要管理员权限（使用 GetExtendedTcpTable API）。
适合配置加密且无法读取内存时的兜底方案。

使用方式：
  # 一次性快照
  python3 run.py monitor-net --airport wandacloud
  python3 run.py monitor-net --airport speedcat --pid 12345

  # 持续监控（每 5 秒扫描一次，Ctrl-C 停止）
  python3 run.py monitor-net --airport wandacloud --watch --interval 5
"""
from __future__ import annotations

import json
import os
import re
import socket
import struct
import subprocess
import sys
import time

from .models import Node, Snapshot, Finding
from . import store


def _is_windows():
    return sys.platform == "win32" or os.name == "nt"


# ---- Windows TCP 连接枚举 ----

TCP_TABLE_OWNER_PID_ALL = 5


def _win_tcp_connections() -> list[dict]:
    """使用 GetExtendedTcpTable 枚举所有 TCP 连接。"""
    import ctypes
    import ctypes.wintypes as wt

    iphlpapi = ctypes.windll.iphlpapi
    size = wt.DWORD(0)
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, TCP_TABLE_OWNER_PID_ALL, 0)
    buf = (ctypes.c_byte * size.value)()
    if iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, 2, TCP_TABLE_OWNER_PID_ALL, 0) != 0:
        return []

    count = struct.unpack_from('I', buf)[0]
    conns = []
    for i in range(count):
        off = 4 + i * 24
        state, la, lp, ra, rp, pid = struct.unpack_from('IIIIII', buf, off)
        conns.append({
            'state': state,
            'local_ip': socket.inet_ntoa(struct.pack('I', la)),
            'local_port': (lp >> 8) | ((lp & 0xFF) << 8),
            'remote_ip': socket.inet_ntoa(struct.pack('I', ra)),
            'remote_port': (rp >> 8) | ((rp & 0xFF) << 8),
            'pid': pid,
        })
    return conns


def _interop_tcp_connections() -> list[dict]:
    """从 WSL 调用 Windows 命令枚举 TCP 连接。"""
    try:
        result = subprocess.run(
            ['cmd.exe', '/c', 'netstat', '-ano'],
            capture_output=True, timeout=15
        )
        text = result.stdout.decode('utf-8', errors='replace')
        if 'wandacloud' not in text.lower() and 'speedcat' not in text.lower():
            text = result.stdout.decode('gbk', errors='replace')
    except Exception:
        return []

    conns = []
    for line in text.split('\n'):
        parts = line.split()
        if len(parts) >= 5 and parts[0] == 'TCP':
            try:
                local = parts[1]
                remote = parts[2]
                state_str = parts[3]
                pid = int(parts[4])

                local_ip, local_port = local.rsplit(':', 1)
                remote_ip, remote_port = remote.rsplit(':', 1)

                state_map = {
                    'ESTABLISHED': 5, 'LISTENING': 2, 'SYN_SENT': 3,
                    'CLOSE_WAIT': 8, 'TIME_WAIT': 11, 'FIN_WAIT2': 7,
                }
                state = state_map.get(state_str, 0)

                conns.append({
                    'state': state,
                    'local_ip': local_ip,
                    'local_port': int(local_port),
                    'remote_ip': remote_ip,
                    'remote_port': int(remote_port),
                    'pid': pid,
                })
            except (ValueError, IndexError):
                pass

    return conns


def get_tcp_connections() -> list[dict]:
    """获取所有 TCP 连接。自动选择 Windows 原生或 interop 方式。"""
    if _is_windows():
        try:
            return _win_tcp_connections()
        except Exception:
            pass
    return _interop_tcp_connections()


# ---- 进程查找 ----

def find_pids(keywords: list[str]) -> list[int]:
    """按关键词查找进程 PID。"""
    try:
        result = subprocess.run(
            ['cmd.exe', '/c', 'tasklist', '/FO', 'CSV', '/NH'],
            capture_output=True, timeout=10
        )
        text = result.stdout.decode('utf-8', errors='replace')
        pids = []
        for line in text.split('\n'):
            for kw in keywords:
                if kw.lower() in line.lower():
                    parts = line.strip('"').split('","')
                    if len(parts) >= 2:
                        try:
                            pids.append(int(parts[1]))
                        except ValueError:
                            pass
                    break
        return list(set(pids))
    except Exception:
        return []


def find_client_pids(client_name: str = None) -> list[int]:
    """查找客户端进程 PID。"""
    if client_name:
        keywords = [client_name + "Core", client_name + "core", client_name]
    else:
        keywords = ['clash', 'mihomo', 'wandacloudCore', 'SpeedCatCore',
                     'flclash', 'verge', 'v2ray', 'xray', 'sing-box']
    return find_pids(keywords)


# ---- 节点提取 ----

# 已知的非代理 IP（DNS/API/测速服务器）
NON_PROXY_IPS = {
    '1.1.1.1', '8.8.8.8', '223.5.5.5', '223.6.6.6',
    '1.12.12.21', '162.159.61.8', '104.21.44.93',
    '127.0.0.1', '0.0.0.0',
}


def extract_proxy_connections(conns: list[dict], pids: list[int]) -> list[dict]:
    """从 TCP 连接中提取代理节点连接（非本地、非 DNS 的 ESTABLISHED 连接）。"""
    seen = set()
    proxy_conns = []
    for c in conns:
        if c['pid'] not in pids:
            continue
        if c['state'] != 5:  # ESTABLISHED
            continue
        ip = c['remote_ip']
        port = c['remote_port']
        # Skip local
        if ip.startswith('127.') or ip.startswith('0.') or ip.startswith('192.168.') or ip.startswith('10.'):
            continue
        if ip in NON_PROXY_IPS:
            continue
        key = f"{ip}:{port}"
        if key not in seen:
            seen.add(key)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror, Exception):
                hostname = ""
            proxy_conns.append({
                'ip': ip, 'port': port, 'hostname': hostname, 'pid': c['pid']
            })
    return proxy_conns


def collect_network_scan(slug: str, client_name: str = None,
                         pid: int = None, detector=None) -> Snapshot:
    """一次性扫描客户端的网络连接，提取代理节点。

    Args:
        slug: 机场 slug
        client_name: 客户端名称
        pid: 直接指定 PID
        detector: 华为检测器
    """
    if pid:
        pids = [pid]
    else:
        pids = find_client_pids(client_name)

    if not pids:
        raise RuntimeError(f"未找到 {client_name or 'Clash'} 进程")

    conns = get_tcp_connections()
    proxy_conns = extract_proxy_connections(conns, pids)

    # 转为 Node 列表
    nodes = []
    for pc in proxy_conns:
        nodes.append(Node(
            name=pc.get('hostname', '') or f"node-{pc['port']}",
            protocol="tcp",
            server=pc['ip'],
            port=pc['port'],
            raw={"hostname": pc.get('hostname', ''),
                 "source": "network_monitor",
                 "pid": pc['pid']},
        ))

    snap = Snapshot(
        airport=slug,
        ts=store.now_iso(),
        source=f"network_monitor:{client_name or 'auto'}",
        nodes=nodes,
        meta={"pids_scanned": pids, "total_conns": len(conns)},
    )

    if detector:
        from .collect import _enrich_and_detect
        snap.findings = _enrich_and_detect(slug, nodes, detector)

    return snap


def watch_network(slug: str, client_name: str = None, pid: int = None,
                  interval: int = 5, max_scans: int = 0,
                  detector=None) -> None:
    """持续监控客户端网络连接，发现新节点就保存快照。

    Args:
        slug: 机场 slug
        client_name: 客户端名称
        pid: 直接指定 PID
        interval: 扫描间隔（秒）
        max_scans: 最多扫描几次（0=一直跑）
        detector: 华为检测器
    """
    from .alert import emit

    seen_keys = set()
    all_nodes = []
    scans = 0

    print(f"[watch-net] 监控 {client_name or slug}，每 {interval}s 扫描一次，Ctrl-C 停止")

    try:
        while True:
            if pid:
                pids = [pid]
            else:
                pids = find_client_pids(client_name)

            if not pids:
                time.sleep(interval)
                continue

            conns = get_tcp_connections()
            proxy_conns = extract_proxy_connections(conns, pids)

            new_count = 0
            for pc in proxy_conns:
                key = f"{pc['ip']}:{pc['port']}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    new_count += 1
                    try:
                        hostname = socket.gethostbyaddr(pc['ip'])[0]
                    except (socket.herror, socket.gaierror, Exception):
                        hostname = ""
                    all_nodes.append(Node(
                        name=hostname or f"node-{pc['port']}",
                        protocol="tcp",
                        server=pc['ip'],
                        port=pc['port'],
                        raw={"hostname": hostname, "source": "network_monitor"},
                    ))
                    print(f"  [{time.strftime('%H:%M:%S')}] NEW: {pc['ip']}:{pc['port']} ({hostname})")

            if new_count > 0 and detector:
                # 保存快照
                snap = Snapshot(
                    airport=slug,
                    ts=store.now_iso(),
                    source=f"network_monitor:{client_name or 'auto'}",
                    nodes=all_nodes,
                    meta={"scans": scans + 1, "total_seen": len(all_nodes)},
                )
                from .collect import _enrich_and_detect
                snap.findings = _enrich_and_detect(slug, all_nodes, detector)
                path = store.save(snap)
                changes = store.diff_latest(slug)
                emit(slug, snap.findings, changes)
                print(f"  [watch-net] 快照已保存: {len(all_nodes)} 节点 → {path}")

            scans += 1
            if max_scans and scans >= max_scans:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        pass

    # 最终保存
    if all_nodes:
        snap = Snapshot(
            airport=slug,
            ts=store.now_iso(),
            source=f"network_monitor:{client_name or 'auto'}",
            nodes=all_nodes,
            meta={"scans": scans, "total_seen": len(all_nodes)},
        )
        if detector:
            from .collect import _enrich_and_detect
            snap.findings = _enrich_and_detect(slug, all_nodes, detector)
        path = store.save(snap)
        print(f"\n[watch-net] 最终: {len(all_nodes)} 节点 → {path}")
