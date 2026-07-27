"""Windows 进程内存扫描采集器 — 从 Clash/mihomo 内核进程内存提取节点。

适用于配置文件被加密的客户端（万达云、SpeedCat 等 FlClash 变种）。
需要管理员权限运行（OpenProcess(PROCESS_VM_READ)）。

使用方式：
  python3 run.py scan-memory --airport wandacloud --client wandacloud
  python3 run.py scan-memory --airport speedcat --client SpeedCat
  python3 run.py scan-memory --airport wandacloud --pid 12345

原理：mihomo 内核在解析配置后，节点信息以 Go 结构体形式存储在堆内存中。
搜索 server/port/password/anytls/vless 等关键词即可提取明文节点数据。
"""
from __future__ import annotations

import json
import os
import re
import socket
import struct
import subprocess
import sys

from .models import Node, Snapshot, Finding
from . import store


# ---- Windows API 定义 ----

def _is_windows():
    return sys.platform == "win32" or os.name == "nt"

def _win_api():
    import ctypes
    import ctypes.wintypes as wt
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    kernel32 = ctypes.windll.kernel32
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ('BaseAddress', ctypes.c_void_p),
            ('AllocationBase', ctypes.c_void_p),
            ('AllocationProtect', wt.DWORD),
            ('RegionSize', ctypes.c_size_t),
            ('State', wt.DWORD),
            ('Protect', wt.DWORD),
            ('Type', wt.DWORD),
        ]
    MEM_COMMIT = 0x1000
    PAGE_GUARD = 0x100
    PAGE_NOACCESS = 0x01
    return kernel32, MEMORY_BASIC_INFORMATION, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS


# ---- 搜索模式 ----

# 使用 bytes 模式搜索原始内存，匹配后用 UTF-8 解码（支持中文节点名）
SEARCH_PATTERNS = {
    # JSON 格式的节点配置：完整 JSON 对象包含 server+port
    'json_node': rb'"server"\s*:\s*"([^"]{3,100})"[^}]*?"port"\s*:\s*(\d+)',
    # anytls/vless 节点片段（包含 server 和 port）
    'anytls_frag': rb'anytls[^}]{0,500}"server"\s*:\s*"([^"]{3,100})"[^}]*?"port"\s*:\s*(\d+)',
    'vless_frag': rb'vless[^}]{0,500}"server"\s*:\s*"([^"]{3,100})"[^}]*?"port"\s*:\s*(\d+)',
    # 完整节点 JSON 对象（name+server+port+password）
    'full_node': rb'\{[^}]*"name"[^}]*"server"\s*:\s*"([^"]{3,100})"[^}]*"port"\s*:\s*(\d+)[^}]*"password"\s*:\s*"([^"]{3,64})"[^}]*\}',
    # IP:port 对（非本地）
    'ip_port': rb'(?<![0-9.])((?:\d{1,3}\.){3}\d{1,3}):(\d{4,5})(?![0-9.])',
    # domain:port 对
    'domain_port': rb'([a-z0-9][a-z0-9._-]+\.[a-z]{2,10}):(\d{4,5})',
    # password/UUID 字段（单独搜索，用于关联到已有节点）
    'password': rb'"password"\s*:\s*"([a-f0-9\-]{20,64})"',
    'uuid': rb'"uuid"\s*:\s*"([a-f0-9\-]{20,64})"',
    # external-controller 和 secret
    'external_controller': rb'external.controller[^\\x00]{0,80}',
    'secret': rb'secret[":\s]{1,5}([a-zA-Z0-9_\-]{6,64})',
}


# ---- 进程查找 ----

def find_pids(keywords: list[str]) -> list[tuple[str, int]]:
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
                            pids.append((parts[0].strip('"'), int(parts[1])))
                        except ValueError:
                            pass
                    break
        return pids
    except Exception:
        return []


def find_clash_pids(client_name: str = None) -> list[tuple[str, int]]:
    if client_name:
        keywords = [client_name + "Core", client_name + "core", client_name]
    else:
        keywords = ['clash', 'mihomo', 'v2ray', 'xray', 'sing-box',
                     'wandacloudCore', 'SpeedCatCore', 'flclash', 'verge']
    return find_pids(keywords)


# ---- 内存扫描 ----

def scan_process_memory(pid: int) -> dict:
    """扫描进程内存，返回所有匹配的字符串。用 UTF-8 解码（支持中文）。"""
    if not _is_windows():
        return _scan_via_interop(pid)

    import ctypes
    kernel32, MBI, VM_READ, QUERY_INFO, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS = _win_api()

    h = kernel32.OpenProcess(VM_READ | QUERY_INFO, False, pid)
    if not h:
        err = kernel32.GetLastError()
        return {"error": f"OpenProcess({pid}) failed: error {err}" +
                (" (需要管理员权限!)" if err == 5 else "")}

    addr = 0
    mbi = MBI()
    mbi_size = ctypes.sizeof(mbi)
    found_items = []
    regions = 0
    total = 0

    while addr < 0x7fffffffffff:
        result = kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size)
        if result == 0:
            break
        region_size = mbi.RegionSize
        if region_size == 0:
            break
        if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD) and mbi.Protect != PAGE_NOACCESS:
            if 0 < region_size < 100 * 1024 * 1024:
                buf = ctypes.create_string_buffer(region_size)
                bytes_read = ctypes.c_size_t(0)
                if kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, region_size, ctypes.byref(bytes_read)):
                    data = buf.raw[:bytes_read.value]
                    total += len(data)
                    regions += 1
                    for label, pattern in SEARCH_PATTERNS.items():
                        for m in re.finditer(pattern, data):
                            # 用 UTF-8 解码（支持中文节点名），失败回退 ASCII
                            try:
                                val = m.group().decode('utf-8', errors='replace')
                            except Exception:
                                val = m.group().decode('ascii', errors='replace')
                            found_items.append({"label": label, "value": val})
        addr += region_size

    kernel32.CloseHandle(h)
    return {"pid": pid, "regions_scanned": regions, "total_mb": round(total / 1024 / 1024, 1), "found_items": found_items}


def _scan_via_interop(pid: int) -> dict:
    """从 WSL 调用 Windows Python 执行内存扫描。"""
    # 生成一个临时脚本在 Windows 侧运行
    script = (
        'import ctypes, ctypes.wintypes as wt, struct, re, json, sys\n'
        'PROCESS_VM_READ = 0x0010\n'
        'PROCESS_QUERY_INFORMATION = 0x0400\n'
        'kernel32 = ctypes.windll.kernel32\n'
        'class MBI(ctypes.Structure):\n'
        '    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),("AllocationProtect", wt.DWORD),("RegionSize", ctypes.c_size_t),("State", wt.DWORD),("Protect", wt.DWORD),("Type", wt.DWORD)]\n'
        'MEM_COMMIT = 0x1000\n'
        'PAGE_GUARD = 0x100\n'
        'PAGE_NOACCESS = 0x01\n'
        'PATTERNS = {\n'
        '    "json_node": rb\'"server"\\s*:\\s*"([^"]{3,100})"[^}]*?"port"\\s*:\\s*(\\d+)\',\n'
        '    "anytls_frag": rb\'anytls[^}]{0,500}"server"\\s*:\\s*"([^"]{3,100})"[^}]*?"port"\\s*:\\s*(\\d+)\',\n'
        '    "vless_frag": rb\'vless[^}]{0,500}"server"\\s*:\\s*"([^"]{3,100})"[^}]*?"port"\\s*:\\s*(\\d+)\',\n'
        '    "full_node": rb\'{[^}]*"name"[^}]*"server"\\s*:\\s*"([^"]{3,100})"[^}]*"port"\\s*:\\s*(\\d+)[^}]*"password"\\s*:\\s*"([^"]{3,64})"[^}]*}\',\n'
        '    "ip_port": rb\'(?<![0-9.])((?:\\d{1,3}\\.){3}\\d{1,3}):(\\d{4,5})(?![0-9.])\',\n'
        '    "domain_port": rb\'([a-z0-9][a-z0-9._-]+\\.[a-z]{2,10}):(\\d{4,5})\',\n'
        '    "password": rb\'"password"\\s*:\\s*"([a-f0-9\\-]{20,64})"\',\n'
        '    "uuid": rb\'"uuid"\\s*:\\s*"([a-f0-9\\-]{20,64})"\',\n'
        '    "external_controller": rb\'external.controller[^\\x00]{0,80}\',\n'
        '    "secret": rb\'secret[":\\s]{1,5}([a-zA-Z0-9_\\-]{6,64})\',\n'
        '}\n'
        f'pid = {pid}\n'
        'h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)\n'
        'if not h:\n'
        '    print(json.dumps({"error": f"OpenProcess({pid}) failed: error {kernel32.GetLastError()}"}))\n'
        '    sys.exit(0)\n'
        'addr = 0\n'
        'mbi = MBI()\n'
        'mbi_size = ctypes.sizeof(mbi)\n'
        'found = []\n'
        'regions = 0\n'
        'total = 0\n'
        'while addr < 0x7fffffffffff:\n'
        '    r = kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size)\n'
        '    if r == 0: break\n'
        '    rs = mbi.RegionSize\n'
        '    if rs == 0: break\n'
        '    if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD) and mbi.Protect != PAGE_NOACCESS:\n'
        '        if 0 < rs < 100*1024*1024:\n'
        '            buf = ctypes.create_string_buffer(rs)\n'
        '            br = ctypes.c_size_t(0)\n'
        '            if kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, rs, ctypes.byref(br)):\n'
        '                data = buf.raw[:br.value]\n'
        '                total += len(data)\n'
        '                regions += 1\n'
        '                for label, pattern in PATTERNS.items():\n'
        '                    for m in re.finditer(pattern, data):\n'
        '                        try:\n'
        '                            val = m.group().decode("utf-8", errors="replace")\n'
        '                        except:\n'
        '                            val = m.group().decode("ascii", errors="replace")\n'
        '                        found.append({"label": label, "value": val})\n'
        '    addr += rs\n'
        'kernel32.CloseHandle(h)\n'
        'print(json.dumps({"pid": pid, "regions": regions, "total_mb": round(total/1024/1024,1), "found_items": found}))\n'
    )

    try:
        result = subprocess.run(
            ['cmd.exe', '/c', 'python', '-c', script],
            capture_output=True, timeout=120
        )
        output = result.stdout.decode('utf-8', errors='replace').strip()
        if output:
            return json.loads(output)
    except Exception as e:
        return {"error": f"interop scan failed: {e}"}
    return {"error": "interop scan: no output"}


# ---- 节点提取 ----

# 非代理域名
SKIP_DOMAINS = {
    'www.gstatic.com', 'dns.alidns.com', 'dns.cloudflare.com',
    'api2.cursor.sh', 'gemini.google.com', 'github.com',
    'metacubex.com', 'rulesdns.alidns.com', 'img.alicdn.com',
    'o.alicdn.com', 'staticfile.org',
}

# 非代理 IP
SKIP_IPS = {
    '1.1.1.1', '8.8.8.8', '8.8.4.4', '223.5.5.5', '223.6.6.6',
    '1.12.12.21', '162.159.61.8', '104.21.44.93',
    '127.0.0.1', '0.0.0.0',
}


def extract_nodes(found_items: list[dict]) -> list[Node]:
    """从内存扫描结果提取结构化节点。用 UTF-8 解码的值支持中文节点名。"""
    nodes = {}
    # 收集所有 password/UUID，用于后续关联
    all_passwords = set()
    all_uuids = set()
    for item in found_items:
        if item["label"] in ("password", "uuid"):
            m = re.search(r'"(?:password|uuid)"\s*:\s*"([^"]+)"', item["value"])
            if m:
                all_passwords.add(m.group(1))
        if item["label"] == "uuid":
            m = re.search(r'"uuid"\s*:\s*"([^"]+)"', item["value"])
            if m:
                all_uuids.add(m.group(1))

    for item in found_items:
        val = item["value"]
        label = item["label"]

        # JSON node / anytls_frag / vless_frag / full_node
        if label in ("json_node", "anytls_frag", "vless_frag", "full_node"):
            # 提取 server 和 port
            m = re.search(r'"server"\s*:\s*"([^"]+)"[^}]*?"port"\s*:\s*(\d+)', val)
            if not m:
                # 也尝试 port 在 server 前面的情况
                m = re.search(r'"port"\s*:\s*(\d+)[^}]*?"server"\s*:\s*"([^"]+)"', val)
                if m:
                    port, server = int(m.group(1)), m.group(2)
                else:
                    continue
            else:
                server, port = m.group(1), int(m.group(2))

            if server in SKIP_IPS or server in ('1.1.1.1', '127.0.0.1', '0.0.0.0'):
                continue

            # 提取 name（用 UTF-8 解码的值，支持中文）
            name_m = re.search(r'"name"\s*:\s*"([^"]*)"', val)
            if name_m:
                name = name_m.group(1)
                # 清理不可打印字符（保留中文和 emoji）
                name = re.sub(r'[\x00-\x1f]', '', name)
            else:
                name = f"node-{port}"

            # 提取 password
            pass_m = re.search(r'"password"\s*:\s*"([^"]+)"', val)
            password = pass_m.group(1) if pass_m else ""

            # 提取 uuid（vless 用）
            uuid_m = re.search(r'"uuid"\s*:\s*"([^"]+)"', val)
            uuid_val = uuid_m.group(1) if uuid_m else ""

            # 协议
            proto = 'anytls' if 'anytls' in val else ('vless' if 'vless' in val else 'unknown')

            # SNI
            sni_m = re.search(r'"sni"\s*:\s*"([^"]+)"', val)
            sni_val = sni_m.group(1) if sni_m else ""

            key = f"{server}:{port}"
            if key not in nodes:
                raw = {"source": "memory_scan"}
                if password:
                    raw["password"] = password
                if uuid_val:
                    raw["uuid"] = uuid_val
                if sni_val:
                    raw["sni"] = sni_val
                nodes[key] = Node(name=name, protocol=proto, server=server,
                                  port=port, raw=raw)

        # IP:port pairs
        elif label == "ip_port":
            m = re.match(r'(\d+\.\d+\.\d+\.\d+):(\d+)', val)
            if m:
                ip, port = m.group(1), int(m.group(2))
                if ip in SKIP_IPS or ip.startswith('127.') or ip.startswith('0.') or ip.startswith('192.168.') or ip.startswith('10.'):
                    continue
                key = f"{ip}:{port}"
                if key not in nodes:
                    nodes[key] = Node(name=f"node-{port}", protocol="unknown",
                                      server=ip, port=port, raw={"source": "memory_scan"})

        # domain:port pairs
        elif label == "domain_port":
            m = re.match(r'([a-z0-9][a-z0-9._-]+\.[a-z]{2,10}):(\d+)', val)
            if m:
                domain, port = m.group(1), int(m.group(2))
                if domain in SKIP_DOMAINS:
                    continue
                key = f"{domain}:{port}"
                if key not in nodes:
                    nodes[key] = Node(name=f"node-{port}", protocol="unknown",
                                      server=domain, port=port, raw={"source": "memory_scan"})

    # 如果有独立的 password/UUID 但没有关联到节点，
    # 尝试为所有缺密码的节点补充
    if all_passwords:
        common_pw = None
        # 找出现最频繁的 password（通常是所有节点共用一个）
        for pw in all_passwords:
            common_pw = pw  # 取最后一个（通常是正确的 UUID 格式）
        if common_pw:
            for n in nodes.values():
                if not n.raw.get("password"):
                    n.raw["password"] = common_pw

    return list(nodes.values())


def collect_memory_scan(slug: str, client_name: str = None,
                        pid: int = None, detector=None) -> Snapshot:
    """从 Clash 内核进程内存扫描提取节点。"""
    if pid:
        pids = [("manual", pid)]
    else:
        pids = find_clash_pids(client_name)

    if not pids:
        raise RuntimeError(f"未找到 {client_name or 'Clash'} 进程，请确认客户端已启动并连接")

    all_nodes = []
    meta = {"processes": []}

    for name, proc_pid in pids:
        result = scan_process_memory(proc_pid)
        if "error" in result:
            meta["processes"].append({"name": name, "pid": proc_pid, "error": result["error"]})
            continue

        meta["processes"].append({
            "name": name, "pid": proc_pid,
            "regions": result.get("regions_scanned", result.get("regions", 0)),
            "total_mb": result.get("total_mb", 0),
            "items_found": len(result.get("found_items", [])),
        })

        nodes = extract_nodes(result.get("found_items", []))
        all_nodes.extend(nodes)

    # 去重
    seen = {}
    for n in all_nodes:
        key = n.key()
        if key not in seen:
            seen[key] = n
    nodes = list(seen.values())

    snap = Snapshot(
        airport=slug,
        ts=store.now_iso(),
        source=f"memory_scan:{client_name or 'auto'}",
        nodes=nodes,
        meta=meta,
    )

    # 富化 + 检测
    if detector:
        from .collect import _enrich_and_detect
        snap.findings = _enrich_and_detect(slug, nodes, detector)

    return snap
