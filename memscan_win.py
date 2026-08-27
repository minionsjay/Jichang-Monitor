"""Windows 原生内存扫描器 — 直接在 Windows 侧运行（绕过 WSL interop）。

用法（管理员权限）:
    python memscan_win.py --pid 19872 --airport ssrdog --out scan_result.json
    python memscan_win.py --client SSRDOG --airport ssrdog --out scan_result.json

输出 JSON 兼容 airmon Snapshot 格式，可直接导入 monitor 项目。
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import re
import sys
import subprocess
from datetime import datetime, timezone

# ---- Windows API ----
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
kernel32 = ctypes.windll.kernel32


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

# ---- 搜索模式 ----
PATTERNS = {
    # sing-box JSON 格式（SSRDOG 用 sing-box， outbound 配置）
    "sb_outbound": rb'\{[^{}]{0,300}"tag"\s*:\s*"([^"]{1,80})"[^{}]{0,600}"server"\s*:\s*"([^"]{2,100})"[^{}]{0,300}"server_port"\s*:\s*(\d{2,5})',
    # 兼容 server_port 在前
    "sb_outbound2": rb'\{[^{}]{0,300}"server"\s*:\s*"([^"]{2,100})"[^{}]{0,300}"server_port"\s*:\s*(\d{2,5})',
    # clash 格式（name+server+port）
    "clash_node": rb'\{[^{}]{0,200}"name"\s*:\s*"([^"]{1,80})"[^{}]{0,400}"server"\s*:\s*"([^"]{2,100})"[^{}]{0,200}"port"\s*:\s*(\d{2,5})',
    # 通用 server+port（clash）
    "generic_sp": rb'"server"\s*:\s*"([^"]{2,100})"[^{}]{0,200}"port"\s*:\s*(\d{2,5})',
    # 协议类型标记
    "proto_anytls": rb'(?i)anytls[^{}]{0,100}',
    "proto_hysteria": rb'(?i)hysteria2?"?\s*[:{][^{}]{0,100}',
    # 密码/UUID
    "password": rb'"password"\s*:\s*"([a-zA-Z0-9\-_.=:+/]{8,100})"',
    "uuid": rb'"uuid"\s*:\s*"([a-f0-9\-]{20,64})"',
    # IP:port
    "ip_port": rb'(?<![0-9.])((?:\d{1,3}\.){3}\d{1,3}):(\d{3,5})(?![0-9.])',
    # domain:port
    "domain_port": rb'([a-z0-9][a-z0-9._-]{3,60}\.[a-z]{2,10}):(\d{3,5})',
}

SKIP_DOMAINS = {
    "www.gstatic.com", "dns.alidns.com", "dns.cloudflare.com",
    "api2.cursor.sh", "gemini.google.com", "github.com",
    "raw.githubusercontent.com", "client.crisp.chat", "api.ip.sb",
    "api4.ipify.org", "ifconfig.me", "ipv4.icanhazip.com",
    "www.msftconnecttest.com", "www.msftncsi.com", "ocsp.digicert.com",
    "crl.microsoft.com", "www.microsoft.com", "update.googleapis.com",
    "o.alicdnobjects.com", "img.alicdn.com", "cdn.jsdelivr.net",
}
SKIP_IPS = {
    "1.1.1.1", "8.8.8.8", "8.8.4.4", "223.5.5.5", "223.6.6.6",
    "119.29.29.29", "114.114.114.114", "1.12.12.21", "162.159.61.8",
    "127.0.0.1", "0.0.0.0", "192.168.1.23", "169.254.255.255",
}


def find_pid(name):
    r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, timeout=15)
    for line in r.stdout.decode("utf-8", errors="replace").split("\n"):
        if name.lower() in line.lower():
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    pass
    return None


def scan(pid):
    h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        err = kernel32.GetLastError()
        return {"error": f"OpenProcess({pid}) failed: error {err}"
                + ("（需要管理员权限！）" if err == 5 else "")}

    addr = 0
    mbi = MBI()
    mbi_size = ctypes.sizeof(mbi)
    found = []
    regions = 0
    total = 0
    MAX_REGION = 64 * 1024 * 1024

    while addr < 0x7FFFFFFFFFFFF:
        ret = kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size)
        if ret == 0:
            break
        rs = mbi.RegionSize
        if rs == 0:
            break
        if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD) and mbi.Protect != PAGE_NOACCESS:
            if 0 < rs < MAX_REGION:
                buf = ctypes.create_string_buffer(rs)
                br = ctypes.c_size_t(0)
                if kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, rs, ctypes.byref(br)):
                    data = buf.raw[: br.value]
                    total += len(data)
                    regions += 1
                    for label, pat in PATTERNS.items():
                        try:
                            for m in re.finditer(pat, data):
                                try:
                                    val = m.group().decode("utf-8", errors="replace")
                                except Exception:
                                    val = m.group().decode("ascii", errors="replace")
                                found.append({"label": label, "value": val})
                        except re.error:
                            pass
        addr += rs

    kernel32.CloseHandle(h)
    return {"pid": pid, "regions": regions, "total_mb": round(total / 1024 / 1024, 1),
            "found_items": found}


def extract_nodes(items):
    nodes = {}
    passwords = set()
    uuids = set()

    for it in items:
        if it["label"] == "password":
            m = re.search(r'"password"\s*:\s*"([^"]+)"', it["value"])
            if m:
                passwords.add(m.group(1))
        elif it["label"] == "uuid":
            m = re.search(r'"uuid"\s*:\s*"([^"]+)"', it["value"])
            if m:
                uuids.add(m.group(1))

    def add(name, server, port, proto, raw_extra=None):
        if server in SKIP_IPS or server in SKIP_DOMAINS:
            return
        if server.startswith("127.") or server.startswith("0.") or server.startswith("192.168.") or server.startswith("10."):
            return
        if server.startswith("172.") and 16 <= int(server.split(".")[1]) <= 31:
            return
        key = f"{server}:{port}"
        if key not in nodes:
            raw = {"source": "memory_scan"}
            if raw_extra:
                raw.update(raw_extra)
            nodes[key] = {"name": name, "protocol": proto, "server": server, "port": port, "raw": raw}

    for it in items:
        val, label = it["value"], it["label"]
        try:
            if label in ("sb_outbound",):
                m = re.search(r'"tag"\s*:\s*"([^"]+)"[^{}]*"server"\s*:\s*"([^"]+)"[^{}]*"server_port"\s*:\s*(\d+)', val)
                if m:
                    add(m.group(1), m.group(2), int(m.group(3)), "sing-box-outbound")
            elif label in ("sb_outbound2",):
                m = re.search(r'"server"\s*:\s*"([^"]+)"[^{}]*"server_port"\s*:\s*(\d+)', val)
                if m:
                    add(f"node-{m.group(2)}", m.group(1), int(m.group(2)), "sing-box")
            elif label == "clash_node":
                m = re.search(r'"name"\s*:\s*"([^"]+)"[^{}]*"server"\s*:\s*"([^"]+)"[^{}]*"port"\s*:\s*(\d+)', val)
                if m:
                    add(m.group(1), m.group(2), int(m.group(3)), "clash")
            elif label == "generic_sp":
                m = re.search(r'"server"\s*:\s*"([^"]+)"[^{}]*"port"\s*:\s*(\d+)', val)
                if m:
                    add(f"node-{m.group(2)}", m.group(1), int(m.group(2)), "generic")
            elif label == "ip_port":
                m = re.match(r'(\d+\.\d+\.\d+\.\d+):(\d+)', val)
                if m:
                    add(f"node-{m.group(2)}", m.group(1), int(m.group(2)), "ip")
            elif label == "domain_port":
                m = re.match(r'([a-z0-9][a-z0-9._-]+\.[a-z]{2,10}):(\d+)', val)
                if m:
                    add(f"node-{m.group(2)}", m.group(1), int(m.group(2)), "domain")
        except Exception:
            pass

    # 为缺密码的节点补上最常见密码
    common_pw = None
    if passwords:
        common_pw = max(passwords, key=lambda p: len(p))
    if common_pw:
        for n in nodes.values():
            if not n["raw"].get("password"):
                n["raw"]["password"] = common_pw

    return list(nodes.values())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int)
    ap.add_argument("--client", help="进程名（如 SSRDOG）")
    ap.add_argument("--airport", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    pid = args.pid or (find_pid(args.client or args.airport) if args.client else None)
    if not pid:
        print(f"[失败] 未找到进程: {args.client}")
        sys.exit(1)

    print(f"扫描 PID {pid} 内存...")
    result = scan(pid)
    if "error" in result:
        print(f"[失败] {result['error']}")
        sys.exit(1)

    print(f"  {result['regions']} regions, {result['total_mb']} MB, "
          f"{len(result['found_items'])} items")

    nodes = extract_nodes(result["found_items"])
    print(f"  提取节点: {len(nodes)} 个")

    # 分类统计
    by_proto = {}
    for n in nodes:
        by_proto[n["protocol"]] = by_proto.get(n["protocol"], 0) + 1
    for p, c in sorted(by_proto.items(), key=lambda x: -x[1]):
        print(f"    {p}: {c}")

    # 打印节点列表
    for n in sorted(nodes, key=lambda x: (x["protocol"], x["server"]))[:60]:
        print(f"    {n['name'][:30]:32s} {n['protocol'][:18]:20s} {n['server']}:{n['port']}")

    # 保存 Snapshot 格式
    snap = {
        "airport": args.airport,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": f"memory_scan:{args.client or 'pid' + str(pid)}",
        "nodes": nodes,
        "findings": [],
        "meta": {
            "pid": pid,
            "regions": result["regions"],
            "total_mb": result["total_mb"],
            "scan_host": "windows-native",
        },
    }
    out = args.out or f"scan_{args.airport}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(snap, f, ensure_ascii=False, indent=2)
    print(f"\n保存 → {out}")


if __name__ == "__main__":
    main()
