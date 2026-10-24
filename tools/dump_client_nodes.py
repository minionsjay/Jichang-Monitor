# -*- coding: utf-8 -*-
"""从客户端 core 进程内存里捞**完整**节点配置（含 uuid/password/servername），写成 data/client_nodes/<slug>.json。

背景：客户端型机场（qingyunti/ssrdog/speedcat/fastlink 等）用 scan-memory 只能拿到
IP:端口碎片（protocol=unknown），无法导出成 mihomo 配置。它们的完整节点只存在于
core 进程内存里（青云梯极速版甚至用 .memory-only-v2 明确不落盘）。本脚本按
(server,port) 从内存里的 "proxies":[ JSON 数组取完整对象。

用法（客户端要**先手动打开并保持运行**）：
    python -X utf8 tools/dump_client_nodes.py --slug qingyunti
    python -X utf8 tools/dump_client_nodes.py --slug qingyunti --process ApexCore --pid 12345
之后跑 `python -X utf8 -m airmon.nodeset` 重新导出 nodes/<slug>.yaml。

原始 dump（FlClash/Mihomo 系客户端 core 进程内存中提取"proxies":[...]）。

原理：FlClash 把合并后的运行期配置以 JSON 交给 core，core 常驻内存（含全部 uuid/password/servername）。
本探针在可读内存区定位 b'"proxies":['，用括号配平取出完整数组，UTF-8 解码后转成 Clash YAML/JSON。

用法: python -X utf8 .tmp_ver/dump_config_mem.py <pid> <slug>
输出: .tmp_ver/profiles/<slug>.yaml （内容是 {"proxies":[...]} 的 JSON，YAML 可直接加载）
"""
import ctypes
import ctypes.wintypes as wt
import json
import os
import sys
import time

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_VM_READ, PROCESS_QUERY_INFORMATION = 0x10, 0x400
MEM_COMMIT, PAGE_GUARD = 0x1000, 0x100
READABLE = (0x02, 0x04, 0x20, 0x40)
MARK = b'"proxies":['


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wt.DWORD), ('RegionSize', ctypes.c_size_t),
                ('State', wt.DWORD), ('Protect', wt.DWORD), ('Type', wt.DWORD)]


def balanced_array(data: bytes, start: int) -> bytes | None:
    """start 指向 '['，返回配平的数组字节（考虑 JSON 字符串与转义）。"""
    depth = 0
    i = start
    n = len(data)
    in_str = False
    esc = False
    while i < n:
        c = data[i]
        if in_str:
            if esc:
                esc = False
            elif c == 0x5C:
                esc = True
            elif c == 0x22:
                in_str = False
        else:
            if c == 0x22:
                in_str = True
            elif c == 0x5B:  # [
                depth += 1
            elif c == 0x5D:  # ]
                depth -= 1
                if depth == 0:
                    return data[start:i + 1]
        i += 1
    return None


def main(pid: int, slug: str, proc_name: str = "core"):
    h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        print(json.dumps({'error': f'OpenProcess failed err={ctypes.get_last_error()}'}))
        return
    found = {}
    mb = 0.0
    addr, mbi = 0, MBI()
    while kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        base, size = mbi.BaseAddress or 0, mbi.RegionSize or 0
        if (mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in READABLE
                and not (mbi.Protect & PAGE_GUARD) and 0 < size < 512 * 1024 * 1024):
            buf = ctypes.create_string_buffer(size)
            read = ctypes.c_size_t(0)
            if kernel32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, ctypes.c_size_t(size), ctypes.byref(read)):
                data = buf.raw[:read.value]
                mb += len(data) / 1048576
                pos = data.find(MARK)
                while pos >= 0:
                    arr = balanced_array(data, pos + len(b'"proxies":'))
                    if arr:
                        try:
                            for obj in json.loads(arr.decode('utf-8', 'replace')):
                                if not isinstance(obj, dict) or not obj.get('server'):
                                    continue
                                key = (obj.get('type'), obj.get('server'), obj.get('port'), obj.get('name'))
                                found.setdefault(key, obj)
                        except Exception:
                            pass
                    pos = data.find(MARK, pos + 1)
        addr = base + size
        if addr <= 0:
            break
    kernel32.CloseHandle(h)
    nodes = list(found.values())
    os.makedirs('.tmp_ver/profiles', exist_ok=True)
    with open(f'.tmp_ver/profiles/{slug}.yaml', 'w', encoding='utf-8') as f:
        json.dump({'proxies': nodes}, f, ensure_ascii=False, indent=1)
    # 一等来源：data/client_nodes/<slug>.json（airmon.nodeset._client_nodes 会读它）
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'client_nodes')
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, slug + '.json')
    stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    with open(path, 'w', encoding='utf-8') as f:
        json.dump({'extracted_at': stamp, 'slug': slug, 'source': 'mem:' + str(proc_name),
                   'nodes': nodes}, f, ensure_ascii=False, indent=1)
    types = {}
    for n in nodes:
        types[n.get('type')] = types.get(n.get('type'), 0) + 1
    print(json.dumps({'pid': pid, 'scanned_mb': round(mb, 1), 'nodes': len(nodes), 'types': types, 'out': path},
                     ensure_ascii=False))


def find_pid(name: str):
    import subprocess
    r = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {name}.exe', '/FO', 'CSV', '/NH'], capture_output=True)
    for line in (r.stdout or b'').decode('gbk', 'replace').strip().splitlines():
        parts = line.strip('"').split('","')
        if len(parts) >= 2 and parts[0].lower() == f'{name}.exe'.lower():
            return int(parts[1])
    return None


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='从客户端 core 内存提取完整节点 → data/client_nodes/<slug>.json')
    ap.add_argument('--slug', required=False, help='机场 slug，如 qingyunti')
    ap.add_argument('--process', default='ApexCore', help='core 进程名（不含 .exe），默认 ApexCore')
    ap.add_argument('--pid', type=int, default=0, help='直接指定 PID')
    a = ap.parse_args()
    if len(sys.argv) >= 3 and not sys.argv[1].startswith('-'):
        main(int(sys.argv[1]), sys.argv[2], 'core'); raise SystemExit(0)
    if not a.slug:
        ap.error('--slug 必填')
    pid = a.pid or find_pid(a.process)
    if not pid:
        raise SystemExit(f'未找到 {a.process}.exe，请先手动打开客户端并保持运行')
    main(pid, a.slug, a.process)
