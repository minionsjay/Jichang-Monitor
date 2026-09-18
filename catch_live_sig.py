import ctypes, ctypes.wintypes as wt, re, json, sys, time, threading
import http.client

PROCESS_VM_READ = 0x0010; PROCESS_QUERY_INFORMATION = 0x0400
kernel32 = ctypes.windll.kernel32
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),("AllocationProtect", wt.DWORD),("RegionSize", ctypes.c_size_t),("State", wt.DWORD),("Protect", wt.DWORD),("Type", wt.DWORD)]
MEM_COMMIT = 0x1000; PAGE_GUARD = 0x100; PAGE_NOACCESS = 0x01
pid = int(sys.argv[1])
h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
if not h:
    print("OpenProcess failed"); sys.exit(1)

NEEDLES = [b"X-Channel-Sig: ", b'"signature":"' ]
results = []
scan_count = [0]
stop = [False]

def trigger_traffic():
    # 通过QQT本地代理发请求 → 触发 device.flow_events 上报(带签名请求)
    while not stop[0]:
        try:
            c = http.client.HTTPConnection('127.0.0.1', 21081, timeout=5)
            c.request('GET', 'http://example.com/', headers={'Host': 'example.com'})
            r = c.getresponse(); r.read()
            c.close()
        except Exception:
            pass
        time.sleep(2)

def scan_once():
    addr = 0; mbi = MBI(); mbi_size = ctypes.sizeof(mbi)
    found = []
    while addr < 0x7fffffffffff:
        r = kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size)
        if r == 0: break
        rs = mbi.RegionSize
        if rs == 0: break
        if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD) and mbi.Protect != PAGE_NOACCESS:
            if 0 < rs < 8*1024*1024:  # 只扫小区域加快速度
                buf = ctypes.create_string_buffer(rs)
                br = ctypes.c_size_t(0)
                if kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, rs, ctypes.byref(br)):
                    data = buf.raw[:br.value]
                    for n in NEEDLES:
                        start = 0
                        while True:
                            i = data.find(n, start)
                            if i < 0: break
                            # X-Channel-Sig: 后面跟值 → 排除纯常量(常量后面是\x00或非hex)
                            ctx = data[i:i+300]
                            if n == b"X-Channel-Sig: ":
                                m = re.match(rb'X-Channel-Sig: ([0-9a-f]{16,512})', ctx)
                                if m:
                                    found.append(('header', m.group(1).decode()))
                            else:
                                # 完整信封(带真实签名的请求体)
                                m = re.search(rb'\{"encrypted_data":"[^"]+","iv":"[^"]+","tag":"[^"]+","timestamp":\d+,"signature":"[0-9a-f]{64}"\}', data[max(0,i-600):i+700])
                                if m:
                                    found.append(('envelope', m.group().decode()))
                            start = i + 1
        addr += rs
    scan_count[0] += 1
    return found

t = threading.Thread(target=trigger_traffic, daemon=True)
t.start()
t0 = time.time()
print("实时捕获中(触发流量+每轮扫描)…")
seen = set()
while time.time() - t0 < 150:
    found = scan_once()
    for kind, val in found:
        if val not in seen:
            seen.add(val)
            print(f"[{time.strftime('%H:%M:%S')}] ★ {kind}: {val[:180]}")
            results.append((kind, val))
    if results:
        # 再扫几轮收集更多, 然后停
        time.sleep(1)
        if len(seen) >= 3:
            break
    time.sleep(0.8)
stop[0] = True
print(f"\n扫描轮数: {scan_count[0]}, 捕获: {len(results)} 条")
json.dump(results, open(sys.argv[2], 'w'), indent=1)
