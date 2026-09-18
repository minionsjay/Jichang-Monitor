import ctypes, ctypes.wintypes as wt, re, sys, time, threading, json
import http.client
PROCESS_VM_READ = 0x0010; PROCESS_QUERY_INFORMATION = 0x0400
kernel32 = ctypes.windll.kernel32
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),("AllocationProtect", wt.DWORD),("RegionSize", ctypes.c_size_t),("State", wt.DWORD),("Protect", wt.DWORD),("Type", wt.DWORD)]
MEM_COMMIT = 0x1000; PAGE_GUARD = 0x100; PAGE_NOACCESS = 0x01
pid = int(sys.argv[1])
h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
KNOWN = set(json.load(open(sys.argv[3])) if len(sys.argv) > 3 else [])
stop = [False]
def trigger():
    while not stop[0]:
        try:
            c = http.client.HTTPConnection('127.0.0.1', 21081, timeout=5)
            c.request('GET', 'http://example.com/')
            c.getresponse().read(); c.close()
        except Exception: pass
        time.sleep(1.5)
def find_new():
    addr = 0; mbi = MBI(); mbi_size = ctypes.sizeof(mbi)
    news = []
    while addr < 0x7fffffffffff:
        r = kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size)
        if r == 0: break
        rs = mbi.RegionSize
        if rs == 0: break
        if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD) and mbi.Protect != PAGE_NOACCESS:
            if 0 < rs < 4*1024*1024:
                buf = ctypes.create_string_buffer(rs)
                br = ctypes.c_size_t(0)
                if kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, rs, ctypes.byref(br)):
                    data = buf.raw[:br.value]
                    for m in re.finditer(rb'"timestamp":(17\d{8}),', data):
                        ts = m.group(1).decode()
                        if ts not in KNOWN and int(ts) > 1789634691:
                            # 找完整信封
                            s = data.rfind(b'{"encrypted_data"', max(0, m.start()-4000), m.start())
                            if s >= 0:
                                e = data.find(b'}', m.end())
                                if e > 0:
                                    env = data[s:e+1]
                                    if b'"signature"' in env:
                                        news.append(env.decode('utf-8', errors='replace'))
                                        KNOWN.add(ts)
        addr += rs
    return news
threading.Thread(target=trigger, daemon=True).start()
print("等待新信封(触发流量)…", flush=True)
t0 = time.time()
new_env = None
while time.time() - t0 < 120 and not new_env:
    news = find_new()
    if news:
        new_env = news[0]
        print(f"[{time.strftime('%H:%M:%S')}] ★ 新信封! {new_env[:100]}…", flush=True)
        break
    time.sleep(1.5)
stop[0] = True
if new_env:
    # 立刻全量dump
    print("立即dump全量内存…", flush=True)
    addr = 0
    mbi = MBI(); mbi_size = ctypes.sizeof(mbi)
    f = open(sys.argv[2], 'wb')
    total = 0
    while addr < 0x7fffffffffff:
        r = kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size)
        if r == 0: break
        rs = mbi.RegionSize
        if rs == 0: break
        if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD) and mbi.Protect != PAGE_NOACCESS and 0 < rs < 64*1024*1024:
            buf = ctypes.create_string_buffer(rs)
            br = ctypes.c_size_t(0)
            if kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, rs, ctypes.byref(br)) and br.value:
                f.write(buf.raw[:br.value]); total += br.value
        addr += rs
    f.close()
    print(f"dump {total/1024/1024:.0f}MB 完成", flush=True)
    open(sys.argv[2] + '.env', 'w').write(new_env)
else:
    print("120秒内无新信封", flush=True)
