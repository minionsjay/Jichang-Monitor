import ctypes, ctypes.wintypes as wt, json, sys
PROCESS_VM_READ = 0x0010; PROCESS_QUERY_INFORMATION = 0x0400
kernel32 = ctypes.windll.kernel32
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),("AllocationProtect", wt.DWORD),("RegionSize", ctypes.c_size_t),("State", wt.DWORD),("Protect", wt.DWORD),("Type", wt.DWORD)]
MEM_COMMIT = 0x1000; PAGE_GUARD = 0x100; PAGE_NOACCESS = 0x01
pid = int(sys.argv[1])
h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
addr = 0; mbi = MBI(); mbi_size = ctypes.sizeof(mbi)
ctxs = []
while addr < 0x7fffffffffff:
    r = kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size)
    if r == 0: break
    rs = mbi.RegionSize
    if rs == 0: break
    if mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD) and mbi.Protect != PAGE_NOACCESS:
        if 0 < rs < 100*1024*1024:
            buf = ctypes.create_string_buffer(rs)
            br = ctypes.c_size_t(0)
            if kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, rs, ctypes.byref(br)):
                data = buf.raw[:br.value]
                for needle in (b"grant", b"X-Subscribe-Token"):
                    start = 0
                    while True:
                        i = data.find(needle, start)
                        if i < 0: break
                        ctx = data[max(0,i-300):i+400]
                        t = ctx.decode('utf-8', errors='replace')
                        if any(k in t for k in ('subscribe', 'Subscribe', 'token', 'url', 'http')):
                            ctxs.append(t)
                        start = i + 1
                        if len(ctxs) > 60: break
    addr += rs
kernel32.CloseHandle(h)
out = [''.join(ch if 0x20 <= ord(ch) < 0x7f else '·' for ch in c) for c in ctxs]
print(json.dumps(out, ensure_ascii=False))
