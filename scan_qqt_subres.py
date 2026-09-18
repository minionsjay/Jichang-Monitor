import ctypes, ctypes.wintypes as wt, re, json, sys
PROCESS_VM_READ = 0x0010; PROCESS_QUERY_INFORMATION = 0x0400
kernel32 = ctypes.windll.kernel32
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),("AllocationProtect", wt.DWORD),("RegionSize", ctypes.c_size_t),("State", wt.DWORD),("Protect", wt.DWORD),("Type", wt.DWORD)]
MEM_COMMIT = 0x1000; PAGE_GUARD = 0x100; PAGE_NOACCESS = 0x01
pid = int(sys.argv[1])
h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
addr = 0; mbi = MBI(); mbi_size = ctypes.sizeof(mbi)
PATTERNS = {
    "sub_response": rb'\{"c":0,"d":\{"[a-z_]*(?:sub|node|server)[a-z_]*":[\s\S]{0,3000}',
    "node_array": rb'"(?:nodes|servers|node_list)"\s*:\s*\[[\s\S]{0,2500}?\]',
    "routing_rules": rb'"[a-z_]*rout[a-z_]*"[\s\S]{0,300}',
    "a01_names": rb'"[AB]0[0-9]-[^"]{2,30}"',
    "sub_url": rb'(?:sub|subscribe)[a-z_]*_?url[a-z_]*"?\s*[:=]\s*"[^"]{10,200}"',
    "login_resp": rb'\{"c":\d+,"d":\{"[^"]*(?:token|session)[^"]*[\s\S]{0,400}',
}
found = {k: {} for k in PATTERNS}
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
                for label, pattern in PATTERNS.items():
                    for m in re.finditer(pattern, data):
                        try: val = m.group().decode('utf-8', errors='replace')
                        except Exception: continue
                        found[label].setdefault(val[:2000], 0)
                        found[label][val[:2000]] += 1
    addr += rs
kernel32.CloseHandle(h)
print(json.dumps({k: dict(sorted(v.items(), key=lambda x: -x[1])[:6]) for k, v in found.items()}, ensure_ascii=False, indent=1))
