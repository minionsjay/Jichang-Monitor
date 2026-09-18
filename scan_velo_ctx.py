import ctypes, ctypes.wintypes as wt, re, json, sys
PROCESS_VM_READ = 0x0010; PROCESS_QUERY_INFORMATION = 0x0400
kernel32 = ctypes.windll.kernel32
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),("AllocationProtect", wt.DWORD),("RegionSize", ctypes.c_size_t),("State", wt.DWORD),("Protect", wt.DWORD),("Type", wt.DWORD)]
MEM_COMMIT = 0x1000; PAGE_GUARD = 0x100; PAGE_NOACCESS = 0x01
pid = int(sys.argv[1])
h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
if not h:
    print(json.dumps({"error": f"OpenProcess failed"})); sys.exit(0)
addr = 0; mbi = MBI(); mbi_size = ctypes.sizeof(mbi)
NEEDLES = [b"challenge_signature", b"aero-device-challenge", b'"device_proof"', b'"nonce"', b'attest']
contexts = {n.decode(): [] for n in NEEDLES}
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
                for n in NEEDLES:
                    start = 0
                    while len(contexts[n.decode()]) < 8:
                        i = data.find(n, start)
                        if i < 0: break
                        ctx = data[max(0,i-500):i+800]
                        contexts[n.decode()].append(ctx)
                        start = i + 1
    addr += rs
kernel32.CloseHandle(h)
# 输出可打印片段
out = {}
for k, ctxs in contexts.items():
    arr = []
    for c in ctxs:
        # 提取可打印ASCII/UTF8片段
        txt = c.decode('utf-8', errors='replace')
        txt = re.sub(r'[^\x20-\x7e\u4e00-\u9fff\n]', '·', txt)
        arr.append(txt)
    out[k] = arr
print(json.dumps(out, ensure_ascii=False, indent=1))
