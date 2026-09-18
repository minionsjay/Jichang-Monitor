import ctypes, ctypes.wintypes as wt, re, json, sys
PROCESS_VM_READ = 0x0010; PROCESS_QUERY_INFORMATION = 0x0400
kernel32 = ctypes.windll.kernel32
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),("AllocationProtect", wt.DWORD),("RegionSize", ctypes.c_size_t),("State", wt.DWORD),("Protect", wt.DWORD),("Type", wt.DWORD)]
MEM_COMMIT = 0x1000; PAGE_GUARD = 0x100; PAGE_NOACCESS = 0x01
pid = int(sys.argv[1])
h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
if not h:
    print(json.dumps({"error": f"OpenProcess failed {kernel32.GetLastError()}"})); sys.exit(0)
addr = 0; mbi = MBI(); mbi_size = ctypes.sizeof(mbi)
PATTERNS = {
    "challenge_json": rb'\{[^{}]{0,200}"challenge_id"[^{}]{0,400}\}',
    "attest_body": rb'\{[^{}]{0,100}"challenge_signature"[^{}]{0,600}\}',
    "aero_prefix": rb'aero-device-challenge[a-z0-9:]{0,80}',
    "pubkey_pem": rb'-----BEGIN PUBLIC KEY-----[\s\S]{0,100}',
    "device_proof": rb'"device_proof"[^{}]{0,200}',
    "sub_url": rb'https://[0-9.]+/api/v1/client/subscribe[^"\s]{0,120}',
    "x_attest": rb'X-Device-Attest[^\x00]{0,150}',
    "sub_token": rb'"subscribe_token"[^{}]{0,150}',
    "session_tok": rb'"session_token"[^{}]{0,150}',
    "device_id": rb'"device_id"\s*:\s*"[0-9a-f]{16,64}"',
}
found = {}
count = 0
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
                count += len(data)
                for label, pattern in PATTERNS.items():
                    for m in re.finditer(pattern, data):
                        try: val = m.group().decode('utf-8', errors='replace')
                        except Exception: val = str(m.group()[:150])
                        found.setdefault(label, {}).setdefault(val, 0)
                        found[label][val] += 1
    addr += rs
kernel32.CloseHandle(h)
out = {}
for label, vals in found.items():
    out[label] = dict(sorted(vals.items(), key=lambda kv: -kv[1])[:12])
print(json.dumps({"pid": pid, "scanned_mb": round(count/1024/1024,1), "results": out}, ensure_ascii=False, indent=1))
