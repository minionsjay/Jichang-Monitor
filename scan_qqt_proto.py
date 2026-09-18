import ctypes, ctypes.wintypes as wt, re, json, sys
PROCESS_VM_READ = 0x0010; PROCESS_QUERY_INFORMATION = 0x0400
kernel32 = ctypes.windll.kernel32
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),("AllocationProtect", wt.DWORD),("RegionSize", ctypes.c_size_t),("State", wt.DWORD),("Protect", wt.DWORD),("Type", wt.DWORD)]
MEM_COMMIT = 0x1000; PAGE_GUARD = 0x100; PAGE_NOACCESS = 0x01
pid = int(sys.argv[1])
h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
if not h:
    print(json.dumps({"error": "OpenProcess failed"})); sys.exit(0)
addr = 0; mbi = MBI(); mbi_size = ctypes.sizeof(mbi)
PATTERNS = {
    "key_register_body": rb'\{[^{}]{0,200}(?:public_key|publicKey)[^{}]{0,500}\}',
    "query_body": rb'\{[^{}]{0,100}"encrypted_data"[^{}]{0,400}\}',
    "session_token": rb'"auth_v2_session_token"\s*:\s*"[^"]{10,120}"',
    "login_json": rb'\{[^{}]{0,100}"(?:email|account|password)"[^{}]{0,200}\}',
    "aes_key_hex": rb'"[a-f0-9]{64}"',
    "device_id": rb'"device_id"\s*:\s*"[0-9a-f\-]{16,64}"',
    "channel_sig": rb'X-Channel-Sig[^\x00]{0,100}',
    "pem_pub": rb'-----BEGIN PUBLIC KEY-----[\s\S]{20,80}',
    "api_resp": rb'\{"code":\d+,"(?:encrypted_data|data)"[^\x00]{0,200}',
    "node_names": rb'"(?:A0[1-5]|B0[12])[^"]{0,20}"',
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
                        except Exception: val = str(m.group()[:120])
                        found.setdefault(label, {}).setdefault(val, 0)
                        found[label][val] += 1
    addr += rs
kernel32.CloseHandle(h)
out = {}
for label, vals in found.items():
    out[label] = dict(sorted(vals.items(), key=lambda kv: -kv[1])[:10])
print(json.dumps({"pid": pid, "scanned_mb": round(count/1024/1024,1), "results": out}, ensure_ascii=False, indent=1))
