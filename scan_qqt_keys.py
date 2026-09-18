import ctypes, ctypes.wintypes as wt, re, json, sys
PROCESS_VM_READ = 0x0010; PROCESS_QUERY_INFORMATION = 0x0400
kernel32 = ctypes.windll.kernel32
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),("AllocationProtect", wt.DWORD),("RegionSize", ctypes.c_size_t),("State", wt.DWORD),("Protect", wt.DWORD),("Type", wt.DWORD)]
MEM_COMMIT = 0x1000; PAGE_GUARD = 0x100; PAGE_NOACCESS = 0x01
pid = int(sys.argv[1])
h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
addr = 0; mbi = MBI(); mbi_size = ctypes.sizeof(mbi)
out = {"pem_priv": [], "pem_pub": [], "hex64_ctx": [], "jwk": [], "key_field": []}
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
                for m in re.finditer(rb'-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]{0,1700}?-----END (?:RSA )?PRIVATE KEY-----', data):
                    if len(out['pem_priv']) < 3:
                        out['pem_priv'].append(m.group().decode('ascii', errors='replace'))
                for m in re.finditer(rb'-----BEGIN PUBLIC KEY-----[\s\S]{0,500}?-----END PUBLIC KEY-----', data):
                    if len(out['pem_pub']) < 4:
                        out['pem_pub'].append(m.group().decode('ascii', errors='replace'))
                for m in re.finditer(rb'\{"kty":"RSA"', data):
                    if len(out['jwk']) < 2:
                        out['jwk'].append(data[m.start():m.start()+900].decode('utf-8', errors='replace'))
                # key相关字段名上下文
                for m in re.finditer(rb'"[a-z_]*key[a-z_]*"\s*:\s*"[a-f0-9]{32,80}"', data):
                    if len(out['key_field']) < 15:
                        out['key_field'].append(m.group().decode('utf-8', errors='replace')[:150])
    addr += rs
kernel32.CloseHandle(h)
print(json.dumps(out, ensure_ascii=False, indent=1))
