import ctypes, ctypes.wintypes as wt, re, json, sys
PROCESS_VM_READ = 0x0010; PROCESS_QUERY_INFORMATION = 0x0400
kernel32 = ctypes.windll.kernel32
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),("AllocationProtect", wt.DWORD),("RegionSize", ctypes.c_size_t),("State", wt.DWORD),("Protect", wt.DWORD),("Type", wt.DWORD)]
MEM_COMMIT = 0x1000; PAGE_GUARD = 0x100; PAGE_NOACCESS = 0x01
pid = int(sys.argv[1])
h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
addr = 0; mbi = MBI(); mbi_size = ctypes.sizeof(mbi)
# 只找起点, 然后向前取到配对的结尾 (信封无嵌套大括号, 直到最后一个 })
found = []
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
                for m in re.finditer(rb'\{"code":0,"encrypted_data":"[A-Za-z0-9+/=]{500,}"', data):
                    # 从起点向后找完整的信封结尾: ",\"iv\":\"...\",\"tag\":\"...\",\"timestamp\":...,\"signature\":\"...\"}"
                    end = data.find(b'}', m.end())
                    if end < 0 or end - m.start() > 300000: continue
                    blob = data[m.start():end+1]
                    if b'"iv"' in blob and b'"tag"' in blob and b'"signature"' in blob:
                        s = blob.decode('utf-8', errors='replace')
                        if s not in found:
                            found.append(s)
    addr += rs
kernel32.CloseHandle(h)
print(json.dumps([len(f) for f in found]))
import codecs
with open(sys.argv[2], 'wb') as fo:
    fo.write(json.dumps(found).encode('utf-8'))
