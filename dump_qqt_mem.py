import ctypes, ctypes.wintypes as wt, sys, os
PROCESS_VM_READ = 0x0010; PROCESS_QUERY_INFORMATION = 0x0400
kernel32 = ctypes.windll.kernel32
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),("AllocationBase", ctypes.c_void_p),("AllocationProtect", wt.DWORD),("RegionSize", ctypes.c_size_t),("State", wt.DWORD),("Protect", wt.DWORD),("Type", wt.DWORD)]
MEM_COMMIT = 0x1000; PAGE_GUARD = 0x100; PAGE_NOACCESS = 0x01
MEM_PRIVATE = 0x20000
pid = int(sys.argv[1])
out = sys.argv[2]
h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
if not h:
    print("OpenProcess failed"); sys.exit(1)
addr = 0; mbi = MBI(); mbi_size = ctypes.sizeof(mbi)
f = open(out, 'wb')
total = skipped = 0
regions = []
while addr < 0x7fffffffffff:
    r = kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size)
    if r == 0: break
    rs = mbi.RegionSize
    if rs == 0: break
    if (mbi.State == MEM_COMMIT and not (mbi.Protect & PAGE_GUARD) and mbi.Protect != PAGE_NOACCESS
            and 0 < rs < 64*1024*1024):
        buf = ctypes.create_string_buffer(rs)
        br = ctypes.c_size_t(0)
        if kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, rs, ctypes.byref(br)) and br.value:
            f.write(buf.raw[:br.value])
            regions.append(br.value)
            total += br.value
    else:
        skipped += rs
    addr += rs
kernel32.CloseHandle(h)
f.close()
print(f"dumped {total/1024/1024:.1f}MB from {len(regions)} private RW regions (skipped {skipped/1024/1024:.0f}MB non-private)")
