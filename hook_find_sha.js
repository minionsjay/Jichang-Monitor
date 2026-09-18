var nfx = Process.getModuleByName('nfxcore.dll');
send({t:'module', base: nfx.base.toString(), size: nfx.size});

// 搜索所有可读区域
var allRanges = nfx.enumerateRanges('r--');
send({t:'ranges', count: allRanges.length});
for (var i = 0; i < allRanges.length; i++) {
    var r = allRanges[i];
    if (r.size > 0x10000000) continue;
    try {
        // SHA-256 K表前4个值连续
        var results = Memory.scanSync(r.base, r.size, "98 2f 8a 42 91 44 37 71 67 f8 f7 62");
        if (results.length > 0) {
            send({t:'found_ktable', addr: results[0].address.toString(), 
                  range: r.base.toString(), prot: r.protection, size: r.size});
        }
        // SHA-256 H初始值
        var results2 = Memory.scanSync(r.base, r.size, "67 e6 09 6a 85 ae 67 bb");
        if (results2.length > 0) {
            send({t:'found_h0', addr: results2[0].address.toString(),
                  range: r.base.toString(), prot: r.protection});
        }
    } catch(e) {
        send({t:'scan_err', range: r.base.toString(), err: e.message});
    }
}
send({t:'done'});
