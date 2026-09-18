// Hook SHA-256 compression function in nfxcore.dll
// 以及监控HMAC初始化
var nfx = Process.getModuleByName('nfxcore.dll');
var base = nfx.base;

// SHA-256 K表加载点 @ 0x15dd972 (file offset ≈ virtual address since DLL)
// 但DLL加载基址不同,需要计算RVA
// PE文件: .text section virtual address需要从PE头解析

// 简化: 直接搜索DLL内存中的SHA-256 K表特征
var k0 = [0x98, 0x2f, 0x8a, 0x42];  // 0x428a2f98 LE
var k1 = [0x91, 0x44, 0x37, 0x71];  // 0x71374491 LE
var kTableAddr = null;

// 在DLL内存范围内搜索K表
var ranges = nfx.enumerateRanges('r-x');
for (var i = 0; i < ranges.length && !kTableAddr; i++) {
    var r = ranges[i];
    if (r.size < 0x1000 || r.size > 0x2000000) continue;
    try {
        var results = Memory.scanSync(r.base, r.size, 
            "98 2f 8a 42 91 44 37 71 67 f8 f7 62");
        if (results.length > 0) {
            kTableAddr = results[0].address;
            send({t:'ktable', addr: kTableAddr.toString(), module: r.base.toString()});
            break;
        }
    } catch(e) {}
}

if (kTableAddr) {
    // 找到K表后, hook引用它的函数(搜索LEA指令)
    // 简化: 在K表附近的代码段找函数头(prologue: push rbp / sub rsp)
    // 或者直接hook一个更大的范围
    
    // 更好的方案: hook nfx_ 开头的所有导出,看签名调用链
    var exports = nfx.enumerateExports();
    var hooked = 0;
    exports.forEach(function(exp) {
        if (exp.name.indexOf('nfx_') !== 0) return;
        if (['nfx_qu','nfx_qd','nfx_frs','nfx_ping','nfx_state'].indexOf(exp.name) >= 0) return;
        try {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    var info = {t:'nfx', fn: exp.name};
                    // 读指针参数
                    for (var i = 0; i < 2; i++) {
                        try {
                            var p = args[i];
                            if (!p.isNull() && p.compare(ptr(0x10000)) > 0) {
                                var bytes = p.readByteArray(Math.min(128, 128));
                                var arr = new Uint8Array(bytes);
                                var s = '';
                                var hex = '';
                                for (var j = 0; j < arr.length; j++) {
                                    var c = arr[j];
                                    s += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
                                    hex += ('0' + c.toString(16)).slice(-2);
                                }
                                if (s.replace(/\./g, '').length > 8) {
                                    info['arg' + i + '_txt'] = s.substring(0, 100);
                                }
                                if (hex.replace(/00/g, '').length > 20) {
                                    info['arg' + i + '_hex'] = hex.substring(0, 64);
                                }
                            }
                        } catch(e) {}
                    }
                    send(info);
                }
            });
            hooked++;
        } catch(e) {}
    });
    send({t: 'ready', hooked: hooked, ktable: kTableAddr.toString()});
} else {
    send({t: 'error', msg: 'K table not found'});
}
