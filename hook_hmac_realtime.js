// 策略: 在QQT每次发送签名请求时,立即dump相关内存区域
// 因为签名只在请求发送瞬间存在

var nfx = Process.getModuleByName('nfxcore.dll');

// 监控所有从Dart到nfxcore的FFI调用
// 当检测到可能的签名相关调用时,dump参数

// 更直接: hook ws2_32.dll的send/sendto (网络发送 = 签名已完成)
// 在send触发时,读取进程内存中的HMAC相关数据

var sendFn = Module.getGlobalExportByName('send');
var wsaSendFn = Module.getGlobalExportByName('WSASend');

var captureCount = 0;
var lastCapture = 0;

function captureOnSend(socket, buf, len) {
    var now = Date.now();
    if (now - lastCapture < 2000) return;  // 防重复
    if (captureCount >= 5) return;
    if (len < 100 || len > 100000) return;
    
    // 检查是否包含api/v2/query
    try {
        var preview = buf.readUtf8String(Math.min(len, 200));
        if (preview && preview.indexOf('/api/v2/query') >= 0) {
            lastCapture = now;
            captureCount++;
            send({t:'query_send', len: len, count: captureCount});
            
            // 立即dump整个进程的一个快照区域(搜索最近的HMAC状态)
            // HMAC-SHA256 opad: key XOR 0x5C repeated 64 times
            // 在当前线程栈和最近的堆中搜索
            var ranges = Process.enumerateRanges('rw-');
            var hmacHits = 0;
            for (var i = 0; i < ranges.length && hmacHits < 3; i++) {
                var r = ranges[i];
                if (r.size < 0x1000 || r.size > 0x10000000) continue;
                // 搜索连续的0x5C字节(HMAC opad填充)
                try {
                    var results = Memory.scanSync(r.base, Math.min(r.size, 0x1000000),
                        "5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c");
                    if (results.length > 0) {
                        for (var j = 0; j < Math.min(results.length, 2); j++) {
                            // opad前面的32字节就是密钥 XOR 0x5C
                            var opadAddr = results[j].address;
                            // 密钥在opad前32字节(key^0x5C后)
                            // 但完整的HMAC ipad在前64字节
                            // key(32B) + 0x00*32 → XOR 0x5C*64 = key^5C + 5C*32
                            // 所以opad = [key^5C(32B), 5C*32(32B)]
                            // key = opad[0:32] XOR 5C
                            var keyBytes = opadAddr.readByteArray(32);
                            var arr = new Uint8Array(keyBytes);
                            var keyHex = '';
                            for (var k = 0; k < 32; k++) {
                                keyHex += ('0' + (arr[k] ^ 0x5C).toString(16)).slice(-2);
                            }
                            send({t:'hmac_key', key: keyHex, 
                                  addr: opadAddr.toString(), range: r.base.toString()});
                            hmacHits++;
                        }
                    }
                } catch(e) {}
            }
            if (hmacHits == 0) {
                send({t:'no_hmac_found'});
            }
        }
    } catch(e) {}
}

if (sendFn) {
    Interceptor.attach(sendFn, {
        onEnter: function(args) {
            captureOnSend(args[0], args[1], args[2].toInt32());
        }
    });
}
if (wsaSendFn) {
    Interceptor.attach(wsaSendFn, {
        onEnter: function(args) {
            // WSASend: lpBuffers, dwBufferCount
            var bufs = args[1];
            var count = args[2].toInt32();
            if (count > 0 && count < 10) {
                var buf = bufs.readPointer(); // WSABUF.buf
                var len = bufs.readU32();     // WSABUF.len  
                if (len > 0 && len < 100000) {
                    captureOnSend(null, buf, len);
                }
            }
        }
    });
}

send({t:'ready'});
