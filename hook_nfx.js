// Hook所有 nfxcore.dll 导出函数, 抓参数数据
function hexPreview(ptr, len) {
  if (ptr.isNull() || len <= 0 || len > 8192) return null;
  try {
    var bytes = new Uint8Array(ptr.readByteArray(Math.min(len, 512)));
    var s = '';
    for (var i = 0; i < bytes.length; i++) {
      var c = bytes[i];
      s += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
    }
    return s;
  } catch(e) { return null; }
}
var mod = Process.getModuleByName('nfxcore.dll');
var interesting = ['session_key', 'client_identity', 'hydra', 'begin', 'setup', 'auth', 'sign', 'encrypt', 'key', 'transactional_egress_arm', 'transactional_egress_identity', 'frs', 'qd', 'qu'];
mod.enumerateExports().forEach(function(exp) {
  var name = exp.name;
  if (!interesting.some(function(k) { return name.indexOf(k) >= 0; })) return;
  try {
    Interceptor.attach(exp.address, {
      onEnter: function(args) {
        var info = {t: 'nfx', fn: name};
        // 尝试读前3个指针参数指向的内存
        for (var i = 0; i < 3; i++) {
          var p = args[i];
          try {
            if (!p.isNull() && p.toUInt32() > 0x10000) {
              var prev = hexPreview(p, 256);
              if (prev && prev.replace(/\./g, '').length > 12) {
                info['p' + i] = prev.substring(0, 150);
              }
            }
          } catch(e) {}
        }
        // 尝试把参数当整数
        info.args = [args[0].toString(16), args[1].toString(16), args[2].toString(16)];
        send(info);
      }
    });
  } catch(e) {}
});
send({t: 'ready', mod: mod.name, base: mod.base.toString()});
