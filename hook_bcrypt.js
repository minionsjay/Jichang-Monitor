// Frida 17 API
function exp(name) {
  try { return Module.getGlobalExportByName(name); } catch(e) {}
  try { return Process.getModuleByName('bcrypt.dll').getExportByName(name); } catch(e) {}
  return null;
}
var algos = {};
var hashKeys = {};

var open = exp('BCryptOpenAlgorithmProvider');
if (open) Interceptor.attach(open, {
  onEnter: function(args) { this.alg = args[1].readUtf16String(); },
  onLeave: function(ret) {
    if (this.alg) {
      algos[ret.toString()] = this.alg;
      send({t:'open', alg: this.alg, h: ret.toString()});
    }
  }
});

var createHash = exp('BCryptCreateHash');
if (createHash) Interceptor.attach(createHash, {
  onEnter: function(args) {
    this.hAlg = args[0].toString();
    this.ph = args[1];
    this.pbSecret = args[4];
    this.cbSecret = args[5].toInt32();
  },
  onLeave: function(ret) {
    if (ret.toInt32() === 0) {
      var h = this.ph.readPointer().toString();
      var info = {t:'createHash', h: h, alg: algos[this.hAlg] || this.hAlg, secretLen: this.cbSecret};
      try {
        if (this.cbSecret > 0 && this.cbSecret < 256) {
          info.secretHex = Array.from(new Uint8Array(this.pbSecret.readByteArray(this.cbSecret))).map(function(b){return ('0'+b.toString(16)).slice(-2);}).join('');
          hashKeys[h] = info.secretHex;
        }
      } catch(e) { info.err = '' + e; }
      send(info);
    }
  }
});

var hashData = exp('BCryptHashData');
if (hashData) Interceptor.attach(hashData, {
  onEnter: function(args) {
    var h = args[0].toString();
    var cb = args[2].toInt32();
    if (cb > 0 && cb < 65536) {
      try {
        var bytes = new Uint8Array(args[1].readByteArray(Math.min(cb, 2048)));
        var s = '';
        for (var i = 0; i < bytes.length; i++) {
          var c = bytes[i];
          s += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
        }
        send({t:'hashData', h: h, len: cb, key: hashKeys[h] || null, preview: s.substring(0, 250)});
      } catch(e) {}
    }
  }
});

var genKey = exp('BCryptGenerateSymmetricKey');
if (genKey) Interceptor.attach(genKey, {
  onEnter: function(args) {
    var cb = args[5].toInt32();
    if (cb > 0 && cb <= 64) {
      try {
        var hex = Array.from(new Uint8Array(args[4].readByteArray(cb))).map(function(b){return ('0'+b.toString(16)).slice(-2);}).join('');
        send({t:'genKey', len: cb, key: hex});
      } catch(e) {}
    }
  }
});

['BCryptSignHash','BCryptVerifySignature'].forEach(function(n) {
  var a = exp(n);
  if (a) Interceptor.attach(a, { onEnter: function(args) { send({t: n}); } });
});

send({t:'ready'});
