# QQT 逆向工程 — 当前状态快照(2026-09-17 17:45)

> 本文档记录截至此刻的所有发现、已完成步骤、未完成步骤、以及继续分析所需的全部上下文。
> 目标: 完全无客户端拉取QQT订阅节点(当前进度 ~95%,只差签名算法最后一环)。

---

## 一、已完全攻破的部分 ✅

### 1.1 信道加密(AES-256-GCM) — 已破解
```
信道密钥: 2bc0a6964606f3f1d199c48d38fce44b46edf9ea32a7d51d9bba6410203bbd46
X-Key-ID: key_20260917_7DE39B0B
X-Device-ID: 8da778a30591fd955a612a471a52cc84
```
- 信封格式: `{encrypted_data(b64), iv(b64,12B), tag(b64,16B), timestamp(unix), signature(64hex)}`
- 解密方式: `AESGCM(key).decrypt(iv, encrypted_data+tag, None)` — **29个信封全部解密成功**

### 1.2 请求/响应协议(v2) — 完全映射
```
请求明文: {"v":2,"a":"<动作>","p":{参数},"s":"<会话token>","t":unix时间戳,"trace_id":"<动作>-<uuid4>"}
响应明文: {"c":0,"d":{数据},"m":"","v":2}
```
- 动作集: auth.login(p含明文邮箱密码) / auth.logout / user.info / **user.sub**(订阅) /
  user.routing_rules / user.list_rule_subscriptions / device.register / device.list /
  device.heartbeat / device.flow_events / invite.info / notice.list / app.check_update / system.caps
- 会话token: `80ce41a2efd6501a54de37297caec8b177986636cf2ad318785eca8715c117c3`(登录后获取)

### 1.3 实战验证(在线测试)
用信道密钥构造 user.sub 请求 → 服务器返回 `code:1003 签名验证失败`
= **除签名外全部被服务器接受**(key_id/device_id/加密信封/请求格式全对)

### 1.4 Phantom节点完整规格(内存提取)
```
{"address":"iepl.qqt.wgnmdgfw.com","port":32711|32814|32815|32830|32835,
 "password":"28a65268-644c-3135-9ac4-b2b392977f83",
 "serverName":"www.baidu.com",          ← SNI伪装百度
 "templateId":"chrome-151-windows-11"}   ← TLS指纹伪装Chrome151/Win11
```

### 1.5 QQT后端API架构
- Bootstrap: `GET /api/v2/bootstrap` + 头 `X-Airport-ID: AIRPORT_3596D3D5323B`(多租户)
- 服务器: `backendapi.cniw4-dcc3vq.com`(FastAPI) + Azure trafficmanager 3个备选
- QQT真实产品名: **relayway**(relayway.com / relaywayx.com / relayway.cn)
- 认证协议标识: `relayway-auth-account-v1`

---

## 二、签名算法 — 唯一未破解的环节 ❌

### 2.1 已确认的信息
- 签名格式: **HMAC-SHA256**, 输出为64字符hex(不带"hmac-sha256:"前缀, 前缀只在X-Channel-Sig头中)
- 格式正则(来自app.so字符串): `^hmac-sha256:[0-9a-f]{64}$`
- **签名密钥不是信道AES key** — 是从`master_key`派生的`sessionKeyHex`
- 密钥派生链: `install_salt` → PBKDF2 → 解密ENCv3存储的`master_key` → 派生`sessionKeyHex`

### 2.2 本地存储分析
```
flutter.secure_install_salt_v2 = vyMUtLu4AKu/QOOLVjPRu/cJq1wN+oQ4IYbpEvICsoA= (32B)
flutter.secure_security_master_key = ENCv3:y2SyMERcBuNMFnTWoCovIga... (解密后44B明文)
flutter.secure_security_rsa_public_key = ENCv3:... (设备RSA公钥, 420B密文)
flutter.secure_security_rsa_private_key = ENCv3:... (设备RSA私钥, 1120B密文)
flutter.secure_auth_v2_session_token = ENCv3:...
flutter.secure_security_key_id = ENCv3:...
flutter.secure_security_aes_key_hash = ENCv3:...
```
- ENCv3 = AES-256-GCM + PBKDF2(来自`[SecureStorage] Initialized with AES-256-GCM + PBKDF2 (v3)`)
- 72B密文 = 12B nonce + 44B ciphertext + 16B tag
- **PBKDF2的密码未知**(已试: 空串/ENCv3/qqt/flutter/secure_storage/install/v3/master_key/default × 4种迭代数)

### 2.3 已穷尽排除的方案(100%排除)
| 方案 | 排除证据 |
|---|---|
| HMAC-SHA256(信道key, 各种消息) | C暴力扫描600MB dump × 7种消息, 8字节对齐, NOT FOUND |
| HMAC-SHA256(会话token/device_id/key_id) | 全部离线测试✗ |
| HMAC-SHA256(HKDF派生key) | 20种HKDF参数组合✗ |
| sha256(key‖m) / sha256(m‖key) | C暴力扫描600MB×1字节粒度, NOT FOUND |
| BLAKE2s/2b(keyed) | 离线测试✗ |
| HMAC ipad/opad内存残留 | 扫描0x36/0x5C连续块, 无有效命中 |
| nfxcore.dll FFI导出hook | 77个导出全hook, 签名不走这些入口 |
| Windows BCrypt API hook | 0个事件(不使用系统CNG) |
| 直接暴力所有32B窗口(7种消息格式) | C+OpenMP 4.5分钟扫描632MB, NOT FOUND |

### 2.4 关键发现(来自app.so静态分析)
- `buildSignature` — 函数名(Dart字符串池)
- `sessionKeyHexProvider: master key unavailable` — 签名密钥来自master key的hex
- `[NfxCore] bundleSetSessionKey(` — 密钥通过nfxcore.dll设置
- `relayway-auth-account-v1` — 认证域分隔符(可能参与HMAC消息)
- SHA-256压缩函数在nfxcore.dll中 @文件偏移0x15dd972(K表@0x15deac0)
- **QQT Flutter框架是Dart 3.3.4, ELF x64, 无符号**
- **所有加密在nfxcore.dll(Rust)中**, Dart侧只做序列化
- **blutter不支持x64 Windows**(仅支持Android arm64)

---

## 三、下一步(继续分析的路线图)

### 路线A: 解密ENCv3 master_key(最优先)
```
已知: install_salt(32B), ENCv3密文(72B = 12B nonce + 44B ct + 16B tag)
未知: PBKDF2的password
```
1. **从内存中找解密后的master_key**: 之前的暴力搜索只试了HMAC密钥格式,没试过直接搜索master_key的32B原文然后用它做PBKDF2派生sessionKey
2. **从app.so中提取PBKDF2参数**: 搜索迭代次数(iterations)和password字符串的构造代码
3. **用Ghidra正确加载app.so**: 用Java脚本(不是Python)分析Dart snapshot中的函数定义

### 路线B: Frida实时HMAC密钥捕获
```
原理: 在签名计算的瞬间, HMAC密钥以64B ipad/opad形式存在于内存
时机: 在ws2_32.send()被调用时(QQT发送签名请求到服务器的时刻)
```
1. Hook `ws2_32.dll!send` 和 `ws2_32.dll!WSASend`
2. 检测到含`/api/v2/query`的HTTP请求时,立即扫描进程内存
3. 搜索连续16字节`0x5C`(HMAC opad后半部分) — 前32字节XOR 0x5C = 签名密钥
4. 同时搜索连续16字节`0x36`(HMAC ipad后半部分)
- **已写好脚本**: `hook_hmac_realtime.js` + `run_hook4.py`(未运行成功,被中断)

### 路线C: 完全静态逆向nfxcore.dll(Rust)
```
nfxcore.dll包含: SHA-256(K表@0x15deac0)、SHA-512、BLAKE2、ChaCha20、Poly1305、AES
SHA-256压缩函数入口: 文件偏移0x15dd972
```
1. 用Ghidra加载nfxcore.dll(PE x64)
2. 从SHA-256压缩函数向上追踪调用链,找到HMAC-SHA256的入口
3. 在HMAC入口处找到key参数的来源
4. 逆向key的初始化路径(sessionKeyHex的生成逻辑)

### 路线D: 重放攻击(不需要破解签名)
```
如果只需要拉取节点, 可以直接重放app发出的完整签名请求
```
1. 用实时捕获脚本抓取一个完整的`user.sub`请求(含有效签名)
2. 在签名过期前立即重放(需要确定签名时效)
3. 这不是"无客户端"方案,但可以在app运行时低成本获取订阅

---

## 四、工具与脚本清单

| 文件 | 用途 | 状态 |
|---|---|---|
| `airmon/velo_api.py` | Velochron无客户端采集 | ✅ 生产可用 |
| `airmon/uiauto.py` | UI自动化登录(QQT/Velochron通用) | ✅ 已集成 |
| `airmon/dpapi.py` | DPAPI缓存采集(Velochron备线) | ✅ 已集成 |
| `scan_qqt_proto.py` | QQT内存协议扫描(信封/密钥/节点) | ✅ 可用 |
| `scan_qqt_full.py` | QQT完整信封捕获(不限长) | ✅ 可用 |
| `scan_qqt_nodes.py` | QQT phantom节点提取 | ✅ 可用 |
| `scan_velo_proto.py` | Velochron协议扫描 | ✅ 可用 |
| `dump_qqt_mem.py` | QQT私有RW内存dump | ✅ 可用 |
| `catch_live_sig.py` | 实时信封捕获(触发流量+扫描) | ✅ 可用 |
| `catch_and_dump.py` | 捕获新信封+即时dump | ✅ 可用 |
| `scan_new_env.py` | 搜索指定时间戳后的新信封 | ✅ 可用 |
| `hook_bcrypt.js` | BCrypt CNG hook | ✅ 但QQT不使用CNG |
| `hook_nfx.js` | nfxcore FFI导出hook | ✅ 签名不走导出 |
| `hook_sha256.js` | nfxcore SHA-256 K表搜索 | ✅ K表运行时地址已定位 |
| `hook_hmac_realtime.js` | HMAC密钥实时捕获(send hook+内存扫描) | ⚠️ 已写好未跑通 |
| `run_hook*.py` | Frida驱动脚本 | ✅ Frida 17.18.0已装 |
| `/tmp/brute_gcm` | AES密钥拾荒(C+OpenMP) | ✅ 已成功找到信道key |
| `/tmp/brute_multi` | 多消息HMAC暴力搜索(C+OpenMP) | ✅ 已排除所有候选 |
| `/tmp/brute_all` | 三构造暴力搜索(C+OpenMP) | ✅ 已排除 |
| `qqt_md5.bin` | 最新QQT内存dump(632MB) | ✅ 可用于继续分析 |

---

## 五、数据文件

| 文件 | 内容 |
|---|---|
| `研究数据/qqt_信道解密样本.json` | 29条解密信封(含明文/签名/时间戳/信道key/key_id/device_id/session) |
| `研究数据/qqt_nodes_dump.json` | 5个phantom节点完整配置 |
| `velo_secure2/` | Velochron解密后的设备密钥/token(可DPAPI复现) |
| `velo_native_nodes.json` | Velochron 33个aero_v2节点(无客户端拉取) |

---

## 六、QQT完整攻击面图

```
┌─────────────────────────────────────────────────────────────┐
│ QQT Client (qqt.exe)                                        │
│                                                             │
│  ┌──────────────┐    FFI    ┌──────────────────────┐       │
│  │ Flutter/Dart  │◄────────►│ nfxcore.dll (Rust)    │       │
│  │  app.so 12MB  │          │  35MB                │       │
│  │  Dart 3.3.4   │          │  SHA-256/512         │       │
│  │  x64 AOT      │          │  AES-GCM/ChaCha20    │       │
│  │  无符号/剥离   │          │  BLAKE2/Poly1305     │       │
│  │  加密在Rust侧  │          │  RSA-OAEP            │       │
│  └──────┬───────┘          └──────────┬───────────┘       │
│         │                              │                    │
│  ┌──────▼──────────────────────────────▼───────────┐       │
│  │  签名流水线:                                     │       │
│  │  master_key(ENCv3存储) → sessionKeyHex          │       │
│  │  → HMAC-SHA256(sessionKey, 未知消息格式)          │       │
│  │  → "hmac-sha256:" + hex64                       │       │
│  │  → X-Channel-Sig 头 + envelope.signature 字段    │       │
│  └─────────────────────────────────────────────────┘       │
│                                                             │
│  已攻破: AES-GCM信道(密钥已提取) / 协议(29信封解密)          │
│  未攻破: HMAC签名密钥(需要解密ENCv3或实时捕获)               │
└─────────────────────────────────────────────────────────────┘
```

---

## 七、Velochron 无客户端方案(已100%完成)

```
① POST /api/v1/passport/auth/login {email,password}  ← 普通浏览器头
② GET /api/v1/user/getSubscribe (Authorization + App头)
   → subscribe_url(含600s app_grant) + aero_sub_key(32B hex)
③ GET subscribe_url (App头) → base64(nonce(12B) || AES-256-GCM(ct))
④ AESGCM(aero_sub_key).decrypt(nonce, ct) → 33个aero_v2节点
```
- 已集成: `run.py pull --airport velochron` → `airmon/velo_api.py`
- X-App-Signature: `e9d56d284f5f3e7003c987f6c6557be0da8e7f98f381d4e5bf184e56811adc93`
- 关键陷阱: 登录用浏览器UA(App UA会触发403 device_identity_required), 订阅用App UA+签名
