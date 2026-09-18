# 翻墙机场 CDN 中转与通信协议研究报告

> 探测时间: 2026-09-17 凌晨
> 范围: Jichang-Monitor 全部 44 个机场, 2515 个节点
> 方法: 三重证据链交叉验证 —— ① 重抓全部可用订阅(clash UA)解析 network/ws-opts/tls/SNI/Host 字段; ② 全部节点 server 域名 + 面板/订阅域名做 CNAME 链追踪(dig); ③ CNAME 终点与 A 记录逐 IP 查归属(ip-api/RDAP); ④ 客户端型机场用 DPAPI 解密数据/内存扫描结果分析传输字段。

---

## 一、核心结论(TL;DR)

1. **真·CDN 中转的机场有 5 个**(Cloudflare ×4 家、AWS CloudFront ×1 家), 共约 30 个节点走公共 CDN; 其余绝大多数是"云 VM 中转 / IEPL 专线 / GSLB 多入口 + 直连", 不是 CDN。
2. **CDN 中转的传输协议几乎全是 WebSocket**(vless+ws+tls / vmess+ws), 因为只有 WebSocket(HTTP Upgrade)能被 CDN 正常代理回源; 另有一家用 xhttp(new-yiyuan), velochron 的自研 aero_v2 也跑在 **WSS**(`/api/sync` 路径)上。**hysteria2/hysteria/tuic 是 QUIC(UDP), CDN 不可能代理, 用它们的一定是专线/直连**。
3. **华为云 CDN: 唯一确证案例是 new-yiyuan**(用户提供线索实锤): 旧入口 `video.yhby.xyz` CNAME 至华为云CDN边缘域 `cdnhwcggk22.com`(权威DNS=huaweicloud-dns.org, SOA=hwclouds.cs.huawei.com), **现已弃用**——华为侧配置已删、权威NXDOMAIN, 只剩死CNAME遗迹。该机场现已改为 vless+xhttp(stream-up) 直连(HK/US=AS-Hytron/Vantiva, JP=Cyberverse东京) + Cloudflare 分发。**当前仍在服役的华为云CDN: 0 个**。华为只以 IaaS(云主机)身份残存: 万达云中转 116.205.40.114=HWCSNET华为云北京(路由域已失效)、muniu 注册IP 119.8.242.52=华为云香港(节点已死)、jsqpro 面板曾华为云(已迁意大利)。2515 节点落地 IP: **0 条华为**。

---

## 二、CDN 中转机场清单(真·公共CDN, 节点流量过CDN)

### 2.1 Cloudflare 系(4 家)

| 机场 | 节点 | 链路证据 | 协议/传输 |
|---|---|---|---|
| **liangxin(良心)** | ~18 个 "cf" 节点 | `cfyes.7770006.xyz` → CNAME `cf.yfjc.sbs` → **141.193.213.8 (Cloudflare)**; ws-Host `jp1-lx.7770006.xyz`/`lx-1sg.lxy1015.top` 也都解析到 Cloudflare | **vless + ws + tls**, path=`/liangxin/*`, Host=自备域 |
| **flybar** | ~10 个 "优化" 节点 | `zz*.0900738.xyz` → `yxrk.0900738.xyz` → `saas.sin.fan`(SaaS接入层) → **`singgcdn.singgnetworkcdn.com` → 172.64.153.74 (Cloudflare)**; ws-Host `aa-N.116156.xyz` → Cloudflare | **vless + ws + tls**, path=`/newlogin/login.do` |
| **selom** | 2 个 "低倍率CF2" 节点 | `cf.090227.xyz` → `cf.hw.090227.xyz` → `cmcc.hw.090227.xyz` → **104.17.x (Cloudflare)**; Host `cftest.selom.online` → Cloudflare | **vless + ws**, path=`/vless-ws` |
| **xm999** | 2 个 vmess 节点 | `mtv1/mtv2.238689.xyz` → **104.18.36.123 / 172.67.217.215 (Cloudflare)**; Host=同域 | **vmess + ws**, path=随机串 |

> 注: selom 那条 CNAME 链的中间层命名为 `cf.hw` → `cmcc.hw`(字面像"移动/华为"), 但**纯粹是 DNS 别名命名, 流量实际落 Cloudflare**, 与华为基础设施无关。

### 2.2 AWS CloudFront 系(1 家运营商, 两个机场品牌)

| 机场 | 节点 | 链路证据 | 协议/传输 |
|---|---|---|---|
| **jinglingxueyuan(精灵学院)** | 6 个 "CloudFront" 节点(节点名直接标注) | server `cfn.cdn.moe233.org` → CNAME `cfn-hkg.cdn.qchwnd.moe` → **13.33.171.71 (AWS CloudFront, reverse=server-13-33-171-71.hkg1 = 香港PoP)**; Host/SNI = `d3u6b75zj1a6q0.cloudfront.net` 等真 CloudFront 分发域 | **vmess + ws** |
| **no626**(同 moe233 运营商) | 订阅分发走 CDN | `sky-subscription.0443.link` → CNAME **`dtdf8bznametj.cloudfront.net` → 13.35.190.x (CloudFront HKG)**; 节点本体走自建 edge(见 3.2) | anytls/tcp |

### 2.3 "名字像CDN但不是CDN"的(避坑)

| 机场 | 表象 | 实际 |
|---|---|---|
| **jsqpro** | server 域名 `api365-jscdn-*.cdn.myinba55.com`(带"jscdn"/"cdn"字样), SNI `vod-stream.shiqycdn.com` | 解析到 **NetLab Global VPS(189.24.106.x)**, "cdn"是命名伪装; shiqycdn.com 无解析, 纯 SNI 伪装 |
| **cherryvpn** | 域名前缀 `oss-cn-shanghai/guangzhou`(阿里OSS风格), SNI `oss-cn-japan/hongkong.aliyuncs.com` | 124 个节点全部解析到**同一个 Azure 日本东 VM(20.89.58.34)按端口区分** —— 是单台 Azure 中转机, 不是 CDN; 阿里 OSS 域名只是 SNI 伪装 |
| **maxiong** | SNI `f132cdn-us.ckpfef.top` 带 "cdn" | hysteria2(QUIC), CDN 不可能; ckpfef.top 自有域 GSLB → AWS |

---

## 三、非 CDN 的中转/接入架构(对照)

### 3.1 云 VM 中转(GSLB/多入口, 不是CDN)
- **bygcloud** → 腾讯云集群(129.204/106.55/159.75/119.91, GeoDNS 4 IP), vless+tcp+tls, SNI www.apple.com
- **bywave** → GCP 香港(34.96/34.150/35.241), anytls
- **mojie** → `gtm-host.com` GSLB → Azure 韩国(20.214.9.195)/Newrui(123.253.227.x)/GTT(87.83.216.x); vmess+ws 走 Azure 中转, **ws-Host 伪装成淘宝CDN域名 `*.mobgslb.tbcache.com`**(实际不经过淘宝)
- **hsyun** → AWS 香港 + rros.cc 多级CNAME, anytls
- **ktm/feiniao_2/maxiong/applegame/dualnet** → 自有 GSLB 链(`gtm-*`/`awsld*`/`linknode→hfzz`/`bnnodelbten-lbg`) → AWS/Oracle/GTT 等 VPS
- **selom(非CF节点)/flybar(非ws节点)** → 阿里云HK(47.243)/AWS/Akile, tcp 直连
- **jsqpro** → NetLab VPS(见上)

### 3.2 自建边缘 PoP 网络(moe233 运营商)
jinglingxueyuan/no626 的主力节点: `UUID.relay.moe233.org` → `*-hkg/nrt.edge.qchwnd.moe`:
- lain-hkg → 202.155.155.x(Future-Lain, HK)
- pump-hkg → 103.182.96.x(CNSV/PAN-LIAN, HK)
- astrix-nrt → 14.137.237.x(Alpha JP, 东京)
- silic-nrt → 103.214.169.x(Silicon Cloud, 东京)
自建边缘 + anytls(直连, SNI=UUID.qchwnd.moe), 加上 CloudFront CDN 备线(2.2)。

### 3.3 IEPL/国内中转入口(专线, 与CDN无关)
- **QQT(quqiuquan)**: `iepl.qqt.wgnmdgfw.com:32707` IEPL 专线 + 529 个十六进制伪装域名池(SonderCloud/Azure HK), 自研 **phantom 协议 over TCP**
- **lingdian(零点云)**: `*.bilibilitutu.com`(B站仿冒域, GeoDNS 藏) → **中国移动广州 120.233.118.x 国内入口** → AWS 落地
- **dovex**: gmedia.hostlocal.cc → **中国移动广东 183.240.12.158** 入口
- **ktm**: `iepl.ktmcn.net` → GTT 专线
- **everlife**: `traffic.iepl.a1.gfw250.com` IEPL
- **velochron**: `aero.velochron.top` GeoDNS 多入口: **上海电信 114.80.8.142 + 上海联通 112.65.199.168(国内入口!)** + 香港 HKT 58.152.81.115 + 日本 SAKURA 160.16.60.90; `iplc_mode: true`

### 3.4 GeoDNS 隐藏入口(权威 NXDOMAIN, 只对目标运营商应答)
flyint(`bestvmr.com`)、muniu-ninja(`cnameip.xyz`)、speedcat/qingyunti/fastlink(`llguanglisf.com` → 历史解析 AWS)、hhy(`gunzivip.space`/`nicehao.top` → 历史解析 ACEVILLE CN2)、lingdian(`bilibilitutu.com`) —— 详见《机场节点机制说明.md》。

### 3.5 家宽落地直连
xm999 主力(`mm.mmnfast.com` GSLB → **台湾 HINET 动态家宽 1-161-53-122/114-37-212-167**)、flyint 台湾线(`koumixp.com→bbprovm.com` → HINET 家宽)。

---

## 四、通信协议与传输层全景矩阵

### 4.1 按传输层分

| 传输 | 机场(节点) | 说明 |
|---|---|---|
| **WebSocket(ws/wss)** | liangxin、flybar、selom、xm999、jinglingxueyuan(**CDN 中转专用**)、mojie(Azure中转)、dualnet(1节点)、new-yiyuan(2节点 trojan+ws) | **CDN 中转的唯一现实选择**: CDN 只代理 HTTP/WS 流量, ws 的 Host 头兼做分流键 |
| **xhttp** | new-yiyuan(18节点 vless+xhttp, SNI update.microsoft.com) | Xray 新传输, 为 CDN 优化设计的 ws 演进 |
| **gRPC** | mitce(34节点 vless+grpc, SNI `s0.awsstatic.com`) | gRPC over HTTP/2, CDN 可代理(CloudFront 支持), 但 mitce 服务器是直连 VPS(18.162.x AWS), awsstatic 只是 SNI 伪装 |
| **TCP 直连 + TLS** | bygcloud(vless, SNI apple)、flyint(vless/trojan, SNI dl.google.com)、yiyuan(vless, SNI addons.mozilla.org)、selom/xm999 主力、hsyun/pkq/cloudnx/no626/jinglingxueyuan(anytls)、applegame(trojan)、oixcloud、feiniao(trojan/vless) | SNI 借大厂域名(apple/amazon/mozilla/itunes/steam/pubg/抖音 douyin-dpi/淘宝 tbcache/腾讯COS myqcloud/阿里OSS aliyuncs) 纯伪装, 不经过对应 CDN |
| **UDP/QUIC** | maxiong(hysteria2 全量)、ktm(hy2×12)、feiniao(hysteria×45)、chaoyue(hy2 全量)、yiyuan(hy2×43)、liangxin(hy2×21)、mitce(hy2×15+tuic×10)、mojie(hy2×7)、feiniao_1(hy2)、cherryvpn(hy2×4) | **CDN 不可能中转 UDP** —— 全部专线/直连 |
| **纯 TCP 无 TLS** | ayucloud(ss 全量)、ktm(ss×52)、neko77(mieru)、feiniao_2(vmess)、everlife 部分、cloudnx(anytls) | |
| **自研协议** | QQT(**phantom**/tcp)、velochron(**aero_v2**/honey_pot_wss, ws_path=/api/sync, 每节点独立 edge_psk+aead_key, carrier SNI aero-carrier.sw8.pw)、muniu-ninja(**ninja**, SS-AEAD 魔改)、neko77(mieru)、ssrdog(sing-box 内嵌, 订阅被服务端客户端指纹校验拦截) | 客户端锁定型机场标配 |

### 4.2 WebSocket 中转的原理(为什么是它)

```
用户 →(vless+ws+tls, Host=机场自备域)→ CDN边缘(Cloudflare/CloudFront)
     →(按 Host/SNI 分流, 回源)→ 机场源站(落地)
```
- **SNI 与 Host 双键**: SNI 用 CDN 认可的域名完成 TLS 握手; HTTP Upgrade 的 Host 头是机场在 CDN 侧配置的"自备域名", CDN 按它路由到对应源站。
- **为什么 CDN 中转都要 ws**: CDN 只转发 HTTP/1.1 Upgrade / HTTP/2 之上的 WebSocket 长连接, 原生 TCP/UDP 一律不代理。所以 vless/vmess+ws 是"过 CDN"的标准姿势; xhttp 是新一代(分块上下行, 更抗封锁)。
- **CDN 中转的收益**: 入口 IP 是 CDN 海量 anycast IP(封锁成本高)、真源站 IP 不暴露、SNI 可以伪装成任意被 CDN 托管的域。
- **代价**: 延迟增加、CDN 免费额度限速(Cloudflare 免费计划对 ws 长连接不友好), 所以各家 CDN 节点通常标"低倍率 0.3x"少数派, 主力还是专线/直连。

### 4.3 SNI/Host 伪装 ≠ CDN 中转(重要区分)
本次排查发现大量"借大厂域名"但**不走对应 CDN** 的情况:
- cherryvpn: SNI=阿里 OSS(oss-cn-japan.aliyuncs.com), 实际连 Azure 日本 VM
- cloudnx: SNI=腾讯 COS(cos.ap-guangzhou.myqcloud.com), 实际连 AWS 新加坡
- mojie: ws-Host=淘宝CDN(mobgslb.tbcache.com), 实际连 Azure 韩国/Newrui
- mitce: SNI=AWS 静态资源(awsstatic.com), 实际连 AWS EC2 直连
- dualnet: SNI=抖音(douyin-dpi.com/douyincdn.com), 实际连 AWS 日本
判定标准: **看 server 域名解析出的 IP 是不是真 CDN 边缘**(Cloudflare 104.x/172.6x/141.193.x、CloudFront 13.3x、Azure Front Door anycast 等), 而不是看 SNI 写了什么。

---

## 五、华为相关排查结果(专项)

### 5.1 华为云 CDN —— 唯一确证案例: new-yiyuan(已弃用)
**【2026-09-17 补充, 用户提供线索后实锤】** new-yiyuan(一元机场) 旧入口 `video.yhby.xyz`:
```
video.yhby.xyz  →CNAME→  video.yhby.xyz.019fa3c2.cdnhwcggk22.com
                                    ↑ 华为云CDN边缘域 (cdnhwc* 特征)
   cdnhwcggk22.com 的 NS = ns2.huaweicloud-dns.com / .cn
   SOA = ns1.huaweicloud-dns.org. hwclouds.cs.huawei.com.
```
**现状**: CNAME 记录仍挂在 yhby.xyz 的 DNS(dyna-ns.net)上, 但华为云CDN权威服务器
(ns1/ns2.huaweicloud-dns.org) 对该边缘域返回**权威 NXDOMAIN** —— 华为侧的 CDN 加速配置已删除,
只剩一条死 CNAME 遗迹(阿里223.5.5.5/腾讯DoH 复测一致)。

**new-yiyuan 当前技术栈(已完全弃用华为CDN)**:
- 订阅分发/官网: `sub2.smallstrawberry.com` / `the-best-airport.com` → **Cloudflare**
- 节点: 18 个 **vless + xhttp(mode=stream-up)** 直连, 域名结构 `地区.账号UUID.入口哈希.the-best-airport.com`:
  - HK×4 → 157.254.20.4(AS-Hytron/Vantiva, 香港冷门AS)
  - JP×10 → 82.40.47.61/63/65/67(Cyberverse LLC, 东京)
  - US×4 → 157.254.23.63(AS-Hytron/Vantiva)
  - 全部 443 端口, SNI 伪装 update.microsoft.com / baidu.com / 自域
- 另有 2 个 server=0.0.0.0 的 trojan+ws 废弃占位节点, 节点名"请立即到官网下载新客户端!"(正推自有客户端)

> 更正结论: 之前"华为云CDN 0命中"的表述基于**当前44个机场的现存域名**; 用户提供的历史线索
> 证实 new-yiyuan **曾经**是华为云CDN中转(与本报告 2.x 的 CDN 中转模式同类), 现已迁移。
> 当前仍在服役的华为云CDN: **0 个**。

### 5.1.1 其余扫描: 华为CDN特征(cdnhwc*/hwclouds/huaweicloud CNAME) 其他命中

### 5.2 华为云只以 IaaS(云主机)身份出现(3 处, 均已复核)
| 位置 | IP | 归属(ip-api 实测) | 性质 |
|---|---|---|---|
| 万达云(wdy) 中转 | 116.205.40.114 | **HWCSNET / Huawei Cloud Service data center(华为云北京)** | 中转 VM(非CDN); 另有 120.240.42.49/50 移动广州 |
| muniu 注册 IP | 119.8.242.52 | Huawei International Pte. LTD(华为云香港) | 历史注册痕迹, 节点已死 |
| jsqpro 面板 | 218.245.99.148(旧) | 曾 HWCSNET; **现已解析 93.46.8.90(意大利 Fastweb)** | 已迁离华为云 |

### 5.2.1 【2026-09-17 凌晨全量复扫】最新数据中华为云主机 IP = 0

对当前全部数据的穷尽式复扫(三步判定):
1. **897 个唯一 IP**(全部最新快照的节点 server IP + 落地解析 IP + 节点域名当前 DNS 解析 + 面板/订阅域名当前 IP):
   - 华为云 17 个 CIDR 网段预筛: **0 命中**
   - 其中 652 个已有 CSV/RDAP 归属文本: **0 条 HWCSNET/HUAWEI/华为**
   - 剩余 245 个无归属 IP 逐一 ip-api 实时查询: **0 条华为**
2. **QQT 专项**(成功登录那次的 46 节点快照 + 529 个十六进制伪装域名的 114 个解析 IP): **0 华为**(SonderCloud/Azure/Linode 系)
3. **万达云华为中转现状追踪**: 笔记中指向华为云北京的代理域 `fl0506.wdy66.cn` **现已无 DNS 解析**; 万达云面板/订阅域(`521wdy.xiongmao139.cn`/`sub0530.wdyserver.com`)均已迁到 **腾讯 EdgeOne(落地中国移动边缘 112.48.148.117/111.29.14.190)**。116.205.40.114 这个 IP 本身仍属华为云, 但因万达云客户端当前未登录(加密配置无法离线取证), 已无法确认其现网中转是否仍走华为——该证据停留在 2026-08-27 的 monitor-net 捕获。

**结论: 截至 2026-09-17, 全部在监控机场的节点/入口/落地/面板/订阅层均无华为云主机 IP 在用; 华为的痕迹只剩万达云 8 月末的一条历史中转捕获(116.205.40.114, IP 仍属华为云但路由域已失效)和 muniu 的历史注册 IP(119.8.242.52, 节点已死)。**

### 5.3 节点落地层
2515 个节点落地 IP 的 RDAP/ip-api 归属扫描: **0 条华为**(HWCSNET/HUAWEI/华为)。上一轮扫描出现的唯一"华为命中"是 QQT 内存里 chat.deepseek.com 的 DNS 缓存(DeepSeek 自己托管在华为云), 属于扫描噪声误报, 已在研究报告中说明。

### 5.4 顺带: 各小 CDN 背后的真实基础设施
机场们用的"杂牌 CDN/加速"底座都不是华为:
- **7colorCDN**(QQT API、applegame 面板): Linode(Akamai)/CloudRadium
- **mofanodes**(bygcloud/maxiong 面板): XNNET + Cloudie(香港)
- **azureedgecdns.xyz**(cherryvpn 订阅分发, 仿冒 Azure 命名): CoreNET(香港)
- **initcc**(speedcat 面板): **中国移动** 120.233.206.x
- **suike.cloud**(qiangda 面板): 湖北飞讯(FXNET)
- **58dns.me**(muniu 订阅): Akari Networks(日本)
- **vivide.top**(ayucloud 订阅): GoMami(新加坡)
- **dnsdog.cc**(ssrdog 面板): CTG/Mega II(香港)
- **jsq1.cc**(feiniao_2 面板): 阿里云(英国)
- **腾讯 EdgeOne**(wandacloud/hsyun 面板): eo.dnseN.com CNAME
- **真 CloudFront**(no626 订阅分发)

---

## 六、按机场的完整协议×链路总表

| 机场 | 协议 | 传输 | 入口架构 | CDN? |
|---|---|---|---|---|
| liangxin | vless/hysteria2 | **ws+tls** / QUIC / tcp | Cloudflare + 直连 | ✅ Cloudflare |
| flybar | mieru/vless/ss | **ws+tls** / tcp | SaaS→singgcdn→Cloudflare + AWS/Akile | ✅ Cloudflare |
| selom | vless/ss | **ws** / tcp | Cloudflare(2节点) + 阿里HK | ✅ Cloudflare(少量) |
| xm999 | anytls/vmess/vless/hy2 | **ws** / tcp / QUIC | Cloudflare(2节点) + HINET家宽GSLB | ✅ Cloudflare(少量) |
| jinglingxueyuan | anytls/vmess | **ws** / tcp | **CloudFront** + 自建edge(qchwnd) | ✅ AWS CloudFront |
| no626 | anytls | tcp | 自建edge + CloudFront(订阅) | ➖(订阅层CF) |
| new-yiyuan | vless/trojan | **xhttp** / ws | UUID域直连 | ➖(xhttp为CDN设计但未见CDN入口) |
| mojie | vmess/hysteria2 | ws(Host=淘宝域伪装) / QUIC | gtm-host GSLB→Azure/Newrui/GTT | ❌(伪装) |
| cherryvpn | anytls/hysteria2 | tcp / QUIC | 单台Azure日本VM按端口分 | ❌(OSS SNI伪装) |
| cloudnx | anytls | tcp | AWS新加坡(COS SNI伪装) | ❌ |
| jsqpro | anytls/vless | tcp | NetLab VPS("jscdn"命名伪装) | ❌ |
| mitce | vless/tuic/hysteria2 | **grpc** / QUIC | AWS直连(awsstatic SNI伪装) | ❌ |
| dualnet | vless/vmess | tcp / ws×1 | AWS LB(抖音SNI伪装) | ❌ |
| bygcloud | vless | tcp+tls | 腾讯云GeoDNS集群 | ❌(云VM中转) |
| bywave | anytls | tcp | GCP香港 | ❌(云VM中转) |
| hsyun | anytls | tcp | AWS HK + EdgeOne面板 | ❌ |
| ktm | ss/hysteria2 | tcp/QUIC | IEPL(GTT) + gtm GSLB→AWS | ❌(专线) |
| QQT | **phantom**(自研) | tcp | IEPL + 7colorCDN(API层) | ➖(API层7color) |
| velochron | **aero_v2**(自研) | **honey_pot_wss**(/api/sync) | 上海电信/联通+HKT+SAKURA 国内中转 | ❌(IPLC中转) |
| muniu-ninja | **ninja**(自研) | tcp | GeoDNS藏死 | ❌ |
| ssrdog | (sing-box内嵌) | — | 直连IP+dnsdog | ❌ |
| speedcat/qingyunti/fastlink | (mihomo内嵌) | — | llguanglisf GeoDNS→AWS | ❌ |
| hhy | (内嵌) | — | gunzivip GeoDNS→ACEVILLE CN2 | ❌ |
| lingdian | (内嵌) | — | bilibilitutu GeoDNS→**移动广州入口**→AWS | ❌(国内中转) |
| dovex | (内嵌) | — | **移动广东入口**→AWS | ❌(国内中转) |
| ayucloud/feiniao_2/neko77/pkq/oixcloud/feiniao/applegame/yiyuan/hsyun/everlife… | ss/vless/trojan/vmess/anytls/mieru | tcp/QUIC | 直连/IEPL/家宽 | ❌ |

---

## 七、附: 本次分析的数据产物
- `/tmp/transports.json` — 22 机场订阅全量解析(协议/传输/SNI/Host/path)
- `/tmp/dns_analysis.json` — 全部节点域名的 CNAME 链 + A 记录
- `/tmp/login_subs.json`、`/tmp/sub_*.json` — 登录路线抓取的订阅原文(selom/ktm/hsyun/jsqpro/xm999)
- `data/nodes_export.csv` — 2515 节点落地归属(华为列全空)

---

## 八、同源运营商图谱(2026-09-17 补充: 44 个品牌背后是谁)

> 方法: 跨机场共享注册域/CNAME链/入口IP/内存扫描哈希前缀交叉分析(已剔除 FlClash 系客户端
> 内存里 DNS/时间服务器等共性噪声 —— 8.8.8.8/doh.pub/time.apple/cp.cloudflare.com 这类
> 是"同软件家族"信号, 不是"同运营商"信号)。

### 8.1 白标基础设施簇(强信号)

**① llguanglisf.com 簇 —— 节点白标服务商**
| 品牌 | 客户端 | 节点域前缀 |
|---|---|---|
| speedcat | SpeedCat(FlClash系) | `scapp-*`(如 scapp-pk6f8zb) |
| qingyunti | QingyunLite(FlClash系) | `abappds-*.apiqytn2` |
| fastlink | FastLink(FlClash系) | `flapp-*`(如 flapp-peknyx7) |

三家品牌共用 llguanglisf.com GeoDNS 域族(→AWS, 当前对非目标网络 NXDOMAIN)+ 姊妹域
llguangli25n.com(qingyunti 订阅入口→durex-hkt1g02-01.yotocloud.com 落 HKT)。
**同一节点基础设施服务商, 三个品牌各自换皮** —— 典型"白标机场"模式: 卖家提供
节点池+GeoDNS+换皮客户端, 买家只管品牌运营。落地池各异(speedcat AWS SG / qingyunti AWS JP)。

**② bilibilitutu/nicehao 簇(hhy + lingdian)**
两家内存扫描节点域共享**同一个32位十六进制租户前缀** `75cff2ad89aadf5e257059ee571ebe11`:
- hhy: `75cff2ad…zf.szyd.nicehao.top`(→ACEVILLE CN2)
- lingdian: `75cff2ad…ob2.bilibilitutu.com`(→移动广州入口→AWS)
同一白标后端的不同线路出口, 两品牌各自 FlClash 系客户端(hhycenter/0dcloud)。

**③ moe233 簇(jinglingxueyuan + no626)**
同一运营商双品牌: 共享 relay.moe233.org 边缘网(UUID.relay 域 → *-hkg/nrt.edge.qchwnd.moe
自建PoP: CNSV/Future-Lain/AlphaJP/SiliconCloud)+ CloudFront CDN 线(cfn.cdn.moe233.org)
+ 订阅分发也在 CloudFront(sky-subscription.0443.link)。anytls SNI 也是同一 qchwnd.moe 体系。

**④ kuainiao + qiangda(双死品牌)**
共享 3 个注册域(laotiehj.top / dd33e.com / shhaisj.com)+ gfnly.com GSLB(→腾讯云HK
43.139.75.199)。同一运营商两个品牌, 现双双被墙/失活。

### 8.2 品牌家族(同一运营商的多品牌/多入口)
- **飞鸟家族**: feiniao + feiniao_1 + feiniao_2 —— 三个品牌三套面板(v2board×2 + xlcc自研), 同一运营方
- **muniu**: muniu(老订阅池) + muniu-ninja(隐藏池) —— 同一机场两个产品线
- **一元机场**: yiyuan(旧: 69.63.197.45 自建面板 + RackNerd 直连) → new-yiyuan(新: the-best-airport.com
  + Cloudflare 分发 + xhttp + Hytron/Cyberverse) —— 品牌延续, 基础设施完全换代, 中间还试过华为云CDN(video.yhby.xyz)
- **wandacloud(wdy)**: 独立 FlClash 白标, 不属于 llguanglisf 簇 —— 自己的 wdy66.cn GeoDNS(→移动广州)
  + xiongmao139.cn 面板(腾讯EdgeOne)+ 历史华为云北京中转

### 8.3 弱信号/待定
- bygcloud + maxiong: 面板/订阅域都 CNAME 到 mofanodes.com(XNNET/Cloudie HK 的小CDN)
  —— 可能只是选了同一家面板CDN服务商, 不构成同运营商证据
- selom 的多域别名(selom.xyz/selom.online/sly666.xyz/ycsh.shop/090227.xyz): 单品牌域名矩阵
- 数字系 .xyz 域名家族(7770006=liangxin / 238689=xm999 / 0900738=flybar / 090227=selom):
  便宜域名的流行命名风格, 无归属关联

### 8.4 结论
**44 个监控品牌 ≈ 30~32 个实际运营商**。白标化是 FlClash 系机场的显著趋势:
llguanglisf(3品牌)、bilibilitutu 系(2品牌)、moe233(2品牌)、飞鸟(3品牌)共 10 个品牌
由 4 个后端方提供。对监控的含义: **按"基础设施簇"聚合告警比按品牌聚合更有意义** ——
llguanglisf 簇的 GeoDNS 变更会同时影响 3 个品牌, 单品牌视角看不到全貌。
