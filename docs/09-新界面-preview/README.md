# 机场监控台 · 三个界面方向（预览）

首屏原型，1440×900，数据来自 2026-10-23 20:28 那轮真实采集（47 家机场、2310 节点、34 可用 / 5 订阅失效 / 2 仅客户端 / 6 断流）。

**先看这个**：`style-explorer.html`（单文件，双击可开，三个方向并排）

---

## A · 作战室

深色控制台。主区是一张 11×5 的机场矩阵，每家一格，左侧色条编码状态（绿可用 / 琥珀订阅失效 / 蓝仅客户端 / 红断流），格内数字是快照节点数。右栏是一条"需要你动手"的事件流，直接写清哪家为什么断。底部两条构成条：协议、地区。

- 字体：Segoe UI + Cascadia Mono（数字等宽对齐）
- 色彩：近黑 #07080a 底，状态四色
- 主视觉：矩阵本身，不靠图
- **推荐它做主界面**：你的日常问题是"哪家坏了、为什么、该我做什么"，矩阵 + 事件流能在一屏内回答，且 47 家的规模正好塞满一屏不用滚动。

## B · 体检报告

纸白编辑排版。衬线大标题「47 个机场，今天有 13 家没能交出节点」，四个大数字，一条 30 天节点总数折线，下面两栏名单：套餐到期（过期天数标红）、断了的原因。

- 字体：Georgia / 宋体 标题，Segoe UI 正文
- 色彩：纸 #fbfaf6、墨 #15171b、警示红 #bf3a2b
- 主视觉：标题 + 折线
- 适合当"每天看一页"的日报，不适合频繁巡检（信息密度低、要点三次才能看全）。

## C · 塔台

暗靛雷达。47 家按状态分三层环绕圆心：内环可用 34、中环订阅失效 + 仅客户端 7、外环断流 6；点位大小=节点数，0 节点画空心圈。圆心是节点总数。右侧四个环形仪表（可用率 / 可导出占比 / 已过期 / 覆盖）加断流清单。

- 字体：Segoe UI + Cascadia Mono
- 色彩：暗靛 #080911、紫 #8b7bf7、薄荷 #3ee0b0、玫瑰 #ff6b8a
- 主视觉：环形雷达
- 辨识度最高，但 47 个点位在环上无法精确点名，定位坏机场要配合右侧清单。

---

## 我的建议

**A 做主界面，C 的雷达收进「分析」页当态势图，B 的折线做「趋势」页。** 三者不是三选一，是同一个产品的三个视图：

- 总览 = A（矩阵 + 待办）
- 分析 = C（雷达 + 仪表）
- 趋势 = B（折线 + 名单）

只想先要一个：选 A。

## 怎么打不开就换一种

- 对比页：`docs/09-新界面-preview/style-explorer.html`（内嵌三个方向）
- 单页：`A-control-room.html` / `B-report.html` / `C-tower.html`（同目录，需与 `data.js` 放在一起）
- 本地服务：`http://127.0.0.1:56778/docs/09-新界面-preview/style-explorer.html`

## 已知限制

制作时没有图像输入能力，无法直接看渲染结果，改用机械校验：三页均无横向溢出、无控制台错误、无加载失败，对比度经 lint 修正后达标（首轮 41 处不达标 → 0 处）。A 的矩阵左侧色条与 C 的英文铭牌（CYCLE / SUPPLY）是刻意选择，用于状态编码与仪表感，不是默认模板。逐像素的视觉判断请以你自己的眼睛为准。

## 本地预览后端（机场信息 / 获取节点）

静态页只能读快照。要让抽屉里能显示**面板地址、订阅链接**并点按钮**真的去拉一次节点**，需要起一个只监听本机的 Python 服务：

```bat
python -X utf8 tools/panel_preview_server.py --port 57010
```

然后访问 <http://127.0.0.1:57010/index.html>（这个页面会自动探测 `api/status`，探测不到时抽屉里「机场信息」显示 `—`、「获取节点」按钮置灰，其余功能不受影响）。

- 接口：`GET /api/status`、`GET /api/airport/<slug>`（订阅默认脱敏为 `https://q59F…Qj.yuji.homes`）、`GET /api/airport/<slug>?reveal=1`（取完整链接，供「显示 / 复制」用）、`POST /api/fetch/<slug>`（后台起 `run.py pull --airport <slug>`，单飞，同一机场 60 秒冷却）、`GET /api/fetch/<slug>`（状态 + 日志尾巴，已脱敏）。
- 三道守卫：只绑 `127.0.0.1`；`data/run.lock` 存在时拒绝启动拉取（不跟定时轮抢）；子进程环境带 `HTTP_PROXY=http://[::1]:7890`（本机代理只监听 IPv6 回环）。
- 订阅链接只在用户主动点「显示 / 复制」时才从本机取一次，不写进任何文件、不进 `data.js`、不进 `standalone.html`。离线单文件版没有这些能力。

## 到期标记（2026-10-23）

- 套餐已过期的机场，卡片状态行后面跟一个红色小标「到期」（tooltip：`套餐 YYYY-MM-DD 已到期（N 天前）`），卡片左侧状态色条同时转红。
- 三档密度各自处理：中/大档在位内联（`.cell .xd`）；紧凑档状态行本就隐藏，改用 `.matrix[data-d="s"] .cell.exp::after` 贴右下角，保证任何密度都看得见。
- 当前命中 5 家：yiyuan(-366) / muniu(-99) / oixcloud(-37) / qiangda(-28) / jsqpro(-23)。

## 卡片尺寸修正（2026-10-23，v2）

用户反馈「卡片太小、有些数字被挡着了」——体检证实是真 bug：`.cell` 用固定 `height` + `overflow:hidden`，而内容（名称 16px + 数字 20px + 底行 16px + 内边距 11px ≈ 65px）在 m 档 62px、s 档 48px 的框里装不下，中档 47 格全部把状态行裁到框外，紧凑档过期卡的数字被裁。

修法（结构性）：卡片改 `min-height` + flex 纵向三段（名称 / 数字 / 底行），数字 `margin-top:auto` 贴底；「可导出」从右下角绝对定位移进底行右侧，与状态文字并排，不再压数字；三档尺寸同时放大 s 124×66、m 152×82、l 182×98。

验证：三档 `scrollHeight<=clientHeight` 溢出格数 0、每格子元素越界 0、名称 ellipsis 截断 0；九视图整体 `clipped`/`over` 全空；表格 td 加 `overflow-wrap:anywhere` 一并修掉长域名溢出。

## 复制按钮（2026-10-23）

侧栏 iframe 里 `navigator.clipboard.writeText` 会被拒（`NotAllowedError: Write permission denied`），原实现直接落到「复制失败」。现改为三级降级：

1. `navigator.clipboard.writeText`（点按时先 `window.focus()`）
2. 临时 textarea + `document.execCommand("copy")` —— 覆盖绝大多数 iframe 场景
3. 都失败：把订阅地址全文显示出来并**整段选中**，按钮变成「已选中，Ctrl+C」，旁边提示按 Ctrl+C

同时修了服务端 `_mask_url` 的一个漏打码：v2board 系把 token 放**路径**里（`/link/DXpChNx8ssSCJ8XA`），原来只遮 query 和主机首段，路径里的 token 是明文 → 现在路径中长度 ≥12 的字母数字段也按 `前4…后4` 打码（实测 `http://43.135.28.238/link/DXpC…J8XA?clash=2`）。

## 机场中文名

卡片、表格、抽屉标题都用中文名做主名，英文 slug 作副名（小一号、灰、等宽）：

- 名字来源 `data/airport_names.json`（41/47 家），`src` 字段记录依据：`panel-title`（抓机场面板首页 `<title>`）、`doc`（存量文档）、`infer`（推断）。
- 剩余 6 家没有中文名（cloudnx / fastlink / jsqpro / ss-id / xm999 / ssrdog），保留英文原名，不重复显示副名。
- 纯 ASCII 品牌名（BYWAVE / DOVE / Mitce / oixCloud / KTM Cloud / Dual Net…）视为「本身就是英文名」，不加副名。
- 副名有长度门槛：卡片 ≤10 字符、表格与标题 ≤14 字符，超长 slug（`jinglingxueyuan`）不显示副名，避免挤压中文名。
- 过长中文名用 `cn_short` 短名进卡片（`牧牛云 V-Ninja` → 牧牛忍者、`一元机场（新）` → 一元新站），抽屉与表格仍显示全名。
- 机场库的搜索框现在同时匹配中文名（搜「牧牛」可出 muniu 与 muniu-ninja）。
- 生成链路：`data/airport_names.json` →（`tools/gen_panel_data.py` 的 `load_names()`）→ `data.js` 的 `airports[].name_cn` → `app.js` 的 `nmOf()`。
- 补中文名：直接改 `data/airport_names.json` 加 `{slug: {cn, src}}`，重跑 `python -X utf8 tools/gen_panel_data.py`。

## 在抽屉里改订阅地址

点机场 → 抽屉「机场信息」→ 订阅那一行右侧「修改」→ 粘贴新链接 → 保存。

- 写回目标：`credentials.yaml` 里**这一家的 `sub_url` 一行**，文本级替换，不动其它账号与其它字段。
- 保存前先备份到 `data/backup/credentials-<时间戳>-<毫秒>.yaml`（保留最近 40 份，重名自动加序号）。
- 写完立刻回读校验：YAML 必须能解析、该家 `sub_url` 必须等于新值；任一不满足就**整体回滚**并用原文本覆盖。
- 只接受 `http://` / `https://`，长度 ≤2048，不许出现空格/换行/引号/控制字符；留空＝清空这家订阅（会二次确认）。
- 界面显示始终是打码后的值；「显示」按钮才向本机后端取全文。
- 保存只改配置，**不会立刻拉节点**——改完点同一抽屉里的「获取节点」才会用新链接拉一次。
- 只在本地预览服务（`python -X utf8 tools/panel_preview_server.py --port 57010`）下可用；双击 `standalone.html` 打开时没有后端，编辑入口不出现。

对应后端：`tools/panel_preview_server.py` 的 `save_sub_url()` 与 `POST /api/sub`。

## 「最近成功」的时间口径（2026-10-24）

抽屉里「最近成功」= **该机场最近一份「真拿到节点」的快照时间**，由 `tools/gen_panel_data.py` 的 `latest_ok_local()` 扫 `data/<slug>/*.json` 得出，不读 `data/sub_health.json` 里的 `last_ok`。

为什么改：`sub_health.json` 的 `last_ok` 是 2026-10-21 订阅诊断脚本写入的一次性值，之后每轮拉取成功都不会更新，于是出现「今天刚拉到、界面显示 2 天前」。改后 47 家里只有真正没再成功过的（如 bywave，20 节点停在 10-19）才会显示旧时间。

配套：抽屉打开时用后端 `/api/airport/<slug>` 返回的 `last_ok`（同一算法实时算）覆盖显示；点「获取节点」拉取成功后，服务端会自动重跑 `tools/gen_panel_data.py` 重新生成 `data.js`，界面给出「点这里刷新」链接，刷新后卡片数字与时间同步更新。

## 承载与 CDN 归属（2026-10-24 新增）

抽屉里有两处新信息，回答的是「这家机场的节点落在谁家的云/CDN 上」。

- **承载/CDN**（机场信息区）：按快照里每个节点 IP 的 RDAP 归属（owner/netname）归类后取前 4 名，
  形如 `腾讯云 97% · 未归类 3%`。识别得到的厂商有：华为云/CDN、Cloudflare、Akamai、阿里云、
  腾讯云（含海外 Aceville）、AWS、Azure、Google、Oracle、百度云、中华电信 HiNet、香港宽频/HKT、
  Cogent、CTG、三大运营商，以及「IP 转租/代理」「未归类」。
  含华为时该片段标红。归类只依据 RDAP 文本，不做额外请求，认不出的统一记「未归类」。
- **节点表的「归属」列**：逐节点的厂商名，方便看出一家机场的节点是不是集中压在同一个落地。

### CNAME 链也算证据

`airmon/dnsq.py` 用纯标准库实现了 UDP DNS 查询（支持 CNAME 压缩指针、32 线程批量），
`airmon/collect.py` 在富化阶段给域名型 server 采 CNAME 链写入 `raw._cnames`，
`airmon/detect.py` 的域名维度再把这条链一起查。

意义：节点域名 CNAME 到 `xxx.cdnhwcibv.com` / `xxx.hwclouds-dns.com` 这类华为 CDN 边缘域时，
现在能被命中；此前只看 server 字符串，这一层完全看不见。

### 当前实况（2026-10-24 实测 1131 个域名）

- 994 个直接是 A 记录（无 CNAME），137 个有 CNAME 链：1 跳 79、2 跳 32、3 跳 26。
- **没有任何一条指向公共 CDN**（Cloudflare / Akamai / 华为 CDN / CloudFront 均 0），
  链的末跳都是机场自有域或自有 GSLB（`gslb-hy.com`、`gtm-host.com`、`singgnetworkcdn.com`）。
- 115 个域名末跳换到了另一注册域（如 `39140.linknode.cc → wz2.hfzz.eu.org`），
  属于跨域 CNAME 调度，不是 CDN。

也就是说：**检测能力已经就位，但当前 47 家没有一家把节点前置到公共 CDN**。
真有人这么做时，`detect.py` 会同时给两条证据（CNAME 命中 + 边缘 IP 的 RDAP 命中）。

## 拉取成功后卡片即时变绿

在抽屉里点「获取节点」，流程是：`POST api/fetch/<slug>` → 真跑 `run.py pull --airport <slug>` → 成功后自动重跑 `tools/gen_panel_data.py` 重写 `data.js` → 前端 `reloadData()` 重新拉取并重绘。三处关键修复（2026-10-24）：

1. **状态按实测判定**：`state` 不再吃 `data/sub_health.json` 里上一次诊断的旧值，而是「最新快照时间 + 是否真有节点 + 套餐是否过期」实时算。所以订阅换好、拉取成功后卡片立刻从黄转绿（实测 ktm 55 节点、everlife 23 节点）。
2. **清视图绘制标记**：`reloadData()` 里补 `S.drawn = {}`。之前每个视图都有「画过一次就 return」的标记，数据变了但卡片纹丝不动。
3. **抽屉提示重写**：抽屉重绘会重建 `#apFetchMsg`，所以先重绘再写「已完成 · 已刷新」，否则提示被冲掉、看起来像没反应。

`data/sub_health.json` 仍保留 `reason` / `action` 两列（说明「卡在哪、该做什么」），只是不再决定颜色。

## 客户端型机场的完整节点：从 core 内存捞

`scan-memory` 对客户端型机场只能拿到 `IP:端口`（`protocol=unknown`，导不出去）。原因是这类客户端把合并后的完整配置放在 core 进程内存里，磁盘上根本没有——青云梯极速版更极端，`%APPDATA%\com.qytapp.clients.apex\青云梯-极速版\.memory-only-v2` 明确写了「只在内存」。它的订阅地址在 `shared_preferences.json` 里是 `apex-url-v2:` + AES 密文（DPAPI 保护密钥），而订阅端点对脚本出口直接回「安全验证」HTML，所以只能走内存。

```bash
# 1) 先手动打开客户端并保持运行（必须！Apex.exe 自己拉起时 core 只活十几秒）
# 2) 抓完整节点（含 uuid / servername / flow / skip-cert-verify）
python -X utf8 tools/dump_client_nodes.py --slug qingyunti --process ApexCore
#    → data/client_nodes/qingyunti.json
# 3) 重新导出可导入配置
python -X utf8 -m airmon.nodeset
#    → nodes/qingyunti.yaml（mihomo：proxy-providers: {qingyunti: {type: file, path: ./nodes/qingyunti.yaml}}）
```

为什么用 `data/client_nodes/` 这个独立目录：`run.py all` 每轮的 scan-memory 会用「只有 server:port」的快照覆盖最新快照，若只看快照，完整节点会被瞬间吃掉（ssrdog 实测从 36 个归零）。`airmon/nodeset.py` 的 `_client_nodes()` + `_merge_nodes()` 把 client_nodes 当一等来源，按 `(server,port)` 合并。

青云梯极速版实测：62 个 VLESS（XTLS-Vision、每节点独立 SNI），节点名 `香港-01…`，`uuid` 与面板 `xboard_domain_user.uuid` 一致。

## 客户端配置只在内存时怎么捞（server 锚点法）

有些客户端（万达云 `wandacloudCore`、青云梯 `ApexCore`）把订阅配置只放在内存里，磁盘上
`cache.db` 不是 SQLite、`flutter_secure_storage.dat` 需 DPAPI 解密。内存里的节点对象
**起始键不固定**（万达云是 `{"alpn":…,"client-fingerprint":…,"server":…`，`server` 在中间），
所以不能靠 `\{\s*"server"` 匹配，整份 `"proxies":[…` 数组又常跨 region 边界截断。

`airmon/memsan.py` 的做法：找每处 `"server":"…"`，向前回溯到 `{` 并做字符串感知的括号配平，
再 `json.loads` 取单对象（失败就再往前找一个 `{`，最多 4 次）。实测万达云 555 条记录里
捞出 68 个完整 AnyTLS 节点（香港10/台湾20/美国6/新加坡6/日本3/印尼3/韩国3…），
其余 487 条是客户端探测出来的裸 `IP:端口`（无协议无密码，导不进配置，属正常）。

客户端要**保持运行**才能扫：`credentials.yaml` 里给该机场 `client.keep_alive: true`，
`run.py scan-memory` 扫完就不会 `taskkill` 关掉它。

## 运行记录（独立于总览）

「运行」页现在是定时轮的账本，三块：

1. **健康体检**：`tools/watchdog.py` 的四类病（僵尸锁 / 心跳超时 / 台账未收尾 / 太久没成功）。
2. **历史轮次**：`data/runs.json` 最近 20 轮（开始/耗时/触发/结果/成功失败/节点/陈旧），点一行展开失败名单。
   只有带 `trigger: scheduled` 的是定时轮；早期轮次是 `tools/backfill_runs.py` 从快照时间聚类还原的，标 `derived`。
3. **订阅原文存档**：`data/subraw/<slug>/<ts>.yaml|json|txt` 是每轮订阅的原始响应（每机场留 30 份）。
   正文含节点密码/uuid，**不进 git**（`.gitignore` 已排除 `data/subraw/`），面板查看走 `/api/raw/<slug>` 且服务端打码。

定时轮跑完时，前端 60 秒轮询 `/api/status` 的 `started_at|ended_at|nodes_total` 指纹，
一变就 `reloadData()` 并 toast「检测到新一轮跑完」——总览、到期、告警、节点页一起换新。

## 代理可达性（哪些机场非走代理不可）

`python -X utf8 tools/proxy_need.py` → `data/proxy_need.json`，对每家机场的订阅地址与面板各测两次（直连 / 走 `[::1]:7890`），
只读第一段响应，不下载全文。面板上体现为两处：抽屉「订阅入口」一行、运行页「代理可达性」一块。

分类词只有五个：`直连即可` / `直连/代理均可` / `需代理` / `直连不通 · 需代理`（直连失败且代理没测）/ `直连与代理都不通`。

注意两点：

- **代理没开时那一组不测**，所以「需代理」无法判定，只能看到「直连不通」；先开代理再跑一次才有完整结论。
- `403 / 504` 不算「需代理」——那是站点自己拦脚本或站点挂了，开代理也未必通；`SSL 握手失败`才是墙外订阅域的典型特征。

## 快照文件名：本地时间、一眼可读（2026-10-24）

`data/<机场>/` 下的快照文件名从 UTC 紧凑格式改成本地时间：

| | 文件名 | 含义 |
|---|---|---|
| 旧（历史 4.5 万个） | `20261024T132028Z.json` | UTC `2026-10-24 13:20:28` = 北京时间 **21:20:28** |
| 新 | `20261024-212028.json` | 本地时间 **2026-10-24 21:20:28** |

时间取自 `snap.ts`（采集时刻，不是落盘时刻），与 `meta.ts` 一致。
`airmon/snapnames.py` 是文件名的唯一真源：`fmt()` 生成、`parse()` 解析（带 `Z` 按 UTC，
不带 `Z` 按本地时区，都返回带时区的 datetime）、`names()` 排序、`display()` 转人话。

**不要直接 `sorted(文件名)`**：`-`(0x2D) < `T`(0x54)，纯字符串排序会把所有新文件排到旧文件后面，
「最新快照」于是指到几个月前。目录遍历一律走 `snapnames.names(d)`；库里 13 处读取点
（store / rawstore / analyze / dashboard / huawei_detect / prune / quota / gen_panel_data /
panel_preview_server / backfill_runs）已统一。

## 点一次「获取节点」到底做了什么

前端 `POST /api/fetch/<slug>` → 服务端判断类型后起子进程：

* 订阅型：`run.py pull --airport <slug> -v`
  → 拉订阅 / 面板登录 / `server-fetch` API → `airmon.rawstore.save_raw()` 存原文
  → 解析 → `airmon.enrich`（DNS 解析 + RDAP）→ `airmon.detect`（华为五维 + CNAME）
  → `store.save()` 写快照
* 客户端型（没有 `sub_url`）：`run.py scan-memory --airport <slug>`
  → 找/拉起客户端内核 → 扫内存 → 锚点法解出完整节点 → 写快照
  （非管理员时会写 `.tmp_scan/<slug>.bat` 再 UAC 提权跑）

成功后服务端自动两步：`python -m airmon.nodeset`（重算 `nodes/`）→ `tools/gen_panel_data.py`
（重算 `data.js`），前端轮询到 done 就刷新抽屉与卡片。

**落盘清单**（以一次订阅型 pull 实测为准）：

| 文件 | 说明 |
|---|---|
| `data/<slug>/<本地时间>.json` | 本轮快照（节点 + meta + 华为命中） |
| `data/subraw/<slug>/<时间>.<yaml/json/txt/b64>` + `.json` | 订阅原文 + 元数据（打码后可直接看） |
| `data/subraw/index.json` | 原文存档索引 |
| `nodes/<slug>.yaml` / `nodes/<slug>.txt` | Clash proxies / base64 订阅体（47 家全量重写） |
| `nodes/index.json` | 各机场可导出节点数与跳过原因 |
| `docs/09-新界面-preview/app/data.js` | 面板数据包 |
| `data/panel_state.json` | 每机场状态/节点数/原因（服务端读） |
| `data/rdap_cache.json` | RDAP 归属缓存（命中新 IP 时追加） |

`server-fetch` 分支是直接吃 v2board 的 JSON API，没有"订阅原文"，所以不写 `subraw/`。
