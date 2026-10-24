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
