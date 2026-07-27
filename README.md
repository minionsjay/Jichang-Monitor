# 机场订阅监控 + 华为关联检测（airmon）

> 目标：跨多个机场，自动**采集订阅节点 / 落地IP / 域名 / 客户端软件**等可观测面，
> 跑一套**华为关联签名**，命中即产生告警；同时留存历史快照做变更 diff。
> 承接上级目录的机场基础设施分析（`../简要结论.md`、`../analysis_ip_domain.csv`）。

## 两类机场，两条采集路线

- **类型 A 直连订阅型**：域名直接给订阅 URL。周期 GET（带对的 UA）→ 解析 Base64 / Clash YAML / 节点 URI。
- **类型 B 客户端锁定型**（muniu/V-Ninja 这种）：订阅接口运行时签名，直抓 403。
  策略是**借客户端的手**：在隔离容器里常驻官方客户端，靠它自己的 `update_interval` 过签名拉节点、
  落盘明文 `profiles/*.yaml`；我们 watch 落盘目录 / 轮询本地内核 API。签名与 GeoDNS 全交给客户端。

## 分层

| 层 | 模块 | 职责 |
|---|---|---|
| 配置 | `airmon/config.py` + `airports.yaml` | 机场注册表（type/domains/subscription/client） |
| 采集 | `airmon/collect.py` | `direct` / `client` 两个采集器 → 产出 artifacts |
| 解析 | `airmon/parse.py` | 各格式订阅 → 统一 Node（含私有 ninja） |
| 富化 | `airmon/enrich.py` | 节点 server 解析 + RDAP 归属（复用上级 rdap 逻辑） |
| **检测** | `airmon/detect.py` + `signatures/huawei.yaml` | 华为签名引擎，跨 IP/ASN/CIDR/域名/软件字符串 |
| 存储 | `airmon/store.py` | 每次抓取存带时间戳快照，支持历史 diff |
| 告警 | `airmon/alert.py` | 变更 & 华为命中 → 日志/文件（TG 后续接） |
| 调度 | `run.py` | CLI：collect / detect / scan-existing / diff |

## 华为签名维度（`signatures/huawei.yaml`）

| 维度 | 命中示例 |
|---|---|
| RDAP netname/owner | `HWCSNET`、`HUAWEI`、`华为`（**主判据，最稳**） |
| ASN | 华为云 AS55990 / AS136907 等 |
| CIDR | 华为云段（119.8/110.41/122.9/121.36/124.70…，兜底） |
| 域名/CNAME/NS | `huaweicloud.com`、`myhuaweicloud.com`、`hwclouds-dns`、华为云CDN `cdnhwc*` |
| 软件字符串 | `huawei`、`hmscore`、`agconnect`、`obs.*.myhuaweicloud` |

> 已知真实命中（验证用）：`analysis_ip_domain.csv` 里 `HWCSNET` 节点、muniu 注册 IP `119.8.242.52`、
> zyjabn.cn 的华为云 CDN 边缘域 `cdnhwc*`。

## 用法

```bash
cd monitor
# 1) 在现有数据上验证华为检测引擎（不联网抓取，直接扫上级 CSV）
python3 run.py scan-existing ../analysis_ip_domain.csv

# 2) 域名基础设施 + 华为侦察（不需账号，读 seeds.txt）
python3 run.py recon                    # 全部；或 --airport <slug>

# 3) 凭证自动登录 → 取订阅 → 抓节点 → 查华为（需 credentials.yaml）
cp credentials.example.yaml credentials.yaml   # 填 email/password/panel
python3 run.py pull                     # 全部；或 --airport <slug>

# 4) 直连型：已知订阅 URL 时直接采集
python3 run.py collect --airport bywave

# 5) 客户端锁定型（muniu）：摄入常驻客户端落盘 profile
python3 run.py ingest-profile --airport muniu --file profiles/xxx.yaml --index profiles.yaml

# 6) 对最近两次快照做 diff
python3 run.py diff --airport <slug>
```

## 自动登录（pull）说明

多数机场是 **v2board / Xboard**，登录/取订阅 API 一致，`credentials.yaml` 填账号即可批量拉。
实测：`maxiong` 确认 v2board 可通。注意三类需特殊处理：
- **面板域名 ≠ 营销域名**：`credentials.yaml` 的 `panel` 要填**你实际登录的后台地址**（否则 404）。
- **反爬验证**（如 speedcat 的 `/verify` Turnstile）：API 登录被拦，在 `credentials.yaml` 该机场填 `sub_url`（手动取的订阅链接），`pull` 会跳过登录直接抓。
- **SSPanel**（如 pkq 的 Pikachu 页）：`type: sspanel` 或 `auto` 自动回退；走 `/auth/login` + 从 `/user` 抠 `/link/<token>`。
- **muniu**：客户端锁定，走 `ingest-profile`，不走 pull。

`pull` 的三条路由（每个机场按此优先级）：`sub_url` 手动链接 → 否则 v2board/SSPanel 自动登录 → 缺凭证则跳过。

## 状态 / 路线

- [x] 阶段 1：骨架 + 直连采集 + 解析 + RDAP 富化 + **华为检测引擎** + 快照/diff + 文件告警
- [x] 阶段 1.5：域名侦察 recon（无账号）+ 凭证自动登录 pull（v2board/Xboard）
- [x] 阶段 1.6：SSPanel 登录（auto 回退）+ 反爬机场手动订阅 URL(sub_url) 兜底
- [x] 阶段 1.7：panel 自动发现（抓官网挖后台）+ `ingest-page`（无订阅链接机场，从 /user/node 页面抽 SSR/SS 节点）
- [ ] 阶段 2：软件采集面（下载客户端 → 静态拆包 → strings 扫华为签名）
- [~] 阶段 3：类型 B `watch` 落盘自动摄入已做（`run.py watch`）；容器常驻客户端 + 本地内核 API 待部署（需常驻主机）
- [ ] 阶段 4：探活（订阅层/节点层）+ 聚合自用订阅 + TG 告警

## 隐私

`profiles.yaml` / 采集快照含账号邮箱、token、注册 IP、节点密码。
`data/` 快照目录**不要进公开仓库**，告警外发前脱敏。
