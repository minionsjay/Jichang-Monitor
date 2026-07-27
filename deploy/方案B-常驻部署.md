# 方案 B：客户端锁定型机场（V-Ninja 类）常驻自动化部署

> 目标：让官方客户端在隔离环境常驻、自动过签名拉 ninja 隐藏节点落盘，
> `watch` 自动摄入 + 查华为 + 告警。**全程不碰签名逆向**。

## 架构

```
┌─ 隔离容器 / 常驻VM ─────────────────────────────┐
│  官方 V-Ninja 客户端 (Tauri GUI, 跑在 Xvfb 虚拟显示)      │
│    · 已认证数据目录挂载进来 → 免交互登录                    │
│    · update_interval 到点自动过签名拉订阅 → 落盘 profiles/*.yaml │
│                       ↓                                  │
│  run.py watch (常驻) 盯 profiles → 自动摄入               │
│                       ↓                                  │
│  快照 + 华为检测 + 告警(alerts.log / 后续TG)              │
└──────────────────────────────────────────────┘
   ↑ 挂载: ①已登录的 client-data/  ②输出 ../data/
```

## 关键难点与破解

| 难点 | 破解 |
|---|---|
| 容器里没法交互登录 / 可能有验证码 | **一次性在桌面登录好，把客户端数据目录整个拷进容器挂载**（含会话/token），客户端起来即已认证 |
| 客户端是 GUI(Tauri/webkit2gtk) | 用 **Xvfb 虚拟显示**跑无头 |
| 客户端要装 root 服务 + 动 iptables/TUN | **只取节点不需要真路由**——可不开 TUN，省掉 `--privileged`；要 TUN 才加 `NET_ADMIN`+`/dev/net/tun` |
| 闭源客户端有采集/持久化风险 | 每个客户端**独立容器**、网络隔离、只挂需要的卷 |

## 前置物料

1. `client-data/` —— **已登录**的客户端数据目录（从桌面版拷来），即项目里
   `0701-muniu/io.github.clash-verge-ninja.clash-verge-ninja/` 那种结构（含 `profiles.yaml` + `profiles/<uid>.yaml`）。
2. 客户端安装包 `V-Ninja-*.rpm`（放 `deploy/` 下，Dockerfile 会静态解包，不执行安装脚本）。
3. 该订阅的 `PROFILE_UID`（muniu 是 `Roa863gqRJqo`）。

## 起步

```bash
cd monitor/deploy
cp ../../0701-muniu/V-Ninja-2.3.1-1.x86_64.rpm .          # 安装包
cp -r ../../0701-muniu/io.github.clash-verge-ninja.clash-verge-ninja ./client-data  # 已登录数据目录
docker compose up -d --build
docker compose logs -f          # 看 watch 是否在摄入
```

产出直接落到 `monitor/data/muniu-ninja/`，华为命中进 `data/alerts.log`。

## 保活与告警（半自动介入点）

- **登录态失效**是唯一需要人介入的点：客户端会停更 → `profiles/<uid>.yaml` 的 mtime 长期不变。
  监控办法：给 watch 加"profile 超过 N 小时未更新就告警"（TODO，见 README 阶段4），
  收到告警后在桌面重登、重新拷 `client-data/`。
- 客户端本身会按 `update_interval`（muniu 默认 14400s=4h）自动拉，无需主动触发。

## 更稳的替代：专用 VM / 常驻小主机

客户端本就要 root/systemd/TUN，**跑在一台常驻 Linux 小主机/VM 上比塞进容器更省心**：
直接装官方客户端、登录一次，再把 `run.py watch` 注册成 systemd 服务盯落盘即可。
容器方案适合"多个客户端锁定型机场各自隔离"时批量复制。

## 安全红线（承接 0701-muniu 分析）

- 客户端闭源、装 root 服务、动 iptables → **只在一次性容器/VM 跑，别碰主机与主项目数据**。
- `client-data/` 与 `data/` 快照含账号 token / 节点密码 → **不外传、不进公开仓库**。
