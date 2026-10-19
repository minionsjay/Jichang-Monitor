# @local/airmon-sidebar —— 接线速查（lead 用）

> 完整方案：`E:\Hermes-Agent\Jichang-Monitor\docs\08-侧边栏插件方案.md`（§7 结构清单 / §8 安装卸载 / §11 接线清单）

## 装到哪

复制本目录全部文件到 `F:\DSH-Workspace\插件安装\airmon-sidebar\`，然后：

```
plugin_manager { "action": "install_bundle", "target": "F:\\DSH-Workspace\\插件安装\\airmon-sidebar" }
```

`application` = applied 且无 `warnings` → 生效；`restart-required` → 重启 DSH。
（备选手工 link 流程与 profile 级 cordis.patch.yml 覆盖行见方案 §8。）

## 验证

1. `plugin_manager { "action": "list_plugins" }`：`@local/airmon-sidebar` enabled。
2. Web GUI 左轨出现「机场监控」图标 → 面板 KPI 出「机场 47 / 节点 2644」→ footer 显示「实时」。
3. 脱敏抽检：`/airmon-sidebar/api/data` 响应搜 `http`、`"panel"`、`"s":`、`"owners"` → 0 命中（无 URL、无节点服务器字段、无面板地址、无属主信息）。

## 数据源

- 默认读 `E:\Hermes-Agent\Jichang-Monitor\dashboard\index.html`；路径不同 → 设环境变量 `AIRMON_DASHBOARD` 指向 index.html（或改 `logic.js` 顶部 `DEFAULT_INDEX`）。
- 读不到 → 回退包内 `data.json` 快照，面板 footer 显示「内嵌快照」以提醒。

## 生效规则（改动后）

| 文件 | 生效方式 |
|---|---|
| logic.js / panel.html / data.json | 热更（下次请求即生效） |
| client.js | 客户端 HMR（或刷新页面） |
| index.js / package.json / cordis.patch.yml | 需重启 DSH |

## 停用 / 卸载

```
plugin_manager { "action": "set_plugin", "target": "@local/airmon-sidebar", "enabled": false }
plugin_manager { "action": "remove_bundle", "target": "@local/airmon-sidebar" }
```

卸载后建议重启清模块缓存；本插件无持久化用户数据，卸载即净。
