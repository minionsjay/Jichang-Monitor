# 08-原型 · 机场监控侧边栏面板原型

## 文件

| 文件 | 用途 |
|---|---|
| `airmon-panel.html` | **双击可打开**的静态原型：顶部 KPI 条 + 47 机场卡片网格 + 套餐到期摘要 + 告警/华为/运行页。82KB 单文件，内嵌脱敏快照 |
| `data.json` | 脱敏占位数据（54KB，从 `dashboard/index.html` 提取 + 白名单过滤 + 负向扫描 CLEAN）。经 http 静态服务打开时面板会自动 fetch 它升级数据源 |
| `airmon-panel.template.html` | 生成模板（`__DATA__` 占位符），换数据时重跑生成脚本即可，平时不用管 |
| `plugin/` | **完整可安装的 DSH 插件骨架**（@local/airmon-sidebar），接线步骤见 `../08-侧边栏插件方案.md` §11 |

## 双击打开的预期行为

- 立即以内嵌快照渲染（file:// 下浏览器拦截 fetch，属预期）。
- footer 数据源徽标显示「内嵌快照」。
- 顶部「刷新」可重绘；经任意静态服务（如 `python -m http.server`）打开时，徽标会变成 `data.json`，装进插件后经 postMessage 桥显示「实时」。

## 数据更新

替换 `data.json`：按方案 §6.2 白名单契约从新一轮 `dashboard/index.html` 提取（提取脚本要点见方案文档末尾附注），然后：

```bash
python - <<'EOF'
tpl = open('airmon-panel.template.html', encoding='utf-8').read()
data = open('data.json', encoding='utf-8').read().strip()
open('airmon-panel.html', 'w', encoding='utf-8').write(tpl.replace('__DATA__', data.replace('</', '<\\/')))
EOF
cp airmon-panel.html plugin/panel.html && cp data.json plugin/data.json
```

## 样式约定

全部颜色走 `var(--dsw-*, 回退值)`：DSW 内吃真实主题 token，独立打开吃 neutral-bluish 回退值（#fff/#f9fafb/#f1f3f5/#ebeef2/#61666b/#81858c/#0f1115）；主按钮黑 #0f1115 / hover #43454a；业务蓝 #4176e6 仅强调；无渐变。窄栏（侧栏宽约 420-560px）单列自适应，宽栏自动多列。
