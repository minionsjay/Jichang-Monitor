#!/bin/bash
# 启动 Xvfb → 拉起已认证的官方客户端 → watch 盯落盘自动摄入。
set -e

# 1) 虚拟显示（无头跑 GUI）
Xvfb :99 -screen 0 1280x800x24 >/tmp/xvfb.log 2>&1 &
export DISPLAY=:99
sleep 2

# 2) 拉起官方客户端（数据目录已挂载 → 免登录，靠 update_interval 自动更新）
if [ -x /usr/bin/clash-ninja ]; then
    /usr/bin/clash-ninja >/tmp/client.log 2>&1 &
    echo "[entrypoint] 客户端已启动，等待首次订阅落盘…"
else
    echo "[entrypoint] 警告：未找到 /usr/bin/clash-ninja，仅跑 watch"
fi

PROFILE="$CLIENT_DATA/profiles/$PROFILE_UID.yaml"
INDEX="$CLIENT_DATA/profiles.yaml"

# 3) 常驻 watch：落盘一更新就摄入 + 查华为 + 告警
exec python3 /app/run.py watch \
    --airport "$AIRPORT" \
    --file "$PROFILE" \
    --index "$INDEX" \
    --interval "$WATCH_INTERVAL"
