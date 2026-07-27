# V-Ninja 类客户端锁定型机场 —— 常驻取节点容器
# 思路：静态解包官方客户端(不执行安装脚本) + Xvfb 无头跑 GUI + watch 摄入落盘。
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
# 运行 Tauri/webkit GUI + Xvfb + python 所需依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
        libarchive-tools xvfb ca-certificates \
        libwebkit2gtk-4.1-0 libgtk-3-0 libayatana-appindicator3-1 \
        librsvg2-2 libnss3 libasound2t64 \
        python3 python3-yaml python3-requests \
    && rm -rf /var/lib/apt/lists/*

# 静态解包 RPM（bsdtar 只解 payload，不跑 pre/post 安装脚本 → 零执行风险）
WORKDIR /opt/vninja
COPY V-Ninja-*.rpm /tmp/vninja.rpm
RUN bsdtar -xpf /tmp/vninja.rpm -C / && rm /tmp/vninja.rpm

# 监控代码
COPY . /app
WORKDIR /app

# 已登录数据目录由 compose 挂载到此路径
ENV CLIENT_DATA=/root/.local/share/io.github.clash-verge-ninja.clash-verge-ninja
ENV PROFILE_UID=Roa863gqRJqo
ENV AIRPORT=muniu-ninja
ENV WATCH_INTERVAL=300

ENTRYPOINT ["/app/deploy/entrypoint.sh"]
