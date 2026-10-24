"""把 app 的四个文件打成一个单文件 HTML：styles.css + data.js + app.js 全内联。

用途：双击即可看（file:// 下相对引用会被某些沙箱拦），或直接丢进任何静态托管。
生成物：docs/09-新界面-preview/app/standalone.html

  用法： python -X utf8 tools/build_panel_standalone.py [--out PATH]
"""

from __future__ import annotations

import argparse
import io
import re
import sys
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "docs" / "09-新界面-preview" / "app"

# 正则自检：单文件版里不允许出现任何凭据形状
SECRET_PATTERNS = {
    "jwt": r"eyJ[A-Za-z0-9_-]{10,}",
    "password": r"(?i)password\s*[:=]",
    "subscribe_token": r"(?i)(subscribe\?token|token=[A-Za-z0-9]{16,})",
    "key_field": r"(?i)(aead_key|auth_token)",
    "long_url": r"https?://[^\s\"'<>]{40,}",
    "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
}


def read(name: str) -> str:
    return io.open(APP / name, encoding="utf-8").read()


def inline_guard(js: str) -> str:
    """内联进 <script> 前，把可能提前闭合的 </script 转义。"""
    return js.replace("</script", "<\\/script")


def build() -> str:
    html = read("index.html")
    css = read("styles.css")
    data = read("data.js")
    app = read("app.js")

    # 用 lambda 做替换串：内联内容里可能有 \\1、\\g 之类，不能当替换模板
    html = re.sub(
        r'<link rel="stylesheet" href="styles\.css(?:\?[^"]*)?">',
        lambda m: "<style>\n" + css + "\n</style>",
        html,
    )
    html = re.sub(
        r'<script src="data\.js(?:\?[^"]*)?"></script>',
        lambda m: "<script>\n" + inline_guard(data) + "\n</script>",
        html,
    )
    html = re.sub(
        r'<script src="app\.js(?:\?[^"]*)?"></script>',
        lambda m: "<script>\n" + inline_guard(app) + "\n</script>",
        html,
    )

    if re.search(r'(href="styles\.css|src="data\.js|src="app\.js)', html):
        raise SystemExit("内联没替换干净：还有外链引用")
    # 防呆：内联失败时会静默产出骨架页（曾经 434KB 变 6KB 没人发现）
    if len(html) < 200_000 or "function renderOverview" not in html:
        raise SystemExit("内联产物异常：只有 %d 字节或缺主函数，检查 index.html 的引用标签" % len(html))
    return html


def scan(text: str) -> int:
    hits = 0
    for name, pat in SECRET_PATTERNS.items():
        found = re.findall(pat, text)
        if found:
            hits += len(found)
            print("  [!] %s: %d 处 %s" % (name, len(found), found[:2]))
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(APP / "standalone.html"))
    args = ap.parse_args(argv)

    out = build()
    hits = scan(out)
    if hits:
        print("单文件版含 %d 处疑似凭据，拒绝写盘" % hits)
        return 1

    path = Path(args.out)
    io.open(path, "w", encoding="utf-8", newline="\n").write(out)
    print("written %s | %d 字节 | 泄漏自检 CLEAN" % (path, len(out.encode("utf-8"))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
