"""快照文件名的唯一真源：生成、解析、排序。

两种格式并存：

* 历史：``20261024T132028Z.json`` —— UTC 时间，末尾 Z。库里约 4.5 万个文件都是这个格式，
  ``20261024T131556Z`` 看起来像随机串，其实是 ``2026-10-24 13:15:56 UTC``（= 北京时间 21:15:56）。
* 新格式：``20261024-212028.json`` —— **本地时间**，一眼能读出「10 月 24 日 21:20:28」。
  这是按用户要求改的（"用获取节点的时间分钟秒保存，看得清楚一些"）。

因为两种格式混存，**任何按文件名排序的地方都不能直接 ``sorted(names)``**：
``-``(0x2D) 排在 ``T``(0x54) 前面，纯字符串排序会把新格式整体排到旧格式之后，
于是"最新快照"会指到几个月前的旧文件上。一律走 :func:`names`。
"""

from __future__ import annotations

import datetime as dt
import os
import re

# 20261024T132028Z.json / 20261024-212028.json
SNAP_RE = re.compile(r"^(\d{8})[T-](\d{6})(Z?)\.json$")
_STRPTIME = "%Y%m%d%H%M%S"


def is_snap(name: str) -> bool:
    """是不是一个快照文件名。"""
    return bool(SNAP_RE.match(name))


def parse(name: str) -> dt.datetime | None:
    """文件名 -> 带时区的 datetime。旧格式按 UTC，新格式按本地时区。解析不了返回 None。"""
    m = SNAP_RE.match(os.path.basename(name))
    if not m:
        return None
    try:
        naive = dt.datetime.strptime(m.group(1) + m.group(2), _STRPTIME)
    except ValueError:
        return None
    if m.group(3):  # 有 Z：历史上的 UTC
        return naive.replace(tzinfo=dt.timezone.utc)
    return naive.astimezone()  # 无 Z：新格式，本地时间


def parse_stem(stem: str) -> dt.datetime | None:
    """同 parse()，但接受不带 .json 的 stem（也会先剥掉目录部分）。"""
    base = os.path.basename(str(stem))
    return parse(base if base.endswith(".json") else base + ".json")


def epoch(name: str) -> float:
    """用于排序：解析不出时间的排到最后。"""
    d = parse(name)
    return d.timestamp() if d else float("-inf")


def fmt(when: dt.datetime | None = None) -> str:
    """生成本轮新快照的文件名主体（本地时间，如 20261024-212028）。"""
    when = (when or dt.datetime.now()).astimezone()
    return when.strftime("%Y%m%d-%H%M%S")


def display(name: str) -> str:
    """文件名 -> 「2026-10-24 21:20:28」这样的本地时间串（面板/日志用）。"""
    d = parse(name)
    return d.astimezone().strftime("%Y-%m-%d %H:%M:%S") if d else "（时间未知）"


def names(dirpath: str | os.PathLike, reverse: bool = True, limit: int | None = None) -> list[str]:
    """目录里的快照文件名，按真实时间排序（默认最新在前）。"""
    try:
        items = os.listdir(dirpath)
    except OSError:
        return []
    snaps = [n for n in items if SNAP_RE.match(n)]
    snaps.sort(key=epoch, reverse=reverse)
    return snaps[:limit] if limit else snaps


def newest(dirpath: str | os.PathLike) -> str | None:
    got = names(dirpath, reverse=True, limit=1)
    return got[0] if got else None


def paths(dirpath: str | os.PathLike, reverse: bool = True, limit: int | None = None) -> list[str]:
    """同 names()，但返回完整路径。"""
    return [os.path.join(str(dirpath), n) for n in names(dirpath, reverse, limit)]


if __name__ == "__main__":  # 自测：python -X utf8 -m airmon.snapnames
    samples = ["20261024T132028Z.json", "20261024-212028.json", "bad.json"]
    for s in samples:
        print(f"  {s:26s} -> {display(s)}  epoch={epoch(s):.0f}  is_snap={is_snap(s)}")
    print("  新名字示例:", fmt() + ".json")
