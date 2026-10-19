"""数据治理：快照归档/清理 + run.log 轮转。

背景（2026-10-19）：data/ 4.4 万快照 2.2GB 无清理、run.log 21MB 无轮转。

用法：
  python -m airmon.prune                 # dry-run：只统计，不动任何文件
  python -m airmon.prune --archive       # 超期快照移动到 data/_archive/<slug>/
  python -m airmon.prune --delete        # 超期快照直接删除（慎用）
  python -m airmon.prune --runlog        # run.log >20MB 时轮转为 run-<日期>.log，保留 5 份
  python -m airmon.prune --keep-days 30  # 自定义保留天数（默认 60）

安全边界：只处理 data/<slug>/<YYYYMMDDTHHMMSSZ>.json 形态的文件；
跳过 _archive/_ 开头目录；最新一份快照永不处理。
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import shutil
import time

from .store import DATA_DIR, _ts_of

SNAP_RE = re.compile(r"^\d{8}T\d{6}Z\.json$")
ARCHIVE_DIR = os.path.join(DATA_DIR, "_archive")
RUNLOG = os.path.join(DATA_DIR, "..", "run.log")
RUNLOG_MAX = 20 * 1024 * 1024
RUNLOG_KEEP = 5


def _airport_dirs() -> list[str]:
    out = []
    for d in sorted(glob.glob(os.path.join(DATA_DIR, "*"))):
        name = os.path.basename(d)
        if not os.path.isdir(d) or name.startswith(("_", ".")):
            continue
        out.append(d)
    return out


def prune_snapshots(keep_days: float, mode: str) -> int:
    """mode: dry-run | archive | delete。返回处理文件数。"""
    cutoff = time.time() - keep_days * 86400
    moved_bytes = deleted_bytes = seen = 0
    acted = 0
    per_dir = []
    for d in _airport_dirs():
        slug = os.path.basename(d)
        snaps = sorted(f for f in glob.glob(os.path.join(d, "*.json")) if SNAP_RE.match(os.path.basename(f)))
        if not snaps:
            continue
        snaps.sort(key=lambda p: os.path.getmtime(p))
        latest = snaps[-1]          # 最新一份永不处理
        todo = []
        for f in snaps[:-1]:
            ts = _ts_of(f)
            m = os.path.getmtime(f)
            use = ts if ts is not None else m
            if use < cutoff:
                todo.append(f)
        if not todo:
            continue
        size = sum(os.path.getsize(f) for f in todo)
        per_dir.append((slug, len(todo), size, mode))
        seen += len(todo)
        if mode == "archive":
            dest = os.path.join(ARCHIVE_DIR, slug)
            os.makedirs(dest, exist_ok=True)
            for f in todo:
                try:
                    shutil.move(f, os.path.join(dest, os.path.basename(f)))
                    acted += 1
                    moved_bytes += os.path.getsize(os.path.join(dest, os.path.basename(f)))
                except Exception:
                    pass
        elif mode == "delete":
            for f in todo:
                try:
                    size_f = os.path.getsize(f)
                    os.remove(f)
                    acted += 1
                    deleted_bytes += size_f
                except Exception:
                    pass
    if per_dir:
        print(f"快照治理（keep {keep_days:.0f} 天，mode={mode}）：{seen} 个文件超期")
        for slug, n, size, m in per_dir[:10]:
            print(f"  {slug:20} {n:4} 份  {size/1048576:7.1f} MB")
        if len(per_dir) > 10:
            print(f"  ... 共 {len(per_dir)} 个机场")
    else:
        print(f"快照治理（keep {keep_days:.0f} 天，mode={mode}）：没有超期文件")
    if mode == "archive" and acted:
        print(f"已归档 {acted} 份 / {moved_bytes/1048576:.1f} MB → data/_archive/")
    if mode == "delete" and acted:
        print(f"已删除 {acted} 份 / {deleted_bytes/1048576:.1f} MB")
    if mode == "dry-run" and seen:
        print("（dry-run 未改动任何文件；确认后加 --archive 或 --delete 执行）")
    return acted if mode != "dry-run" else seen


def rotate_runlog() -> bool:
    """run.log 超限则轮转：run.log → run-<YYYYMMDD-HHMMSS>.log，保留最近 RUNLOG_KEEP 份。"""
    if not os.path.exists(RUNLOG) or os.path.getsize(RUNLOG) < RUNLOG_MAX:
        return False
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(os.path.dirname(RUNLOG), f"run-{stamp}.log")
    try:
        os.replace(RUNLOG, dest)
    except Exception as e:
        print(f"[runlog 轮转失败] {e}")
        return False
    olds = sorted(glob.glob(os.path.join(os.path.dirname(RUNLOG), "run-*.log")),
                  key=os.path.getmtime, reverse=True)
    for f in olds[RUNLOG_KEEP:]:
        try:
            os.remove(f)
        except Exception:
            pass
    print(f"run.log 已轮转 → {os.path.basename(dest)}（保留最近 {RUNLOG_KEEP} 份）")
    return True


def main(argv=None):
    p = argparse.ArgumentParser(prog="airmon.prune", description=__doc__.splitlines()[0])
    p.add_argument("--keep-days", type=float, default=60.0, help="快照保留天数（默认 60）")
    p.add_argument("--archive", action="store_true", help="超期快照移动到 data/_archive/")
    p.add_argument("--delete", action="store_true", help="超期快照直接删除（优先级低于 --archive）")
    p.add_argument("--runlog", action="store_true", help="轮转超限的 run.log")
    a = p.parse_args(argv)
    acted = 0
    if a.runlog:
        rotate_runlog()
    if not (a.archive or a.delete or a.runlog):
        prune_snapshots(a.keep_days, "dry-run")
        return 0
    if a.archive:
        acted += prune_snapshots(a.keep_days, "archive")
    elif a.delete:
        acted += prune_snapshots(a.keep_days, "delete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
