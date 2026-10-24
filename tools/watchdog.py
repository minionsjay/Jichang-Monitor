#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""看门狗：判断「定时轮是不是已经死了」，别再静默停摆。

为什么要它：2026-10-24 14:28 那轮跑到 14:30 就被硬杀，留下的痕迹互相矛盾——
计划任务 `LastTaskResult=0`（假绿）、`data/run.lock` 还在、`last_run.json` 永远
`status=running`、面板按钮被僵尸锁挡住。人是靠"顺手查一下进程"才发现的。

判据（三种病）：
  1. 僵尸锁   —— run.lock 里有 pid，但该进程已不存在（后面所有轮次都会被跳过）。
  2. 卡死     —— 进程还在，但 run_heartbeat.json 超过 --stale-min 分钟没更新
                  （旧版 run.py 没有心跳文件时，退化为看 last_run.json 的 started_at）。
  3. 未收尾   —— 没有锁、但 last_run.json 仍是 status=running（进程被硬杀，没走收尾）。

用法：
  python -X utf8 tools/watchdog.py                 # 人类可读
  python -X utf8 tools/watchdog.py --json          # 机读（面板/总账可用）
  python -X utf8 tools/watchdog.py --fix-zombie    # 顺手清僵尸锁（默认只报告不动手）
  python -X utf8 tools/watchdog.py --stale-min 90 --append-alert

退出码：0 健康 / 3 发现异常（3 = 有 8 不进 0，便于计划任务/CI 区分）
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
LOCK = os.path.join(DATA, "run.lock")
HB = os.path.join(DATA, "run_heartbeat.json")
LEDGER = os.path.join(DATA, "last_run.json")
ALERTS = os.path.join(DATA, "alerts.log")

DEFAULT_STALE_MIN = 90.0
ROUND_TYPICAL_MIN = 45.0        # 一轮的典型耗时（近 30 轮均值约 42 分钟）
ROUND_INTERVAL_MIN = 180.0      # 调度器每 3 小时一次


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def pid_alive(pid) -> bool:
    """Windows 安全探活。绝不能用 os.kill(pid, 0)——Windows 语义是 TerminateProcess。"""
    try:
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, int(pid))
        if not h:
            return False
        try:
            code = ctypes.c_ulong()
            return bool(k32.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == 259
        finally:
            k32.CloseHandle(h)
    except Exception:
        return False


def _iso_to_epoch(iso: str | None) -> float | None:
    if not iso:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return time.mktime(time.strptime(iso[:19], fmt)) - time.timezone
        except Exception:
            continue
    return None


def check(stale_min: float = DEFAULT_STALE_MIN, now: float | None = None) -> dict:
    """返回体检结论（纯只读，不改任何文件）。"""
    now = time.time() if now is None else now
    lock = _read_json(LOCK) if os.path.exists(LOCK) else None
    hb = _read_json(HB) if os.path.exists(HB) else None
    ledger = _read_json(LEDGER) or {}

    problems: list[dict] = []
    notes: list[str] = []
    round_running = False

    # ── 1) 锁与进程 ──
    lock_pid = (lock or {}).get("pid")
    lock_alive = bool(lock_pid) and pid_alive(lock_pid)
    if os.path.exists(LOCK):
        if lock_alive:
            round_running = True
        else:
            problems.append({
                "kind": "zombie_lock",
                "severity": "high",
                "pid": lock_pid,
                "at": (lock or {}).get("at"),
                "summary": "锁文件还在，但进程 %s 已经不存在" % lock_pid,
                "effect": "之后每一轮都会打印「已有 run.py all 在跑」然后直接退出，数据会一直停住",
                "fix": "删掉 data/run.lock（--fix-zombie 可自动处理）",
            })

    # ── 2) 心跳 / 卡死 ──
    hb_age_min = None
    if hb:
        ep = hb.get("epoch") or _iso_to_epoch(hb.get("updated_at"))
        if ep:
            hb_age_min = round((now - float(ep)) / 60.0, 1)
        if round_running and hb.get("pid") and lock_pid and int(hb["pid"]) != int(lock_pid):
            notes.append("心跳 pid=%s 与锁 pid=%s 不一致（可能刚换轮）" % (hb.get("pid"), lock_pid))
        if hb_age_min is not None and hb_age_min > stale_min:
            problems.append({
                "kind": "stalled",
                "severity": "high",
                "age_min": hb_age_min,
                "step": hb.get("step"),
                "airport": hb.get("airport"),
                "pid": hb.get("pid"),
                "summary": "心跳停在 %.0f 分钟前（阈值 %.0f）：step=%s airport=%s"
                           % (hb_age_min, stale_min, hb.get("step"), hb.get("airport")),
                "effect": "进程可能挂死或被系统挂起，本轮不会自己结束",
                "fix": "查 pid %s 是否还在；确认卡住就 taskkill 掉并删锁重跑" % hb.get("pid"),
            })
    elif round_running:
        started = _iso_to_epoch(ledger.get("started_at"))
        if started:
            age = (now - started) / 60.0
            hb_age_min = round(age, 1)
            if age > stale_min:
                problems.append({
                    "kind": "stalled_no_heartbeat",
                    "severity": "medium",
                    "age_min": round(age, 1),
                    "summary": "锁活着但没有任何心跳文件，last_run 起于 %.0f 分钟前（旧版 run.py 无心跳）" % age,
                    "effect": "无法判断卡在哪一步",
                    "fix": "升级到带心跳的 run.py 后重跑一轮即可恢复可见性",
                })

    # ── 3) 未收尾 ──
    if not round_running and (ledger.get("status") == "running"):
        started = _iso_to_epoch(ledger.get("started_at"))
        age = ((now - started) / 60.0) if started else None
        problems.append({
            "kind": "unfinished_ledger",
            "severity": "medium",
            "age_min": round(age, 1) if age else None,
            "summary": "last_run.json 仍是 status=running，但没有锁也没有进程（进程被硬杀，没走收尾）"
                       + ("，起于 %.0f 分钟前" % age if age else ""),
            "effect": "面板/总账会把「最后一轮」当成还没结束",
            "fix": "下一轮正常跑完会自动覆盖；期间看这个告警别当真",
        })

    # ── 4) 太久没成功过（数据陈旧） ──
    ended = _iso_to_epoch(ledger.get("ended_at"))
    if ended:
        since = (now - ended) / 60.0
        if since > ROUND_INTERVAL_MIN * 1.5:
            problems.append({
                "kind": "no_recent_success",
                "severity": "medium",
                "age_min": round(since, 1),
                "summary": "距上一次成功收尾已 %.0f 分钟（调度间隔 180 分钟）" % since,
                "effect": "数据在变陈旧，可能有多轮被跳过或失败",
                "fix": "查 run.log / run_manual.log 尾部；必要时手动补跑一轮",
            })
    elif ledger.get("status") is None:
        problems.append({
            "kind": "no_ledger",
            "severity": "low",
            "summary": "没有 last_run.json（从没完整跑过一轮，或台账被删）",
            "effect": "无从判断健康状况",
            "fix": "跑一轮 run.py all 生成台账",
        })

    healthy = not any(p["severity"] in ("high", "medium") for p in problems)
    return {
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "healthy": healthy,
        "round_running": round_running,
        "lock_pid": lock_pid,
        "heartbeat_age_min": hb_age_min,
        "heartbeat_step": (hb or {}).get("step"),
        "heartbeat_airport": (hb or {}).get("airport"),
        "heartbeat_progress": (
            "%s/%s" % ((hb or {}).get("done"), (hb or {}).get("total"))
            if hb and hb.get("done") is not None else None
        ),
        "last_run": {
            "status": ledger.get("status"),
            "started_at": ledger.get("started_at"),
            "ended_at": ledger.get("ended_at"),
        },
        "stale_min": stale_min,
        "typical_round_min": ROUND_TYPICAL_MIN,
        "problems": problems,
        "notes": notes,
    }


def append_alert(result: dict) -> None:
    """异常时往 data/alerts.log 追加一条（和既有告警同一个文件，面板/告警流能看到）。"""
    if result["healthy"]:
        return
    kinds = ", ".join(p["kind"] for p in result["problems"])
    block = (
        "===== %s | watchdog =====\n" % result["checked_at"]
        + "看门狗发现 %d 项异常：%s\n" % (len(result["problems"]), kinds)
        + "".join("  [%s] %s\n" % (p["kind"], p["summary"]) for p in result["problems"])
    )
    try:
        with open(ALERTS, "a", encoding="utf-8") as f:
            f.write(block)
    except Exception as e:
        print("[alerts.log 写入失败] %s" % e, file=sys.stderr)


def fix_zombie(result: dict) -> bool:
    """只清「进程确实已死」的锁，不碰活着的轮次。"""
    if not any(p["kind"] == "zombie_lock" for p in result["problems"]):
        return False
    pid = result.get("lock_pid")
    if pid and pid_alive(pid):
        print("[拒绝] pid %s 还活着，不动锁" % pid)
        return False
    try:
        os.remove(LOCK)
        print("[已清理] 僵尸锁 data/run.lock（pid=%s 已不存在）" % pid)
        return True
    except Exception as e:
        print("[清理失败] %s" % e)
        return False


def render(result: dict) -> str:
    lines = []
    head = "健康" if result["healthy"] else "异常"
    lines.append("看门狗 · %s · %s" % (result["checked_at"], head))
    lines.append("  轮次在跑: %s" % ("是" if result["round_running"] else "否"))
    if result["heartbeat_age_min"] is not None:
        lines.append("  心跳: %.1f 分钟前 · step=%s · %s%s" % (
            result["heartbeat_age_min"], result["heartbeat_step"],
            result["heartbeat_progress"] or "-",
            (" · 当前 %s" % result["heartbeat_airport"]) if result["heartbeat_airport"] else "",
        ))
    else:
        lines.append("  心跳: 无")
    lr = result["last_run"]
    lines.append("  上一轮: status=%s · 起 %s · 止 %s" % (lr["status"], lr["started_at"], lr["ended_at"]))
    if result["problems"]:
        lines.append("")
        for p in result["problems"]:
            lines.append("  [%s·%s] %s" % (p["severity"], p["kind"], p["summary"]))
            if p.get("effect"):
                lines.append("      后果: %s" % p["effect"])
            if p.get("fix"):
                lines.append("      处理: %s" % p["fix"])
    for n in result["notes"]:
        lines.append("  注: %s" % n)
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="机场监控看门狗：僵尸锁 / 卡死 / 未收尾")
    ap.add_argument("--stale-min", type=float, default=DEFAULT_STALE_MIN, help="心跳多久没更新算卡死（默认 90 分钟）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--fix-zombie", action="store_true", help="顺手清掉进程已死的僵尸锁")
    ap.add_argument("--append-alert", action="store_true", help="异常时追加一条到 data/alerts.log")
    args = ap.parse_args(argv)

    result = check(args.stale_min)
    if args.fix_zombie:
        if fix_zombie(result):
            result = check(args.stale_min)   # 清完再体检一次
    if args.append_alert:
        append_alert(result)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(render(result))
    return 0 if result["healthy"] else 3


if __name__ == "__main__":
    sys.exit(main())
