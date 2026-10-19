"""面板触发的单机场/全量采集执行器（airmon-sidebar 插件专用）。

用法：
    python -m airmon.panel_refresh <slug>[,<slug2>...]   # 指定机场（逗号分隔）
    python -m airmon.panel_refresh --all                 # 全部订阅型机场

行为：
- 订阅型机场：credentials.yaml 有账号 → run.py pull --airport <slug>；
  否则 airports.yaml direct 型 → run.py collect --airport <slug>。
- 客户端型机场跳过（内存扫描需管理员+GUI 自动化，不适合面板一键触发）。
- 每个机场独立子进程，超时 330s 强杀；进度与结果实时追加到
  data/panel_refresh_state.json（插件 /refresh-status 读这个文件）。
- 本模块绝不打印/落盘任何订阅 token；run.py 子进程 stdout 只保留末尾
  摘要行（含「节点」计数的那行），写进 state.tail。
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
from datetime import datetime

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_PATH = os.path.join(_HERE, "data", "panel_refresh_state.json")
RUN_PY = os.path.join(_HERE, "run.py")
PER_AIRPORT_TIMEOUT = 330  # 与 run.py pull 单机场 300s 上限对齐 + 余量


def _load_yaml(path: str):
    import yaml
    with io.open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _registry() -> dict:
    """slug -> {kind: 'cred'|'direct'|'client', note}"""
    out = {}
    ap = _load_yaml(os.path.join(_HERE, "airports.yaml"))
    for a in (ap.get("airports") or []):
        if not a.get("name"):
            continue
        out[a["name"]] = {"kind": str(a.get("type") or "direct"),
                          "enabled": bool(a.get("enabled", True))}
    cr = _load_yaml(os.path.join(_HERE, "credentials.yaml"))
    for slug in (cr.get("accounts") or {}):
        out.setdefault(slug, {"kind": "direct", "enabled": True})
        if out[slug]["kind"] in ("direct", "sub"):
            out[slug]["kind"] = "cred"  # 有账号走 pull（登录取订阅）
    return out


def _read_state() -> dict:
    try:
        with io.open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_state(st: dict) -> None:
    tmp = STATE_PATH + ".tmp"
    with io.open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=1)
    os.replace(tmp, STATE_PATH)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _tail(text: str, limit: int = 400) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    keep = [ln for ln in lines if ("节点" in ln or "命中" in ln or "失败" in ln
                                   or "超时" in ln or "Error" in ln or "错误" in ln)]
    tail = "\n".join(keep[-4:] or lines[-2:])
    return tail[:limit]


def run_targets(targets: list[str]) -> None:
    reg = _registry()
    st = _read_state()
    st["running"] = True
    st["pid"] = os.getpid()
    st["started_at"] = _now()
    st["jobs"] = st.get("jobs") if isinstance(st.get("jobs"), list) else []
    st["jobs"] = [j for j in st["jobs"] if j.get("slug") in targets] if targets else []
    _write_state(st)

    for i, slug in enumerate(targets, 1):
        info = reg.get(slug)
        job = {"slug": slug, "state": "running", "started": _now(),
               "cmd": "", "exit": None, "tail": "", "ended": None}
        if not info or not info.get("enabled") and info and info.get("kind") != "cred":
            # 未启用且无凭证 → 跳过（credentials 型即使停用也允许拉）
            job.update(state="skipped", tail="注册表未启用或未知机场",
                       ended=_now())
        elif info["kind"] in ("client", "persistent", "memory"):
            job.update(state="skipped",
                       tail="客户端型机场：内存扫描需管理员权限，请走 run.py scan 流程",
                       ended=_now())
        elif info["kind"] == "cred":
            job["cmd"] = f"run.py pull --airport {slug}"
        else:
            job["cmd"] = f"run.py collect --airport {slug}"

        if job["state"] == "running":
            argv = [sys.executable, RUN_PY] + job["cmd"].split()[1:]
            try:
                p = subprocess.run(argv, cwd=_HERE, capture_output=True,
                                   text=True, encoding="utf-8", errors="replace",
                                   timeout=PER_AIRPORT_TIMEOUT)
                job["exit"] = p.returncode
                job["tail"] = _tail((p.stdout or "") + "\n" + (p.stderr or ""))
                job["state"] = "ok" if p.returncode == 0 else "fail"
            except subprocess.TimeoutExpired:
                job["state"] = "fail"
                job["tail"] = f"超时（>{PER_AIRPORT_TIMEOUT}s）"
            except Exception as e:  # noqa: BLE001
                job["state"] = "fail"
                job["tail"] = str(e)[:200]
        job["ended"] = _now()
        st = _read_state()
        st["jobs"] = [j for j in st.get("jobs", []) if j.get("slug") != slug]
        st["jobs"].append(job)
        st["progress"] = f"{i}/{len(targets)}"
        _write_state(st)

    st = _read_state()
    st["running"] = False
    st["finished_at"] = _now()
    _write_state(st)


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 10
    if argv[0] == "--all":
        reg = _registry()
        targets = [s for s, v in reg.items()
                   if v.get("enabled") and v["kind"] in ("cred", "direct")]
        targets.sort()
    else:
        targets = [s.strip() for s in argv[0].split(",") if s.strip()]
    if not targets:
        print("没有可拉取的机场")
        return 11
    run_targets(targets)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
