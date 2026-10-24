"""作战室预览的本地小后端：静态页 + 机场详情 + 「获取节点」真实拉取。

    python -X utf8 tools/panel_preview_server.py [--port 57010] [--no-browser]

提供：
  GET  /                      -> app/index.html
  GET  /api/status            -> 本轮采集状态（data/last_run.json）
  GET  /api/airport/<slug>    -> 机场详情（面板/订阅/客户端/节点数）；订阅地址默认打码
  GET  /api/airport/<slug>?reveal=1 -> 订阅地址全文（仅本机访问用）
  POST /api/fetch/<slug>      -> 真跑 `run.py pull --airport <slug>`，返回任务状态
  GET  /api/fetch/<slug>      -> 该任务状态 + 已脱敏的日志尾巴
  POST /api/sub               -> 改某家的订阅地址，直接写回 credentials.yaml（先备份）

几条硬规则：
  * 只绑 127.0.0.1：这是本机工具，不对外。
  * 同一时刻只允许一个拉取任务；data/run.lock 存在（定时轮在跑）时直接拒绝，避免抢写快照。
  * 日志一律先脱敏再留存/回传：订阅 URL 带 token，run.py -v 会把它打印出来。
"""

from __future__ import annotations

import argparse
import datetime
import io
import json
import re
import os
import re
import subprocess
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "docs" / "09-新界面-preview" / "app"
DATA = ROOT / "data"

# 日志脱敏：先抹整条 URL，再保底拦凭据形状
SCRUB_URL = re.compile(r"https?://\S+")
SCRUB_KEYS = re.compile(r"(?i)(token|password|passwd|uuid|aead_key|auth_token|psk)\s*[=:]\s*\S+")

_jobs: dict[str, dict] = {}
_job_lock = threading.Lock()


# ---------------------------------------------------------------- 数据读取
def _load_yaml(name: str) -> dict:
    try:
        import yaml

        with io.open(ROOT / name, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _load_json(path: Path, default):
    try:
        with io.open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _mask_url(url: str) -> str:
    """保留能认出是哪条链接的部分，凭据只留头尾。

    有些机场把 token 直接做成主机名首段（如 <token>.yuji.homes），
    那种情况下光打码 query 等于没打码，必须把首段也遮掉。
    """
    if not url:
        return ""
    u = urlparse(url)
    host = u.netloc or ""
    if not u.query and u.path in ("", "/") and "." in host:
        head, _, rest = host.partition(".")
        if len(head) >= 8:
            host = (head[:4] + "…" + head[-2:]) + "." + rest
            return "%s://%s" % (u.scheme, host)
    # 路径里也会藏 token（v2board 系 /link/<token>、/api/v1/client/subscribe?token= 之外的形态）
    segs = []
    for seg in u.path.split("/"):
        if len(seg) >= 12 and re.fullmatch(r"[A-Za-z0-9_\-]+", seg):
            segs.append(seg[:4] + "…" + seg[-4:])
        else:
            segs.append(seg)
    path = "/".join(segs)

    q = parse_qs(u.query)
    masked_q = []
    for k, v in q.items():
        val = v[-1] if v else ""
        if k.lower() in ("token", "key", "auth", "sign"):
            shown = val[:4] + "…" + val[-4:] if len(val) > 10 else "…"
            masked_q.append("%s=%s" % (k, shown))
        else:
            masked_q.append("%s=%s" % (k, val))
    query = ("?" + "&".join(masked_q)) if masked_q else ""
    return "%s://%s%s%s" % (u.scheme, host, path, query)


def airport_detail(slug: str, reveal: bool = False) -> dict:
    creds = _load_yaml("credentials.yaml")
    reg = _load_yaml("airports.yaml")
    accounts = (creds.get("accounts") or {}) if isinstance(creds, dict) else {}
    entries = {}
    for e in (reg.get("airports") or []) if isinstance(reg, dict) else []:
        if isinstance(e, dict) and e.get("name"):
            entries[e["name"]] = e

    acc = accounts.get(slug) or {}
    ent = entries.get(slug) or {}
    sub_url = acc.get("sub_url") or ""
    panel = acc.get("panel") or ent.get("panel") or ""
    core = ""
    if isinstance(ent.get("client"), dict):
        core = ent["client"].get("core_process") or ""

    health = _load_json(DATA / "sub_health.json", {}).get(slug) or {}
    ps = (_load_json(DATA / "panel_state.json", {}) or {}).get(slug) or {}
    idx = _load_json(ROOT / "nodes" / "index.json", {})
    row = next((r for r in (idx.get("airports") or []) if r.get("slug") == slug), {}) or {}
    versions = _load_json(DATA / "client_versions.json", {})
    ver = (versions.get(slug) if isinstance(versions, dict) else None) or {}

    return {
        "slug": slug,
        "name": ent.get("display") or slug,
        "type": ent.get("type") or ("client" if core else "subscription"),
        "core": core,
        "panel": panel,
        "panel_host": urlparse(panel).netloc if panel else "",
        "sub_masked": _mask_url(sub_url),
        "sub_full": sub_url if reveal else None,
        "sub_host": urlparse(sub_url).netloc if sub_url else "",
        "sub_present": bool(sub_url),
        # 状态/节点数与卡片同源（gen_panel_data 产出的 panel_state.json），
        # 不再用 sub_health.json 里上一次诊断的旧值 —— 否则抽屉会说「A · 快照 153」
        # 而卡片说「62」，两处对不上。
        "state": ps.get("state") or health.get("state") or "",
        "reason": ps.get("reason") or health.get("reason") or "",
        "action": ps.get("action") or health.get("action") or "",
        "nodes": ps.get("nodes") if ps else row.get("nodes"),
        "exported": ps.get("exported") if ps else row.get("exported"),
        "frag": ps.get("frag") or 0,
        "snap_total": ps.get("snap_total") or row.get("nodes") or 0,
        "client": ver.get("name") or core,
        "client_local": ver.get("local") or "",
        "client_latest": ver.get("latest") or "",
        "status": ver.get("status") or "",
        "last_ok": latest_ok_local(slug),
    }


def latest_ok_local(slug: str, limit: int = 8) -> str:
    """最近一次真拿到节点的时间（扫该机场最近几份快照，别用诊断文件的旧值）。"""
    d = DATA / slug
    try:
        names = sorted((n for n in os.listdir(d) if re.match(r"\d{8}T\d{6}Z", n)), reverse=True)
    except OSError:
        return ""
    for name in names[:limit]:
        try:
            with io.open(d / name, encoding="utf-8") as fh:
                snap = json.load(fh)
        except Exception:
            continue
        if not (snap.get("nodes") or []):
            continue
        try:
            t = datetime.datetime.strptime(name[:16], "%Y%m%dT%H%M%SZ").replace(
                tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
        return t.astimezone().strftime("%Y-%m-%d %H:%M")
    return ""


def round_status() -> dict:
    d = _load_json(DATA / "last_run.json", {})
    return {
        "status": d.get("status"),
        "started_at": d.get("started_at"),
        "ended_at": d.get("ended_at"),
        "running": _run_lock_holder() is not None,
        "pull_ok": d.get("pull_ok"),
        "pull_fail": d.get("pull_fail"),
        "nodes_total": d.get("nodes_total"),
    }


# ---------------------------------------------------------------- 拉取任务
def _scrub(line: str) -> str:
    line = SCRUB_URL.sub("<订阅地址已隐藏>", line)
    line = SCRUB_KEYS.sub(lambda m: m.group(1) + "=<已隐藏>", line)
    return line.rstrip()


def _regen_panel_data(job: dict) -> None:
    """拉取成功后重跑数据生成器，让卡片/表格跟上新快照（best-effort）。"""
    try:
        with _job_lock:
            job["regen"] = "running"
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        # ① 先重算节点索引：scan-memory / pull 只写快照，nodes/index.json 由 nodeset 生成，
        #    不跑这一步，面板会拿旧索引（表现为「明明扫到 95 个，卡片还是 62」）。
        r0 = subprocess.run(
            [sys.executable, "-X", "utf8", "-m", "airmon.nodeset"],
            cwd=str(ROOT), env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=600,
        )
        # ② 再生成面板数据
        r = subprocess.run(
            [sys.executable, "-X", "utf8", "tools/gen_panel_data.py"],
            cwd=str(ROOT), env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=300,
        )
        ok = r.returncode == 0 and "LEAK-CHECK CLEAN" in (r.stdout or "")
        if r0.returncode != 0:
            with _job_lock:
                job["tail"].append("节点索引重算失败：" + _scrub((r0.stderr or r0.stdout or "")[-200:]))
        with _job_lock:
            job["regen"] = "ok" if ok else "failed"
            if not ok:
                job["tail"].append("面板数据重生成失败：" + _scrub((r.stderr or r.stdout or "")[-300:]))
    except Exception as e:  # noqa: BLE001
        with _job_lock:
            job["regen"] = "failed"
            job["tail"].append("面板数据重生成异常：" + _scrub(str(e)))


def _fetch_cmd(slug: str) -> tuple[list[str], str]:
    """选对命令：客户端型机场没有订阅地址，`pull` 必然 0 节点，要用 scan-memory。

    qingyunti/hhy/dovex 这类的节点只活在客户端内核内存里，
    订阅那一套（pull）对它们无效 —— 之前按钮一律跑 pull，所以「运行几次都是 0」。
    """
    creds = _load_yaml("credentials.yaml")
    reg = _load_yaml("airports.yaml")
    acc = ((creds.get("accounts") or {}) if isinstance(creds, dict) else {}).get(slug) or {}
    ent = {}
    for e in (reg.get("airports") or []) if isinstance(reg, dict) else []:
        if isinstance(e, dict) and e.get("name") == slug:
            ent = e
            break
    core = ""
    if isinstance(ent.get("client"), dict):
        core = ent["client"].get("core_process") or ""
    is_client = (acc.get("type") == "client") or bool(core) or not acc.get("sub_url")
    if is_client and not acc.get("sub_url"):
        cmd = [sys.executable, "-X", "utf8", "run.py", "scan-memory", "--airport", slug]
        return cmd, "scan-memory" + ((" · " + core) if core else "")
    return [sys.executable, "-X", "utf8", "run.py", "pull", "--airport", slug, "-v"], "pull"


def _is_admin() -> bool:
    """当前进程有没有管理员权限（读客户端内核内存需要）。"""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_fetch_elevated(slug: str, job: dict, cmd: list[str]) -> None:
    """以管理员权限跑一次扫描：弹 UAC → 用户点「是」→ 扫描在提权进程里跑。

    为什么不能直接 Popen：读客户端内核内存要 PROCESS_VM_READ，
    普通权限会拿到 error 5。所以这里借 Windows 的 UAC 提权，
    把命令写成一个 .bat 由 PowerShell `Start-Process -Verb RunAs` 拉起，
    stdout 重定向到文件（RunAs 不能直接接管道），再逐行读回来。
    """
    tmp = ROOT / ".tmp_scan"
    tmp.mkdir(exist_ok=True)
    log = tmp / (slug + ".log")
    bat = tmp / (slug + ".bat")
    if log.exists():
        try:
            log.unlink()
        except OSError:
            pass
    # 路径全是 ASCII，.bat 用 GBK 写更稳妥；内容里不要出现中文
    body = (
        "@echo off\r\n"
        'cd /d "%s"\r\n'
        '"%s" -X utf8 run.py scan-memory --airport %s > "%s" 2>&1\r\n'
        % (ROOT, sys.executable, slug, log)
    )
    bat.write_bytes(body.encode("gbk", "replace"))

    with _job_lock:
        job["tail"].append("需要管理员权限读取客户端内存，已请求提权 —— 请在弹出的 UAC 窗口点「是」\n")
        job["elevated"] = True
    ps = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command",
        'Start-Process -FilePath "%s" -Verb RunAs -Wait -WindowStyle Hidden' % bat,
    ]
    proc = subprocess.Popen(ps, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    out, _ = proc.communicate(timeout=600)
    for line in (out or "").splitlines():
        if line.strip():
            with _job_lock:
                job["tail"].append(_scrub(line + "\n"))
    if log.exists():
        for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
            with _job_lock:
                job["tail"].append(_scrub(line + "\n"))
                job["tail"] = job["tail"][-60:]
                job["lines"] += 1
    ok = log.exists() and "0节点" not in log.read_text(encoding="utf-8", errors="replace")
    with _job_lock:
        job["state"] = "done" if ok else "failed"
        job["exit"] = 0 if ok else 1
    if ok:
        _regen_panel_data(job)


def _run_fetch(slug: str) -> None:
    job = _jobs[slug]
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["HTTP_PROXY"] = "http://[::1]:7890"
    env["HTTPS_PROXY"] = "http://[::1]:7890"
    cmd, mode = _fetch_cmd(slug)
    with _job_lock:
        job["mode"] = mode
    if mode.startswith("scan-memory") and not _is_admin():
        # 客户端型 + 没有管理员权限：走 UAC 提权，用户点一下「是」即可
        try:
            _run_fetch_elevated(slug, job, cmd)
        except Exception as e:  # noqa: BLE001
            with _job_lock:
                job["state"] = "failed"
                job["exit"] = -1
                job["tail"].append("提权失败：" + _scrub(str(e)) + "\n")
        finally:
            with _job_lock:
                job["ended_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(ROOT), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
        for line in proc.stdout:
            with _job_lock:
                job["tail"].append(_scrub(line))
                job["tail"] = job["tail"][-60:]
                job["lines"] += 1
        proc.wait(timeout=600)
        with _job_lock:
            job["state"] = "done" if proc.returncode == 0 else "failed"
            job["exit"] = proc.returncode
        if proc.returncode == 0:
            _regen_panel_data(job)
    except Exception as e:  # noqa: BLE001
        with _job_lock:
            job["state"] = "failed"
            job["exit"] = -1
            job["tail"].append("异常：" + _scrub(str(e)))
    finally:
        with _job_lock:
            job["ended_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _pid_alive(pid) -> bool:
    """Windows 安全探活（绝不用 os.kill(pid,0)：Windows 语义是 TerminateProcess）。"""
    try:
        import ctypes
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


def _run_lock_holder():
    """返回仍在跑的轮次信息；僵尸锁（进程已死）会被就地清掉并返回 None。"""
    lp = DATA / "run.lock"
    if not lp.exists():
        return None
    info = {}
    try:
        info = json.loads(lp.read_text(encoding="utf-8"))
    except Exception:
        info = {}
    pid = info.get("pid")
    if pid and _pid_alive(pid):
        return info
    try:
        lp.unlink()
        print("[锁] 清理僵尸锁（pid=%s 已不在）" % pid, flush=True)
    except Exception as e:
        print("[锁] 僵尸锁清理失败: %s" % e, flush=True)
    return None


def start_fetch(slug: str) -> dict:
    if not re.match(r"^[a-z0-9._-]{2,40}$", slug or ""):
        return {"ok": False, "error": "slug 不合法"}
    holder = _run_lock_holder()
    if holder:
        return {"ok": False, "error": "定时轮正在跑（pid=%s，起于 %s），等这轮结束再点" % (holder.get("pid"), holder.get("at"))}
    with _job_lock:
        cur = _jobs.get(slug)
        if cur and cur["state"] == "running":
            return {"ok": False, "error": "这家正在拉取中"}
        if any(j["state"] == "running" for j in _jobs.values()):
            return {"ok": False, "error": "另一个机场正在拉取，等它跑完"}
        _jobs[slug] = {
            "slug": slug, "state": "running", "exit": None, "lines": 0, "tail": [],
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ended_at": None,
            "regen": "",
        }
    threading.Thread(target=_run_fetch, args=(slug,), daemon=True).start()
    return {"ok": True, "slug": slug}


def job_status(slug: str) -> dict:
    with _job_lock:
        job = _jobs.get(slug)
        if not job:
            return {"state": "idle", "tail": []}
        snap = dict(job)
        snap["tail"] = list(job["tail"])
    return snap


# ---------------------------------------------------------------- 订阅地址写回
CRED = ROOT / "credentials.yaml"
BACKUP_DIR = DATA / "backup"
SUB_URL_MAX = 2048
_SLUG_RE = re.compile(r"^[a-z0-9._-]{2,40}$")


def _yaml_value(url: str) -> str:
    """能裸写就裸写（跟现有文件风格一致），否则加双引号。"""
    if url == "":
        return '""'
    if re.fullmatch(r"[A-Za-z0-9_\-./:?=&%~+@]+", url):
        return url
    return '"' + url.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _check_sub_url(url: str) -> str | None:
    if url == "":
        return None
    if len(url) > SUB_URL_MAX:
        return "链接太长（上限 %d 字符）" % SUB_URL_MAX
    if re.search(r"[\s\x00-\x1f\x7f\"']", url):
        return "链接里不能有空格、换行或引号"
    u = urlparse(url)
    if u.scheme not in ("http", "https"):
        return "只接受 http:// 或 https:// 开头的订阅链接"
    if not u.netloc:
        return "链接缺少主机名"
    return None


def _account_block(lines: list[str], slug: str):
    """返回 (块起始行, 块结束行(不含), 缩进)，找不到返回 None。"""
    pat = re.compile(r"^(\s+)%s:\s*$" % re.escape(slug))
    for i, line in enumerate(lines):
        m = pat.match(line)
        if not m:
            continue
        base = len(m.group(1))
        j = i + 1
        while j < len(lines):
            ln = lines[j]
            if not ln.strip():
                j += 1
                continue
            ind = len(ln) - len(ln.lstrip(" "))
            if ind <= base:
                break
            j += 1
        return i, j, base
    return None


def save_sub_url(slug: str, url: str) -> dict:
    """把某家的 sub_url 写回 credentials.yaml：文本级替换单行，先备份、写完回读校验。"""
    slug = (slug or "").strip()
    url = (url or "").strip()
    if not _SLUG_RE.match(slug):
        return {"ok": False, "error": "slug 不合法"}
    bad = _check_sub_url(url)
    if bad:
        return {"ok": False, "error": bad}
    if not CRED.exists():
        return {"ok": False, "error": "找不到 credentials.yaml"}

    text = io.open(CRED, encoding="utf-8").read()
    lines = text.splitlines()
    found = _account_block(lines, slug)
    if not found:
        return {"ok": False, "error": "credentials.yaml 里没有这家（%s）的账号块" % slug}
    start, end, base = found

    field_ind = base + 2
    field_pat = re.compile(r"^(\s*)sub_url:\s*(.*)$")
    hit = None
    for k in range(start + 1, end):
        m = field_pat.match(lines[k])
        if m:
            hit = k
            break
    new_line = " " * field_ind + "sub_url: " + _yaml_value(url)
    if hit is not None:
        old_line = lines[hit]
        if old_line == new_line:
            return {"ok": True, "masked": _mask_url(url), "unchanged": True}
        lines[hit] = new_line
    else:
        lines.insert(end, new_line)

    # 备份（只留最近 40 份）
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    bak = BACKUP_DIR / ("credentials-%s-%03d.yaml" % (stamp, int(time.time() * 1000) % 1000))
    n_dup = 0
    while bak.exists():  # 同毫秒重名时加序号，绝不覆盖已有备份
        n_dup += 1
        bak = BACKUP_DIR / ("credentials-%s-%03d-%d.yaml" % (stamp, int(time.time() * 1000) % 1000, n_dup))
    io.open(bak, "w", encoding="utf-8", newline="\n").write(text)
    olds = sorted(BACKUP_DIR.glob("credentials-*.yaml"))
    for f in olds[:-40]:
        try:
            f.unlink()
        except OSError:
            pass

    new_text = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    tmp = CRED.with_suffix(".yaml.tmp")
    io.open(tmp, "w", encoding="utf-8", newline="\n").write(new_text)
    os.replace(tmp, CRED)

    # 回读校验：YAML 能解析，且该家的值确实等于新值
    try:
        import yaml

        with io.open(CRED, encoding="utf-8") as f:
            got = ((yaml.safe_load(f) or {}).get("accounts") or {}).get(slug) or {}
        if (got.get("sub_url") or "") != url:
            io.open(CRED, "w", encoding="utf-8", newline="\n").write(text)
            return {"ok": False, "error": "写入后回读不一致，已回滚"}
    except Exception as e:  # noqa: BLE001
        io.open(CRED, "w", encoding="utf-8", newline="\n").write(text)
        return {"ok": False, "error": "写入后 YAML 解析失败，已回滚：" + str(e)[:120]}

    return {
        "ok": True,
        "slug": slug,
        "masked": _mask_url(url),
        "present": bool(url),
        "backup": str(bak.relative_to(ROOT)).replace("\\", "/"),
        "line": (hit if hit is not None else end) + 1,
    }


# ---------------------------------------------------------------- HTTP
class Handler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(APP), **kw)

    def log_message(self, fmt, *args):  # 静音，避免刷屏
        pass

    def end_headers(self):
        # 本地调试页：一律不缓存，避免改了 app.js 用户那边还是旧版
        if not self.path.startswith("/api/"):
            self.send_header("Cache-Control", "no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        super().end_headers()

    def _json(self, obj, code: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _api(self) -> bool:
        u = urlparse(self.path)
        parts = [p for p in u.path.split("/") if p]
        q = parse_qs(u.query)

        if parts[:2] == ["api", "status"]:
            self._json(round_status())
            return True

        if parts[:2] == ["api", "airport"] and len(parts) == 3:
            reveal = q.get("reveal", ["0"])[0] == "1"
            self._json(airport_detail(parts[2], reveal=reveal))
            return True

        if parts[:2] == ["api", "sub"] and self.command == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 8192:
                self._json({"ok": False, "error": "请求体为空或过大"}, 400)
                return True
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
            except Exception:
                self._json({"ok": False, "error": "请求体不是合法 JSON"}, 400)
                return True
            res = save_sub_url(payload.get("slug") or "", payload.get("sub_url") or "")
            self._json(res, 200 if res.get("ok") else 400)
            return True

        if parts[:2] == ["api", "fetch"] and len(parts) == 3:
            slug = parts[2]
            if self.command == "POST":
                self._json(start_fetch(slug))
            else:
                self._json(job_status(slug))
            return True

        return False

    def do_GET(self):
        if self._api():
            return
        if self.path.split("?")[0] in ("/", "/index.html"):
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        if self._api():
            return
        self._json({"ok": False, "error": "not found"}, 404)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=57010)
    args = ap.parse_args(argv)

    if not APP.exists():
        print("找不到页面目录：%s" % APP)
        return 1

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print("作战室预览：http://127.0.0.1:%d/index.html" % args.port)
    print("  /api/airport/<slug>      机场详情（订阅默认打码）")
    print("  POST /api/fetch/<slug>   真跑 run.py pull --airport <slug>")
    print("  POST /api/sub            改订阅地址 → 写回 credentials.yaml（先备份）")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())
