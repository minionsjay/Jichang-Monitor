"""airmon.quota — 套餐到期/流量采集（subscription-userinfo 响应头）。

数据来源（两级）：
1) 离线收割：data\\<slug>\\*.json 快照 meta.subscription-userinfo
   （collect.py 拉订阅时已把该响应头落盘，零网络成本）。
2) 在线补头：对「从未有 userinfo」或「数据过旧」且 credentials.yaml 有 sub_url
   的账号，发起一次 GET 只读响应头即关闭（不读 body），UA=clash.meta；
   直连失败自动走 127.0.0.1:7890 代理重试一次。

输出 data/quota.json —— 只含派生数值与时间戳，绝不含 sub_url / token / 邮箱。
用法：
    python -m airmon.quota                    # 全量：收割 + 刷新 >7 天的
    python -m airmon.quota --refresh-days 3   # 在线刷新阈值改为 3 天
    python -m airmon.quota --only applegame   # 只处理指定机场
"""

from __future__ import annotations

import argparse
import io
import json
import re
import ssl
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from airmon import snapnames as _snapnames

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
QUOTA_FILE = DATA_DIR / "quota.json"
CREDENTIALS = PROJECT_ROOT / "credentials.yaml"
SNAP_RE = _snapnames.SNAP_RE  # 新旧两种命名都认
UA = "clash.meta/1.18.0"
def _fallback_proxy():
    """直连失败时的兜底代理（自动探测，见 airmon/netcfg.py）。"""
    try:
        from .netcfg import detect
        return detect() or ""
    except Exception:  # noqa: BLE001
        return ""
GB = 1024 ** 3


def _parse_userinfo(raw):
    if not isinstance(raw, str) or "=" not in raw:
        return None
    kv = {}
    for part in raw.split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            try:
                kv[k] = float(v)
            except ValueError:
                pass
    return kv or None


def _entry_from_kv(kv: dict, source: str) -> dict:
    expire_ts = kv.get("expire") or 0
    total = kv.get("total") or 0
    used = (kv.get("upload") or 0) + (kv.get("download") or 0)
    e: dict = {"source": source}
    if expire_ts > 0:
        e["expire_ts"] = int(expire_ts)
        e["expire_date"] = datetime.fromtimestamp(expire_ts).strftime("%Y-%m-%d")
        e["days_left"] = int((expire_ts - datetime.now().timestamp()) // 86400)
    else:
        e["expire_date"] = None
        e["days_left"] = None
    e["total_gb"] = round(total / GB, 1) if total else None
    e["used_gb"] = round(used / GB, 2)
    e["unlimited"] = bool(total and total / GB >= 999998)
    e["used_pct"] = (round(used / total * 100, 1)
                     if total and not e["unlimited"] else None)
    return e


def _iter_dirs() -> list[str]:
    if not DATA_DIR.exists():
        return []
    return sorted(d.name for d in DATA_DIR.iterdir()
                  if d.is_dir() and not d.name.startswith(".")
                  and not d.name.endswith("_analysis"))


def harvest_snapshots() -> dict[str, dict]:
    """离线收割：每个机场取「最新一份带 userinfo 的快照」。"""
    out: dict[str, dict] = {}
    now = datetime.now()
    for slug in _iter_dirs():
        # 新旧命名混存，必须按真实时间取最新（否则会拿到几个月前的旧文件）
        snaps = [DATA_DIR / slug / n for n in _snapnames.names(DATA_DIR / slug, reverse=True)]
        for p in snaps:
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            kv = _parse_userinfo((data.get("meta") or {}).get("subscription-userinfo"))
            if not kv:
                continue
            e = _entry_from_kv(kv, "snapshot:" + p.stem)
            age_days = max(0, int((now - datetime.fromtimestamp(p.stat().st_mtime)).total_seconds() // 86400))
            e["age_days"] = age_days
            e["at"] = now.strftime("%Y-%m-%d %H:%M")
            out[slug] = e
            break
    return out


def _fetch_header_once(sub_url: str, timeout: float, use_proxy: bool) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers: list = [urllib.request.HTTPSHandler(context=ctx)]
    if use_proxy:
        handlers.append(urllib.request.ProxyHandler(
            {"http": _fallback_proxy(), "https": _fallback_proxy()}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(sub_url, headers={"User-Agent": UA, "Accept": "*/*"})
    with opener.open(req, timeout=timeout) as resp:
        return dict(resp.headers.items())


def fetch_live(sub_url: str, timeout: float = 15.0) -> dict:
    """只取响应头：直连失败走代理各试一次；两次都失败抛异常。"""
    last: Exception | None = None
    for use_proxy in (False, True):
        try:
            return _fetch_header_once(sub_url, timeout, use_proxy)
        except Exception as exc:  # noqa: BLE001 —— 错误只记类型，绝不带 URL
            last = exc
    raise last  # type: ignore[misc]


def _userinfo_from_headers(hdrs: dict) -> dict | None:
    for k, v in hdrs.items():
        if k.lower() == "subscription-userinfo":
            return _parse_userinfo(v)
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m airmon.quota",
        description="采集各机场套餐到期/流量（subscription-userinfo），写 data/quota.json")
    ap.add_argument("--refresh-days", type=int, default=7,
                    help="快照数据超过 N 天才在线刷新（默认 7）")
    ap.add_argument("--timeout", type=float, default=15.0, help="单请求超时秒数")
    ap.add_argument("--only", help="只处理指定机场（逗号分隔）")
    ap.add_argument("--out", default=str(QUOTA_FILE))
    args = ap.parse_args(argv)

    creds = yaml.safe_load(io.open(CREDENTIALS, encoding="utf-8"))
    accounts: dict[str, str] = {}
    for name, acc in (creds.get("accounts") or {}).items():
        sub = acc.get("sub_url") if isinstance(acc, dict) else None
        if sub:
            accounts[name] = sub

    entries = harvest_snapshots()
    if args.only:
        keep = {s.strip() for s in args.only.split(",")}
        entries = {k: v for k, v in entries.items() if k in keep}
        accounts = {k: v for k, v in accounts.items() if k in keep}

    now_s = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M")
    to_fetch = []
    for slug, sub in accounts.items():
        e = entries.get(slug)
        if e is None or (e.get("age_days") or 0) > args.refresh_days:
            to_fetch.append(slug)

    def _do(slug: str):
        try:
            hdrs = fetch_live(accounts[slug], args.timeout)
            kv = _userinfo_from_headers(hdrs)
            if kv:
                return slug, _entry_from_kv(kv, "live_header"), None
            return slug, None, "no_header"
        except Exception as exc:  # noqa: BLE001
            return slug, None, type(exc).__name__

    notes: dict[str, str] = {}
    if to_fetch:
        with ThreadPoolExecutor(max_workers=6) as pool:
            for slug, entry, err in pool.map(_do, to_fetch):
                if entry:
                    entry["at"] = now_s
                    entries[slug] = entry
                elif err:
                    notes[slug] = err

    payload = {
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "refresh_days": args.refresh_days,
        "airports": entries,
        "notes": notes,
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=1),
                        encoding="utf-8")

    # 控制台摘要（脱敏：只有 slug/数值/日期）
    print("机场 %d 个有套餐数据 | 在线刷新 %d 个 | 失败 %d 个 → %s"
          % (len(entries), len(to_fetch), len(notes), out_path))
    for slug in sorted(entries):
        e = entries[slug]
        exp = e.get("expire_date") or "无到期日"
        dl = e.get("days_left")
        dls = "" if dl is None else ("（剩 %d 天）" % dl if dl >= 0 else "（已过期）")
        if e.get("unlimited"):
            flow = "不限量"
        elif e.get("total_gb") is not None:
            rem = max(0.0, (e["total_gb"] or 0) - (e["used_gb"] or 0))
            flow = "已用 %.1f/%.1fGB 剩 %.1fGB" % (e["used_gb"], e["total_gb"], rem)
        else:
            flow = "已用 %.1fGB" % e["used_gb"]
        print("  %-16s %s%s %s [%s]" % (slug, exp, dls, flow, e["source"]))
    for slug, err in sorted(notes.items()):
        print("  %-16s 刷新失败：%s" % (slug, err))
    return 0


if __name__ == "__main__":
    sys.exit(main())
