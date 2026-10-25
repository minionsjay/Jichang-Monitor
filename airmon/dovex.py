# -*- coding: utf-8 -*-
"""DOVE 客户端：离线解包 `DOVE.tauri.dat`，不启动客户端也能拿到完整节点。

DOVE 把服务端下发的整份 mihomo 配置加密存成一个文件：

    %APPDATA%\\DOVE.tauri\\DOVE.tauri.dat

格式（逆向自 dove-core.exe 的 config.parseBundle / parseBundleMetaPlain）：

    29 字节头：魔数 "MHBNDL\\x01\\x00" | ver u8=0x12 | nonce 12B | meta_len u32 | body_len u32
    meta : AES-256-GCM(key=K, nonce=头部, 无 AAD) → 4B ver + 32B bodyKey + 16B bodyIV
                                                   + 4B nameLen + name
    body : 16B bodyIV + base64( AES-256-CBC(key=bodyKey, iv=bodyIV, PKCS7) )

K 是程序内嵌常量（DOVE.exe 与 dove-core.exe 各有一份）。

## 为什么这条路径比内存扫描好

内存扫描只能捞到内核里的 `IP:端口` 碎片（配置加载后已解析成 Go 结构体，JSON 文本不再存在），
导不出可用的客户端配置。而这里解出来的是**原始 YAML**，每个节点带
type/server/port/uuid/servername/reality-opts 全字段。

## 解出的节点有两条特殊规则

1. 真实节点（58 个）的 `server` 是 `service.internal` —— 不是公网域名，只有配合
   `dialer-proxy: DOVE` 先连进入口链，服务端才会替你解析。所以**入口组必须一起带上**。
2. 入口节点是 4 个真域名 vless+reality（DOVE1..DOVE4），由 url-test 组 `DOVE` 自动择优。

因此 `to_clash_proxies()` 返回的是「58 个节点 + 4 个入口」整份列表，`dialer-proxy`
字段原样保留；导出给 mihomo 能直接跑通。

## 局限

bundle 是快照，客户端最后一次取配置的产物；不开客户端它不会自己变新。
入口域名与节点端口很稳定，旧 bundle 通常仍可用；服务端换入口/换 UUID 时需要
客户端再取一次（或用户手工更新）。
"""
from __future__ import annotations

import base64
import io
import json
import os
import struct
import time

# 程序内嵌常量（DOVE.exe / dove-core.exe 各一份）
K = b"mihomo-bundle-key-v1-32bytes-!!!"
MAGIC = b"MHBNDL\x01\x00"
VER = 0x12
HEAD_LEN = 29

DEFAULT_DIR = os.path.join(os.path.expandvars("%APPDATA%"), "DOVE.tauri")
DAT_NAME = "DOVE.tauri.dat"


class BundleError(Exception):
    """解包失败（不是 DOVE 的包 / 版本不符 / 文件被改）。"""


def dat_path(install_dir: str = "", data_dir: str = "") -> str:
    """找 bundle 文件：先看显式给的目录，再看 %APPDATA%\\DOVE.tauri。"""
    for d in (data_dir, install_dir, DEFAULT_DIR):
        if not d:
            continue
        p = os.path.join(d, DAT_NAME)
        if os.path.exists(p):
            return p
    p = os.path.join(DEFAULT_DIR, DAT_NAME)
    return p if os.path.exists(p) else ""


def decrypt(path: str):
    """解密 → (bundle 名字, YAML 文本)。四项校验，任何一项不符都抛 BundleError。"""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception as e:  # pragma: no cover
        raise BundleError("缺少 cryptography（pip install cryptography）：%s" % e)

    with io.open(path, "rb") as f:
        d = f.read()
    if len(d) < HEAD_LEN:
        raise BundleError("文件太小，不是 DOVE bundle")
    magic = d[:8]
    if magic != MAGIC:
        raise BundleError("魔数不符（不是 DOVE bundle，或者换了格式）")
    ver = d[8]
    if ver != VER:
        raise BundleError("未支持的版本 0x%02x（当前只认 0x%02x）" % (ver, VER))
    nonce = d[9:21]
    meta_len, body_len = struct.unpack_from("<II", d, 21)
    if len(d) != HEAD_LEN + meta_len + body_len:
        raise BundleError("长度字段与文件大小不符（文件被截断或改过）")

    try:
        meta = AESGCM(K).decrypt(nonce, d[HEAD_LEN:HEAD_LEN + meta_len], None)
    except Exception as e:
        raise BundleError("meta 解密失败（%s）——包里没有 GCM 可信数据" % type(e).__name__)
    if len(meta) < 56:
        raise BundleError("meta 明文过短")
    body_key = meta[4:36]
    body_iv = meta[36:52]
    name_len = struct.unpack_from("<I", meta, 52)[0]
    name = meta[56:56 + name_len].decode("utf-8", "replace")

    body = d[HEAD_LEN + meta_len:]
    if body[:16] != body_iv:
        raise BundleError("body 前缀与 meta 里的 IV 不一致（文件被改过）")
    try:
        ct = base64.b64decode(body[16:], validate=False)
    except Exception as e:
        raise BundleError("body base64 解码失败：%s" % e)
    dec = Cipher(algorithms.AES(body_key), modes.CBC(body_iv)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    pad = pt[-1] if pt else 0
    if not 1 <= pad <= 16:
        raise BundleError("PKCS7 填充异常")
    pt = pt[:-pad]
    return name, pt.decode("utf-8", "replace")


def to_clash_proxies(yaml_text: str) -> tuple[list[dict], list[dict]]:
    """YAML → (proxies 列表, proxy-groups 列表)。字段原样保留（含 dialer-proxy / reality-opts）。"""
    import yaml

    doc = yaml.safe_load(yaml_text) or {}
    proxies = [p for p in (doc.get("proxies") or []) if isinstance(p, dict)]
    groups = [g for g in (doc.get("proxy-groups") or []) if isinstance(g, dict)]
    return proxies, groups


def available(client_cfg: dict | None = None, slug: str = "") -> bool:
    """该机场是否走 DOVE 离线解包。

    **必须证明这台机场就是 DOVE**（slug / package / core_process 任一含 dove），
    不能只因为「本机存在 DOVE.tauri.dat」就把别家机场也当成 DOVE ——
    否则 quqiuquan(QQT)、letsvpn(快连) 会拿到 DOVE 的节点，数据张冠李戴。
    """
    cfg = client_cfg or {}
    pkg = (cfg.get("package") or "").strip().lower()
    core = (cfg.get("core_process") or "").strip().lower()
    s = (slug or "").strip().lower()
    if not ("dove" in pkg or "dove" in core or s in ("dovex", "dove")):
        return False
    p = dat_path(cfg.get("install_dir") or "", cfg.get("data_dir") or "")
    return bool(p) and os.path.exists(p)


def extract(slug: str, client_cfg: dict | None = None, write: bool = True) -> dict:
    """解包 → 写 data/client_nodes/<slug>.json（nodeset 会读它合并进快照）。

    返回 {ok, path, dat, bundle_name, count, protos, extracted_at, error}
    """
    cfg = client_cfg or {}
    p = dat_path(cfg.get("install_dir") or "", cfg.get("data_dir") or "")
    out = {"ok": False, "slug": slug, "dat": p, "path": "", "bundle_name": "",
           "count": 0, "protos": {}, "extracted_at": "", "error": ""}
    if not p or not os.path.exists(p):
        out["error"] = "找不到 %s（DOVE 还没取过配置）" % DAT_NAME
        return out
    try:
        name, text = decrypt(p)
        proxies, groups = to_clash_proxies(text)
    except BundleError as e:
        out["error"] = str(e)
        return out
    except Exception as e:  # noqa: BLE001
        out["error"] = "%s: %s" % (type(e).__name__, e)
        return out

    from collections import Counter
    at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = {
        "extracted_at": at,
        "slug": slug,
        "source": "dove-bundle:%s" % os.path.basename(p),
        "bundle_name": name,
        "dat_mtime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(p))),
        "nodes": proxies,
        "groups": groups,
    }
    out.update({
        "ok": True,
        "bundle_name": name,
        "count": len(proxies),
        "protos": dict(Counter((x.get("type") or "?") for x in proxies)),
        "extracted_at": at,
    })
    if write:
        d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "client_nodes")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "%s.json" % slug)
        tmp = path + ".tmp"
        with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
        out["path"] = path
    return out


if __name__ == "__main__":  # 手工排查：python -X utf8 -m airmon.dovex [dovex]
    import sys

    slug = sys.argv[1] if len(sys.argv) > 1 else "dovex"
    try:
        from .config import load_credentials
        cred = (load_credentials() or {}).get(slug) or {}
    except Exception:
        cred = {}
    cfg = cred.get("client") or {}
    r = extract(slug, cfg, write=False)
    print("dat:", r["dat"])
    print("bundle:", r["bundle_name"] or "-")
    if r["ok"]:
        print("节点:", r["count"], "| 协议:", r["protos"])
    else:
        print("失败:", r["error"])
