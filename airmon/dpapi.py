"""DPAPI 订阅缓存解密采集器 — Velochron 等设备认证锁订阅的客户端。

背景（2026-09-16 实测）：
  Velochron 的 v2board 订阅接口被服务端**硬件设备认证**(device/attest)锁死：
  - /api/v1/user/server/fetch 只返回节点元数据(名字/倍率)，无 server/port
  - subscribe_url 对非认证客户端 HTTP 404
  但客户端自己刷新成功后，会把**完整节点配置**(aero_v2, 含 psk/aead_key/
  transport 等)缓存到：

    %LOCALAPPDATA%\\Velochron\\secure_store\\secure_sub_config_active_a_v2.bin

  该文件仅用 Windows DPAPI (CurrentUser) 加密 —— 同一 Windows 用户可直接
  CryptUnprotectData 解密得到明文 JSON 节点数组(33 节点实测全量)。

  优势：无需启动客户端、无需管理员权限、无需内存扫描。

用法（run.py 在 client 配置含 dpapi_file 时自动调用）：
    from airmon.dpapi import collect_dpapi
    snap = collect_dpapi("velochron", client_cfg, detector)
"""
from __future__ import annotations

import ctypes
import json
import os
import subprocess
import time
from datetime import datetime, timezone

from .models import Node, Snapshot
from . import store


# ---------------------------------------------------------------------------
# DPAPI
# ---------------------------------------------------------------------------

def dpapi_unprotect(data: bytes) -> bytes:
    """CryptUnprotectData（CurrentUser 域）。仅限同一 Windows 用户。"""
    import ctypes.wintypes as wt

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    blob_in = DATA_BLOB()
    blob_in.cbData = len(data)
    blob_in.pbData = ctypes.cast(ctypes.create_string_buffer(data, len(data)),
                                 ctypes.POINTER(ctypes.c_char))
    blob_out = DATA_BLOB()

    crypt32 = ctypes.windll.crypt32
    ok = crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None,
                                    None, 0, ctypes.byref(blob_out))
    if not ok:
        raise OSError(f"CryptUnprotectData failed: {ctypes.GetLastError()}")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


# ---------------------------------------------------------------------------
# Velochron aero_v2 节点
# ---------------------------------------------------------------------------

# 需要保留进 Node.raw 的字段（复现连接所需）
_AERO_FIELDS = ("type", "aero_v2_edge_psk", "aero_v2_edge_key_version",
                "aero_v2_aead_key", "aero_v2_transport", "aero_v2_carrier_sni",
                "aero_v2_ws_path", "aero_v2_device_identity_mode",
                "aero_v2_carrier_insecure_skip_verify", "password", "auth_id",
                "node_id", "udp_port", "mtu", "iplc_mode", "udp_lane_mode",
                "resume_ticket", "admin_log_host")


def _default_sub_file() -> str:
    local = os.environ.get("LOCALAPPDATA", "")
    return os.path.join(local, "Velochron", "secure_store",
                        "secure_sub_config_active_a_v2.bin")


def _file_age_hours(path: str) -> float:
    mtime = os.path.getmtime(path)
    return (datetime.now(timezone.utc).timestamp() - mtime) / 3600


def _launch_client_refresh(install_dir: str, sub_file: str,
                           wait_sec: int = 150) -> bool:
    """缓存过旧时启动一次 GUI 客户端触发订阅刷新，等文件更新。"""
    exe = os.path.join(install_dir, "Velochron.exe")
    if not os.path.exists(exe):
        return False
    before = os.path.getmtime(sub_file)
    try:
        subprocess.Popen([exe], cwd=install_dir)
    except Exception:
        return False
    t0 = time.time()
    while time.time() - t0 < wait_sec:
        time.sleep(10)
        if os.path.getmtime(sub_file) != before:
            time.sleep(5)  # 等写完
            return True
    return False


def parse_aero_nodes(payload: bytes) -> list[Node]:
    """解密后的明文 JSON 数组 → Node 列表。"""
    items = json.loads(payload.decode("utf-8", errors="replace"))
    if isinstance(items, dict):
        items = items.get("nodes") or items.get("proxies") or []
    nodes = []
    for it in items:
        if not isinstance(it, dict):
            continue
        server = it.get("server") or it.get("address")
        if not server:
            continue
        port = it.get("server_port") or it.get("port")
        raw = {"source": "dpapi_cache"}
        for k in _AERO_FIELDS:
            if it.get(k) is not None:
                raw[k] = it[k]
        nodes.append(Node(name=str(it.get("name", f"node-{port}"))[:64],
                          protocol=str(it.get("type", "aero_v2")),
                          server=server, port=int(port or 0), raw=raw))
    return nodes


def collect_dpapi(slug: str, client_cfg: dict, detector=None) -> Snapshot:
    """读 DPAPI 订阅缓存 → 解密 → 解析节点 → (可选)富化检测。"""
    sub_file = client_cfg.get("dpapi_file") or _default_sub_file()
    if not os.path.exists(sub_file):
        raise FileNotFoundError(f"订阅缓存不存在: {sub_file}")

    stale_h = float(client_cfg.get("dpapi_stale_hours", 48))
    launched = False
    if _file_age_hours(sub_file) > stale_h:
        install_dir = client_cfg.get("install_dir", "")
        if install_dir and os.path.exists(install_dir):
            print(f"    [{slug}] 缓存>{stale_h}h，启动客户端刷新订阅...")
            launched = _launch_client_refresh(install_dir, sub_file)
            if not launched:
                print(f"    [{slug}] 客户端刷新未生效，用现有缓存")

    with open(sub_file, "rb") as f:
        blob = f.read()
    if blob[:4] != b"\x01\x00\x00\x00":
        # 已经是明文(JSON)
        payload = blob
    else:
        payload = dpapi_unprotect(blob)

    nodes = parse_aero_nodes(payload)
    snap = Snapshot(airport=slug, ts=store.now_iso(),
                    source=f"dpapi:{os.path.basename(sub_file)}",
                    nodes=nodes,
                    meta={"dpapi_file": sub_file,
                          "dpapi_file_mtime": datetime.fromtimestamp(
                              os.path.getmtime(sub_file)).isoformat(),
                          "client_launched_for_refresh": launched})
    if detector and nodes:
        from .collect import _enrich_and_detect
        snap.findings = _enrich_and_detect(slug, nodes, detector)
    return snap


def refresh_and_close_gui(install_dir: str, core_process: str | None = None):
    """GUI 刷新完成后关闭 GUI（保留服务进程，nanocore 是服务常驻）。"""
    try:
        subprocess.run(["taskkill", "/F", "/IM", "Velochron.exe"],
                       capture_output=True, timeout=10)
        # 不杀 nanocore(服务进程)，由服务管理器负责
    except Exception:
        pass
