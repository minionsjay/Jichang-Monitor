"""极简 DNS 查询：只为拿 CNAME 链（纯标准库 UDP，不依赖 dnspython）。

为什么要它：节点 server 里约 84% 是域名，其中一部分 CNAME 到 CDN 域
（例如 xxx.cdnhwcXXX.com 就是华为云 CDN 的边缘域）。只看 server 字符串
会漏掉这一层关联。

为什么不用 nslookup：每个域名一次子进程约 0.5s，1800 个域名要 15 分钟，
会把一轮 42 分钟的采集拖垮。这里自己拼 DNS 报文走 UDP，32 线程几秒跑完。
"""
from __future__ import annotations

import concurrent.futures
import random
import socket
import struct

# 阿里 → 腾讯 → Google：国内可达优先，8.8.8.8 兜底
DNS_SERVERS = ("223.5.5.5", "119.29.29.29", "8.8.8.8")

_TYPE_A = 1
_TYPE_CNAME = 5


def _encode_name(host: str) -> bytes:
    out = b""
    for label in host.strip().rstrip(".").split("."):
        if not label:
            continue
        try:
            raw = label.encode("idna")
        except Exception:
            raw = label.encode("ascii", "ignore")
        if not raw or len(raw) > 63:
            continue
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _read_name(buf: bytes, off: int) -> tuple[str, int]:
    """解一个域名，支持压缩指针。返回 (名字, 下一个字段偏移)。"""
    parts: list[str] = []
    next_off = off
    jumped = False
    for _ in range(64):
        if off >= len(buf):
            break
        ln = buf[off]
        if ln & 0xC0 == 0xC0:  # 压缩指针
            if off + 1 >= len(buf):
                break
            ptr = struct.unpack("!H", buf[off:off + 2])[0] & 0x3FFF
            if not jumped:
                next_off = off + 2
                jumped = True
            off = ptr
            continue
        if ln == 0:
            off += 1
            if not jumped:
                next_off = off
            break
        off += 1
        parts.append(buf[off:off + ln].decode("ascii", "ignore"))
        off += ln
        if not jumped:
            next_off = off
    return ".".join(parts), next_off


def _parse(buf: bytes) -> tuple[list[str], list[str]]:
    """返回 (cname 链, A 记录 IP 列表)。"""
    if len(buf) < 12:
        return [], []
    _qid, _flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", buf[:12])
    off = 12
    for _ in range(qd):
        _n, off = _read_name(buf, off)
        off += 4
    cnames: list[str] = []
    ips: list[str] = []
    for _ in range(an):
        _n, off = _read_name(buf, off)
        if off + 10 > len(buf):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
        off += 10
        if off + rdlen > len(buf):
            break
        if rtype == _TYPE_CNAME:
            tgt, _ = _read_name(buf, off)
            tgt = tgt.rstrip(".").lower()
            if tgt:
                cnames.append(tgt)
        elif rtype == _TYPE_A and rdlen == 4:
            ips.append(".".join(str(b) for b in buf[off:off + 4]))
        off += rdlen
    return cnames, ips


def query(host: str, server: str, timeout: float = 2.5,
          qtype: int = _TYPE_A) -> tuple[list[str], list[str]]:
    """查一次；查 A 记录时权威服务器通常会把 CNAME 链一起带回来。"""
    qid = random.randint(0, 0xFFFF)
    pkt = (struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
           + _encode_name(host) + struct.pack("!HH", qtype, 1))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        for _ in range(4):
            data, _addr = s.recvfrom(4096)
            if len(data) < 12:
                continue
            if struct.unpack("!H", data[:2])[0] != qid:
                continue
            return _parse(data)
        return [], []
    finally:
        s.close()


def cnames_of(host: str, timeout: float = 2.5) -> list[str]:
    """单个域名的 CNAME 链（多服务器依次重试，全失败返回空列表）。"""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return []
    for server in DNS_SERVERS:
        try:
            cn, _ips = query(h, server, timeout)
            return cn
        except Exception:
            continue
    return []


def cname_many(hosts, workers: int = 32, timeout: float = 2.5) -> dict[str, list[str]]:
    """批量查 CNAME 链，返回 {host: [cname...]}；无 CNAME 的给空列表。"""
    uniq = sorted({(h or "").strip().lower().rstrip(".")
                   for h in hosts if h})
    if not uniq:
        return {}
    out: dict[str, list[str]] = {}

    def _one(h: str) -> tuple[str, list[str]]:
        return h, cnames_of(h, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for h, cn in ex.map(_one, uniq):
            out[h] = cn
    return out


if __name__ == "__main__":
    import sys
    for arg in sys.argv[1:] or ["hktwaaaaa.selom.online"]:
        print("%-42s -> %s" % (arg, ", ".join(cnames_of(arg)) or "（无 CNAME）"))
