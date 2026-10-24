"""域名解析核对工具：把「我们怎么解析的」和「你自己用 dig 会看到什么」摆在一起。

用法：
    python -X utf8 tools/dns_check.py xinaleye.owolist.cn
    python -X utf8 tools/dns_check.py a.com b.com --rdap      # 顺带查每个 IP 的归属

输出四列：系统解析器（getaddrinfo）、阿里 223.5.5.5、Cloudflare 1.1.1.1、Google 8.8.8.8，
最后一行是「面板实际记录的并集」（即 airmon.enrich.resolve_detail 的返回值）。

想用原生 dig 对照（本机 dig 在 WSL 里）：
    wsl -d Ubuntu-22.04 -- dig +short @223.5.5.5 <域名> A
    wsl -d Ubuntu-22.04 -- dig +short @1.1.1.1  <域名> A
Windows 自带（PowerShell）：
    Resolve-DnsName -Name <域名> -Server 1.1.1.1 -Type A
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airmon import dnsq                                    # noqa: E402
from airmon.enrich import _getaddrinfo, resolve_detail     # noqa: E402

SERVERS = [("阿里 223.5.5.5", "223.5.5.5"),
           ("CF 1.1.1.1", "1.1.1.1"),
           ("Google 8.8.8.8", "8.8.8.8")]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="核对域名解析（系统解析器 vs 各公共 DNS）")
    ap.add_argument("hosts", nargs="+", help="域名，可多个")
    ap.add_argument("--rdap", action="store_true", help="同时查每个 IP 的 RDAP 归属")
    ap.add_argument("--timeout", type=float, default=2.5)
    args = ap.parse_args(argv)

    for host in args.hosts:
        print()
        print("=" * 74)
        print(host)
        print("=" * 74)

        sim = _getaddrinfo(host, 3.5)
        print("  系统解析器 getaddrinfo  %2d 个  %s" % (len(sim), " ".join(sim) or "-"))

        per_server = {}
        for label, srv in SERVERS:
            try:
                _cn, ips = dnsq.query(host, srv, timeout=args.timeout)
            except Exception as e:
                ips = []
                label += " (%s)" % str(e)[:18]
            per_server[srv] = ips
            print("  %-22s %2d 个  %s" % (label, len(ips), " ".join(sorted(ips)) or "-"))

        union, alt = resolve_detail(host, 3.5)
        print("  " + "-" * 70)
        print("  面板实际记录(并集)     %2d 个  (海外独有: %s)" % (len(union), " ".join(alt) or "无"))

        # 差异说明：谁贡献了别人没有的 IP
        for label, srv in SERVERS:
            extra = [ip for ip in per_server[srv] if ip not in sim]
            if extra:
                print("    · 只有 %s 解析到: %s" % (label, " ".join(extra)))

        if args.rdap and union:
            from airmon.enrich import rdap as _rdap
            print()
            for ip in union:
                netname, owner, country, asn = _rdap(ip)
                mark = " ←海外独有" if ip in alt else ""
                print("    %-16s %-14s %-34s %-6s %s%s"
                      % (ip, netname[:14], (owner or "")[:34], country[:6], (asn or "")[:28], mark))
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
