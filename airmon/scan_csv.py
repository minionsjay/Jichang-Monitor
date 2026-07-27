"""在现有 analysis_ip_domain.csv（14 列）上跑华为检测，用真实数据验证引擎。"""
from __future__ import annotations

import csv

from .detect import Detector
from .models import Finding


def scan_csv(path: str, airport: str = "existing", detector: Detector | None = None) -> list[Finding]:
    detector = detector or Detector()
    findings: list[Finding] = []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ctx = f"{row.get('domain','')} | {row.get('site_title','') or row.get('verdict','')}"
            findings += detector.scan_ip_record(
                airport,
                ip=row.get("ip", "").strip(),
                netname=row.get("ip_netname", ""),
                owner=row.get("ip_owner", ""),
                domain=row.get("domain", ""),
                context=ctx.strip(" |"),
            )
    # 去重
    seen, out = set(), []
    for fi in findings:
        k = (fi.dimension, fi.rule, fi.evidence, fi.context)
        if k not in seen:
            seen.add(k)
            out.append(fi)
    return out
