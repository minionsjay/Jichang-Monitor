"""统一数据模型：Node（节点）/ Finding（华为命中）/ Snapshot（一次采集快照）。"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Node:
    """归一化后的单个节点。raw 保留原始字段（私有协议如 ninja 靠它）。"""
    name: str
    protocol: str            # vmess/vless/trojan/ss/hysteria2/tuic/ninja/...
    server: str              # 域名或 IP
    port: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        """用于跨快照 diff 的稳定标识。"""
        return f"{self.protocol}://{self.server}:{self.port}"


@dataclass
class Finding:
    """一条华为关联命中。"""
    airport: str
    dimension: str           # rdap_name / asn / cidr / domain / string
    rule: str                # 命中的签名
    evidence: str            # 命中的原始值（IP/域名/字符串片段）
    context: str = ""        # 来自哪个节点/文件/字段
    confidence: str = "high" # high(rdap/domain/string) / medium(cidr/asn)

    def line(self) -> str:
        return (f"[华为命中] {self.airport} | {self.dimension}={self.rule} "
                f"| 证据={self.evidence} | {self.context} ({self.confidence})")


@dataclass
class Snapshot:
    """一个机场一次采集的完整结果。"""
    airport: str
    ts: str                  # ISO 时间戳
    source: str              # 订阅 URL / profile 路径 / csv
    nodes: list[Node] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)  # 到期/流量等

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d
