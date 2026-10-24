"""承载与 CDN 归属归类：把 RDAP 的 owner/netname 映射成可读厂商名。

用途：一是让面板能直接回答"这家机场套的谁家 CDN / 落在谁家云"，
二是把「用了华为 CDN」和「源站在华为云」区分开——两者都是强关联信号，
但语义不同，界面上不该混成一句话。

判定依据只有 RDAP 的 owner / netname 文本（与 detect.py 的 rdap_name 同源），
不做额外网络请求。
"""
from __future__ import annotations

# (key, 显示名, 匹配关键词) —— 顺序即优先级，越具体的放前面
_PATTERNS: list[tuple[str, str, tuple[str, ...]]] = [
    ("huawei", "华为云/CDN", ("huawei", "hwcsnet", "hwclouds", "hicloud", "华为")),
    ("cloudflare", "Cloudflare", ("cloudflare",)),
    ("akamai", "Akamai", ("akamai",)),
    ("fastly", "Fastly", ("fastly",)),
    ("alibaba", "阿里云", ("alibaba", "aliyun", "alicdn", "cainiao")),
    ("bytedance", "火山/字节", ("bytedance", "volces", "volcengine")),
    ("aws", "AWS", ("amazon", "amazonaws", "aws")),
    ("azure", "Azure", ("microsoft", "azure")),
    ("google", "Google", ("google",)),
    ("oracle", "Oracle", ("oracle",)),
    ("tencent", "腾讯云", ("tencent", "shenzhen tencent", "aceville")),
    ("baidu", "百度云", ("baidu",)),
    ("ctg", "CTG/中电信", ("ctg server",)),
    ("hinet", "中华电信 HiNet", ("hinet",)),
    ("pccw", "香港宽频/HKT", ("netvigator", "pccw", "hkt ")),
    ("cogent", "Cogent", ("cogent",)),
    ("reseller", "IP 转租/代理", ("netutils-mnt", "private customer", "cnsv global", "newrui")),
    ("china_mobile", "中国移动", ("china mobile", "cmnet", "cmcc")),
    ("china_telecom", "中国电信", ("china telecom", "chinatelecom", "chinanet")),
    ("china_unicom", "中国联通", ("china unicom", "china169", "unicom")),
]

# 哪些算"CDN/公有云边缘"，用于在界面上单独标注
EDGE_KEYS = {"huawei", "cloudflare", "akamai", "fastly", "alibaba", "tencent",
             "bytedance", "aws", "azure", "google", "oracle", "baidu"}

LABELS = {k: label for k, label, _ in _PATTERNS}
LABELS["other"] = "未归类"


def classify(owner: str = "", netname: str = "") -> str:
    """返回厂商 key；认不出返回 'other'。"""
    hay = f"{netname or ''} {owner or ''}".lower()
    if not hay.strip():
        return "other"
    for key, _label, keys in _PATTERNS:
        for k in keys:
            if k in hay:
                return key
    return "other"


def label(key: str) -> str:
    return LABELS.get(key or "", key or "")


def is_edge(key: str) -> bool:
    return (key or "") in EDGE_KEYS


if __name__ == "__main__":
    for a, b in [("Huawei Cloud Service", "Huawei Cloud Service data center"),
                 ("Cloudflare, Inc.", "CLOUDFLARENET"),
                 ("China Mobile Communications Group Co., Ltd", "CMNET"),
                 ("Akamai Technologies, Inc.", "AKAMAI"),
                 ("n/a", "n/a")]:
        k = classify(a, b)
        print("%-52s -> %-12s %s" % ((a + " | " + b)[:52], k, label(k)))
