# -*- coding: utf-8 -*-
"""机场知识库（推荐站协议科普/行业知识离线包）。

用法:
    python -m airmon.knowledge [--src <jctj_knowledge_raw.json>] [--out <data/knowledge.json>]

数据来源: jichangtuijian1.com /xieyi 栏目科普文章（协议原理/协议对比/客户端选择）
与行业观察文章（拔线潮/流量倍率/防骗指南）的正文结构化摘录。
机场评测类散装文章（云图小镇/穿云箭/扑克云）归入 sites_digest，不在本库。
输出白名单字段，写盘前负向自检；text 每节截断 1800 字符。
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("AIRMON_DATA", str(_HERE / "data")))
def _find_src() -> str:
    """优先 repo 内置源（跨机可重建），回退 Windows 真实 TEMP（DSH 会话 TEMP 会被改写）。"""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for p in (os.path.join(here, "data_src", "jctj_knowledge_raw.json"),
              os.path.join(tempfile.gettempdir(), "jctj_knowledge_raw.json"),
              os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                           "Temp", "jctj_knowledge_raw.json"),
              os.path.expandvars(r"%LOCALAPPDATA%\Temp\jctj_knowledge_raw.json")):
        if p and os.path.isfile(p):
            return p
    return os.path.join(here, "data_src", "jctj_knowledge_raw.json")


DEFAULT_SRC = _find_src()

CAT_PROTOCOL = "协议科普"
CAT_INDUSTRY = "行业知识"

_SLUG_CAT = {
    "hysteria2": CAT_PROTOCOL, "reality": CAT_PROTOCOL, "vless": CAT_PROTOCOL,
    "vless-clash": CAT_PROTOCOL, "xieyi-duibi": CAT_PROTOCOL,
    "xieyi-kehuduan": CAT_PROTOCOL, "shadowsocks": CAT_PROTOCOL,
    "trojan": CAT_PROTOCOL, "anytls": CAT_PROTOCOL,
    "baxianchao": CAT_INDUSTRY, "beilv": CAT_INDUSTRY, "fangpian": CAT_INDUSTRY,
}

_OUT_KEYS = ("slug", "title", "date", "cat", "n_sections", "sections", "doms")
_TEXT_CAP = 1800
_DOMS_CAP = 10
_SLUG_RE = re.compile(r"^[\w.\-]{1,40}$")
_SECRET_RE = re.compile(
    r"token=[A-Za-z0-9]|eyJ[A-Za-z0-9]{10}|sub_url|password\s*[:=]\s*['\"][^'\"]{6,}",
    re.I)


# ---- 静态内置篇（WSL 检测研究提炼，不依赖 TEMP 源，跨机可重建） ------
CAT_RESEARCH = "检测研究"
_EXTRA_KNOWLEDGE = {
    "huawei-detect-judges": {
        "title": "华为云机场流量检测：数据面、判据与评分卡",
        "date": "2026-10-19",
        "cat": CAT_RESEARCH,
        "sections": [
            ["一、问题定义与合规边界",
             "识别对象是「云上代理服务端」——租户在云主机上搭翻墙/机场服务。三条铁律："
             "只分析自己账号/VPC 内的日志（自采自用合法）；不对第三方主动探测（端口扫描、指纹投递均不做）；"
             "不训练模型，判据全部是可解释规则。注意机场服务端会主动伪装成正常业务（443 大流量 HTTPS），"
             "所以单一信号不可定罪，必须多判据叠加评分。"],
            ["二、数据面：华为云 12 类日志源（按可见性）",
             "能拿到域名的只有 CFW（dst_host）与 DNS 解析器日志（QueryName）；"
             "VPC 流日志只有 IP/端口/字节/时长（十分钟聚合窗、无 payload），单网卡每 10 分钟上限 40 万条，"
             "仅部分 ECS 规格支持；报文级内容只有 VPC 流量镜像（投自建 IDS）；"
             "HSS 主机指纹（端口 30 秒级）是主机侧佐证；中国站 NAT 网关无会话日志——"
             "经 NAT 出公网的流量必须靠流日志/镜像兜底。各日志入 LTS 后 <2 分钟可查，"
             "控制台导出单次 250 条、API 5000 条。"],
            ["三、判据体系（J1-J6，对应总纲 F 系判据的静态可算子集）",
             "J1 长连接大流量：duration>=600s 且 bytes>=10MB；J2 高位端口：dport>=10000 占比>50%"
             "（机场节点 10k-65k 高位连续段是实测强指纹，67-69% 节点命中）；"
             "J3 目的扇入：同一 dst:port 被 >=3 个不同源连接（共享代理池形态）；"
             "J4 字节比异常：bytes/packets>8000（少报文大流量=加密隧道）；"
             "J5 机场基建命中：目的 IP/域名命中已知机场节点库（最强判据，直接 90 分）；"
             "J6 机场域名命中：dst_host/QueryName 命中机场域名集。"
             "协议侧最强单判据是 TLS-in-TLS（USENIX24），需报文级镜像，属进阶阶段。"],
            ["四、评分卡与误报控制",
             "J5 命中 +90、J6 +80、J3 扇入 +25（≥10 源 +35）、J2 +20、J1 每条 +10（上限 30）、J4 +15；"
             "总分封顶 100。level：strong>=70、mid 40-70、low<40 不出报告。"
             "误报清单（明确不判）：大文件下载/视频会议（单 J1 高但无扇入无基建）、"
             "DNS 泛解析污染、CDN 大流量、时间同步等系统端口（123/1900）。"
             "单一判据不强报：无基建关联时最高 25 分。"],
            ["五、观测阶梯（由易到难）",
             "第一阶：本机 Clash/sing-box 面板 API 观测（零成本，看真实代理连接五元组）；"
             "第二阶：DNS 日志（域名与解析行为画像）；第三阶：NetFlow/流日志五特征"
             "（长连接/固定端口/扇入/字节比/周期性）；第四阶：流量镜像+JA4/JA4T 指纹+TLS-in-TLS 原型"
             "（仅对评分高的候选网卡做）。每阶产出可独立交付，不必一步到位。"],
            ["六、与机场监控项目的融合",
             "分析端底料是现成的：44+ 机场最新快照的节点 IP/域名（J5 命中库）+ 域名全集 155 活域（J6 命中库）+ "
             "idc_profile 四指标画像。采集端在华为云开通流日志后导出 CSV，"
             "一条命令 python -m airmon.huawei_detect --in <日志> 出评分报告"
             "（data/huawei_findings.json）。判据全部离线可复算，报告含内部 IP 仅限内部使用。"],
        ],
        "doms": [],
    },
}


def build(src: str, out: Path) -> int:
    raw = json.load(io.open(src, encoding="utf-8")) if src and os.path.isfile(src) else {}
    rows = []
    for slug, d in raw.items():
        cat = _SLUG_CAT.get(slug)
        if not cat or not _SLUG_RE.match(str(slug)):
            continue  # 机场评测类(云图小镇等)不进知识库
        sections = []
        for h2, text in (d.get("sections") or [])[:14]:
            if not h2 or not text:
                continue
            sections.append([str(h2)[:120], str(text)[:_TEXT_CAP]])
        doms = [str(x)[:60] for x in (d.get("doms") or [])[:_DOMS_CAP]]
        rows.append({
            "slug": str(slug)[:40],
            "title": str(d.get("title") or slug)[:80],
            "date": str(d.get("date") or "")[:10],
            "cat": cat,
            "n_sections": len(sections),
            "sections": sections,
            "doms": doms,
        })
    rows.sort(key=lambda r: (r["cat"], r["slug"]))
    # 静态内置篇拼在最后（评测源缺失时知识库仍可用）
    have = {r["slug"] for r in rows}
    for slug, k in _EXTRA_KNOWLEDGE.items():
        if slug in have:
            continue
        rows.append({
            "slug": slug[:40], "title": k["title"][:80], "date": k["date"][:10],
            "cat": k["cat"], "n_sections": len(k["sections"]),
            "sections": [[h[:120], t[:_TEXT_CAP]] for h, t in k["sections"]],
            "doms": list(k["doms"])[:_DOMS_CAP],
        })
    rows.sort(key=lambda r: (r["cat"], r["slug"]))
    blob = json.dumps(rows, ensure_ascii=False)
    m = _SECRET_RE.search(blob)
    if m:
        raise SystemExit("知识库含敏感样态 %r，中止写盘" % m.group(0))
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp")
    with io.open(tmp, "w", encoding="utf-8") as f:
        f.write(blob)
    os.replace(tmp, out)
    n_proto = sum(1 for r in rows if r["cat"] == CAT_PROTOCOL)
    n_res = sum(1 for r in rows if r["cat"] == CAT_RESEARCH)
    print("知识库完成：%d 篇（%s %d / %s %d / %s %d）→ %s"
          % (len(rows), CAT_PROTOCOL, n_proto, CAT_INDUSTRY, len(rows) - n_proto - n_res,
             CAT_RESEARCH, n_res, out))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="机场知识库生成（推荐站科普正文离线包）")
    ap.add_argument("--src", default=DEFAULT_SRC, help="抓取产物 JSON（%%TEMP%%\\jctj_knowledge_raw.json，缺失时仅出内置篇）")
    ap.add_argument("--out", default=str(DATA_DIR / "knowledge.json"))
    a = ap.parse_args(argv)
    return build(a.src, Path(a.out))


if __name__ == "__main__":
    sys.exit(main())
