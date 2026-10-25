"""华为关联检测引擎。加载 signatures/huawei.yaml，跨多维度匹配产出 Finding。

维度：
  rdap_name        —— RDAP netname/owner 子串（主判据，最可靠）
  asn              —— ASN 号（可靠）
  cidr             —— IP 落在华为云段（兜底）
  domain           —— 节点 server / CNAME 命中华为域名（需结构校验 + 解析佐证）
  huawei_cdn_relay —— 节点域名 CNAME 到华为云 CDN（cdnhwc* / hcdnw* / huaweicloudwaf）
  fronting         —— 借大厂域名做前置（server 本身就是大厂域）
  string           —— 软件二进制/文本 strings 子串

关于 domain 维度的可信度：
  2026-10 排查发现「华为命中」里出现过假阳性——客户端内存里的**域名常量表被整段读出、
  分隔符丢失**，拼成 `cdnhwcjsb120.comcdnhwccmz121.comdoh.pub` 这种串，按子串匹配就命中
  了 cdnhwc。因此本模块对 domain 维度加了三道闸：
    1. `_is_clean_domain()` 结构校验（拼接串直接丢弃）；
    2. 短签名（<=8 字符）必须落在 label 边界，不能命中 label 内部；
    3. 没有解析出 IP 的域名只能给 low（不参与「华为命中」计数）。
  取舍是「宁可漏报，不可误报」。
"""
from __future__ import annotations

import ipaddress
import os
import re
import yaml

from .models import Finding, Node

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SIG = os.path.join(_HERE, "signatures", "huawei.yaml")

# ---- 域名结构校验 ----
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD_RE = re.compile(r"^[a-z]{2,24}$")
# 拼接特征：某个 label 以 com/net/org 等常见 TLD 开头、后面还接着字母和数字
_GLUED_RE = re.compile(r"(?:com|net|org|cn|xyz|top|vip|cc|info)[a-z]{2,}", re.I)
# 华为云 CDN 正常 label 格式：cdnhwc + 3 字母 + 数字
_CDNHWC_OK = re.compile(r"^cdnhwc[a-z]{3}\d{1,5}$")

# 华为云 CDN / WAF 的接入域名特征
# 实测：fe-static.deepseek.com.436b7a4e.cdnhwcxcy07.com → hcdnw120.vip.global.cdnhwctnm107.com
HUAWEI_CDN_KEYS = ("cdnhwc", "hcdnw", "huaweicloudwaf", "hwclouds-dns")
# CDN 只能承载 HTTP 家族；裸 TCP（ss / vless+reality / anytls）不可能经 CDN 中转
_HTTP_NET = ("ws", "grpc", "h2", "http")

# 常被拿来做「域名前置」的大厂域：server 直接写这些 = 连的不是自己的机器。
# 只收「有真实服务的大厂主域」；gstatic / cloudflare / alicdn 这类纯静态 CDN 域不收——
# 客户端内存里塞满了 DoH 端点（cp.cloudflare.com、www.gstatic.com），收进来全是噪声。
BIG_BRANDS = {
    "deepseek.com": "DeepSeek",
    "apple.com": "Apple",
    "microsoft.com": "Microsoft",
    "office.com": "Microsoft Office",
    "bilibili.com": "哔哩哔哩",
    "taobao.com": "淘宝",
    "qq.com": "腾讯",
    "baidu.com": "百度",
    "github.com": "GitHub",
    "azure.com": "Azure",
}

# 客户端自用的公共服务端点（DoH / DNS / 时间同步），永远不是代理节点
PUBLIC_ENDPOINTS = {
    "doh.pub", "dns.alidns.com", "dns.google", "cp.cloudflare.com",
    "cloudflare-dns.com", "dns.sb", "dns.twnic.tw", "www.gstatic.com",
    "gstatic.com", "one.one.one.one", "time.windows.com", "ntp.aliyun.com",
}


def _is_clean_domain(d: str) -> bool:
    """整串必须是一个合法域名；多个域名连写的「拼接串」返回 False。

    `cdnhwcljk104.comcdnhwclxu105.comcdnhwcbqs106.comdoh.pub` 里，
    `comcdnhwclxu105` 是「上一个域名丢了分隔符、接着下一个域名」，正常域名不会这样。
    取舍：`community.example.com` 这类靠「match 覆盖整个 label」的判定保留下来，不会误伤。
    """
    d = (d or "").strip().lower()
    if not d or len(d) > 253:
        return False
    if any(ch in d for ch in ' \t\r\n"\'\\/@'):
        return False
    labels = d.split(".")
    if len(labels) < 2:
        return False
    if not _TLD_RE.match(labels[-1]):
        return False
    for lab in labels:
        if not _LABEL_RE.match(lab):
            return False
    # 同一个 label 重复出现两次以上 = 整段内存被读了两遍后拼在一起
    seen = set()
    for lab in labels:
        if lab in seen and len(lab) > 3:
            return False
        seen.add(lab)
    # com.com：域名尾巴又接了一个 TLD
    if len(labels) >= 3 and labels[-1] == labels[-2]:
        return False
    # 3 个以上纯数字 label = 「IP 后面又粘了域名」（43.131.39.48fastlink.so）
    numeric = sum(1 for lab in labels if lab.isdigit())
    if numeric >= 3:
        return False
    for lab in labels[:-1]:
        m = _GLUED_RE.match(lab)
        if m and len(m.group(0)) < len(lab):
            return False  # 拼接串：label 里粘着上一个域名的尾巴
        # comdoh / netpub 这类「前面一个域名丢了分隔符」：label 以 TLD 开头且还有内容
        low = lab.lower()
        for tld in ("com", "net", "org", "cn", "xyz", "top", "vip", "cc", "info", "pub"):
            if low.startswith(tld) and len(low) > len(tld) + 2:
                return False
        # 华为 CDN 的正常格式是 cdnhwc + 3 字母 + 数字（cdnhwcbzj102）；
        # 出现 cdnhwc + 别的词 = 又一个拼接串
        if low.startswith("cdnhwc") and not _CDNHWC_OK.match(low):
            return False
    return True


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def is_sane_host(h: str) -> bool:
    """server 是否像一个真能连接的地址（合法域名或 IPv4）。

    内存扫描常把多段字节读成一段：`43.131.39.48fastlink.so`（IP 后接域名）、
    `cdnhwc...comdoh.pub`（多个域名连写）。这类串既连不上，也不该参与任何检测。
    """
    s = (h or "").strip()
    if not s or len(s) > 253:
        return False
    if any(ch in s for ch in ' \t\r\n"\'\\/@'):
        return False
    if _IPV4_RE.match(s):
        return True
    return _is_clean_domain(s)



# ---- 华为相关维度的统一口径 ----
# fronting（借大厂域名做前置）不算「机场在华为云」，必须单独统计，
# 否则 www.baidu.com / chat.deepseek.com 这类目标会把华为命中数虚抬。
HW_DIMS = ("rdap_name", "asn", "cidr", "domain", "huawei_cdn_relay")


def count_huawei(findings) -> int:
    """只数真正指向华为云的 findings。"""
    return sum(1 for f in (findings or []) if getattr(f, "dimension", "") in HW_DIMS)


def split_findings(findings):
    """→ (华为相关, 大厂域前置, 其它)"""
    hw, fr, other = [], [], []
    for f in (findings or []):
        d = getattr(f, "dimension", "")
        if d in HW_DIMS:
            hw.append(f)
        elif d == "fronting":
            fr.append(f)
        else:
            other.append(f)
    return hw, fr, other


class Detector:
    def __init__(self, sig_path: str | None = None):
        with open(sig_path or DEFAULT_SIG, encoding="utf-8") as f:
            sig = yaml.safe_load(f)
        self.name = sig.get("name", "huawei")
        self.rdap_name = [s.lower() for s in sig.get("rdap_name", [])]
        self.asn = {str(a).lstrip("ASas") for a in sig.get("asn", [])}
        self.networks = [ipaddress.ip_network(c) for c in sig.get("cidr", [])]
        self.domain = [s.lower() for s in sig.get("domain", [])]
        self.string = [s.lower() for s in sig.get("string", [])]

    # ---- 单维度检查（返回命中的签名，未命中返回 None）----
    def check_rdap(self, netname: str, owner: str) -> str | None:
        hay = f"{netname} {owner}".lower()
        for s in self.rdap_name:
            if s in hay:
                return s
        return None

    def check_asn(self, asn: str) -> str | None:
        nums = re.findall(r"\d+", asn or "")
        for n in nums:
            if n in self.asn:
                return f"AS{n}"
        return None

    def check_cidr(self, ip: str) -> str | None:
        """静态 17 段兜底 + 动态 ASN 前缀表。

        静态表只覆盖华为云的一小部分；转售/二次分配的 IP 在 RDAP 里
        netname 可能不写 HWCSNET，这时只有「IP 属于华为公告前缀」还能判定。
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net in self.networks:
            if addr.version == net.version and addr in net:
                return str(net)
        try:
            from .hwprefix import contains as _hw_contains
            if _hw_contains(ip):
                return "huawei-asn"
        except Exception:  # noqa: BLE001
            pass
        return None

    def check_domain(self, domain: str) -> str | None:
        """域名子串匹配。短签名（<=8 字符）必须落在 label 边界上。"""
        d = (domain or "").lower()
        if not d:
            return None
        for s in self.domain:
            if not s:
                continue
            if len(s) <= 8:
                # cdnhwc 只能命中 `.cdnhwc...` 或串首，不能命中 `xxcdnhwcxx.yy`
                if re.search(r"(?:^|\.)" + re.escape(s), d):
                    return s
            elif s in d:
                return s
        return None

    def check_string(self, text: str) -> list[str]:
        t = (text or "").lower()
        return [s for s in self.string if s in t]

    # ---- 组合：对一条富化后的 IP 记录做全维度检查 ----
    def scan_ip_record(self, airport: str, *, ip: str = "", netname: str = "",
                       owner: str = "", asn: str = "", domain: str = "",
                       context: str = "") -> list[Finding]:
        out: list[Finding] = []
        if netname or owner:
            hit = self.check_rdap(netname, owner)
            if hit:
                out.append(Finding(airport, "rdap_name", hit,
                                   f"{netname}/{owner}", context, "high"))
        if asn:
            hit = self.check_asn(asn)
            if hit:
                out.append(Finding(airport, "asn", hit, asn, context, "high"))
        if ip and not out:  # rdap 已命中就不必再靠 CIDR 兜底
            hit = self.check_cidr(ip)
            if hit:
                out.append(Finding(airport, "cidr", hit, ip, context, "medium"))
        if domain and _is_clean_domain(domain):
            hit = self.check_domain(domain)
            if hit:
                out.append(Finding(airport, "domain", hit, domain, context, "high"))
        return out

    def scan_text(self, airport: str, text: str, context: str) -> list[Finding]:
        return [Finding(airport, "string", s, s, context, "high")
                for s in self.check_string(text)]

    # ---- 新维度 1：节点域名 CNAME 到华为云 CDN ----
    def scan_cdn_relay(self, airport: str, node: Node) -> list[Finding]:
        # server 本身就是大厂域名（chat.deepseek.com 之类）时，CNAME 链里的华为 WAF
        # 属于「借大厂域前置」，不是「机场把自己的域名挂到华为 CDN」——归 fronting。
        srv = (node.server or "").lower()
        if any(srv == b or srv.endswith("." + b) for b in BIG_BRANDS):
            return []
        chains = [c for c in (node.raw.get("_cnames") or []) if c]
        if not chains:
            return []
        net = (node.raw.get("network") or "").lower()
        httpish = net in _HTTP_NET
        out: list[Finding] = []
        for hop in chains:
            low = hop.lower()
            for k in HUAWEI_CDN_KEYS:
                if k in low:
                    # 协议是 HTTP 家族才可能真的经 CDN 中转；裸 TCP 只是站点加速
                    out.append(Finding(
                        airport, "huawei_cdn_relay", k, hop,
                        f"节点 {node.name or node.server}",
                        "high" if httpish else "medium"))
        return out

    # ---- 新维度 2：借大厂域名做前置 ----
    def is_fronting(self, node: Node) -> str:
        """该节点的连接目标本身就是大厂域名 → 返回品牌 key，否则空串。

        这类节点解析出的 IP 是**大厂自己的服务器**（chat.deepseek.com → 华为云 WAF），
        不能当成「机场把服务器放在华为云」。
        """
        host = (node.server or "").strip().lower()
        if not host or not _is_clean_domain(host):
            return ""
        if host in PUBLIC_ENDPOINTS:
            return ""
        for e in PUBLIC_ENDPOINTS:
            if host.endswith("." + e):
                return ""
        if not (node.raw.get("_resolved_ips") or []):
            return ""
        for brand in BIG_BRANDS:
            if host == brand or host.endswith("." + brand):
                return brand
        return ""

    def scan_fronting(self, airport: str, node: Node) -> list[Finding]:
        """只查 node.server（真实连接目标），且必须真的解析出 IP。

        REALITY 的 servername/sni 天生就伪装成大站，属正常用法，不能算前置——
        把 sni 也纳入的话，全库几十条 REALITY 节点都会误报。
        另外客户端内存里塞满 DoH 端点（cp.cloudflare.com / www.gstatic.com）与
        拼接碎片（44www.gstatic.com），这些既不解析、也不是节点，必须排除。
        """
        brand = self.is_fronting(node)
        if not brand:
            return []
        return [Finding(airport, "fronting", brand, (node.server or "").strip().lower(),
                        f"节点 {node.name or node.server}（{BIG_BRANDS[brand]}）", "medium")]

    # ---- 对一批节点（已富化 server→ips）做检查 ----
    def scan_nodes(self, airport: str, nodes: list[Node],
                   rdap_map: dict[str, tuple]) -> list[Finding]:
        out: list[Finding] = []
        for n in nodes:
            ctx = f"节点 {n.name or n.server}"
            # server 本身 + 它的 CNAME 链都要查域名维度：
            # 机场常把节点域名 CNAME 到 CDN 边缘域（cdnhwc* = 华为云 CDN），
            # 只看 server 会漏掉这一层。
            names = [n.server]
            for c in (n.raw.get("_cnames") or []):
                if c and c not in names:
                    names.append(c)
            has_ip = bool(n.raw.get("_resolved_ips"))
            for nm in names:
                f = self._domain_finding(airport, nm, ctx, has_ip=has_ip)
                if f:
                    out.append(f)
            out += self.scan_cdn_relay(airport, n)
            out += self.scan_fronting(airport, n)
            for ip in n.raw.get("_resolved_ips", []):
                netname, owner, country, asn = rdap_map.get(ip, ("", "", "", ""))
                out += self.scan_ip_record(airport, ip=ip, netname=netname,
                                           owner=owner, asn=asn, context=ctx)
        return _dedup(out)

    def _domain_finding(self, airport, domain, ctx, has_ip: bool = False):
        d = (domain or "").strip()
        if not _is_clean_domain(d):
            return None          # 拼接串 / 非法 host，直接丢弃
        hit = self.check_domain(d)
        if not hit:
            return None
        # 没解析出 IP 的域名只能证明「这段字符串里出现过华为域名特征」，
        # 不能证明节点真落在华为——降级 low，不参与命中统计。
        return Finding(airport, "domain", hit, d, ctx, "high" if has_ip else "low")


def _dedup(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        k = (f.dimension, f.rule, f.evidence, f.context)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
