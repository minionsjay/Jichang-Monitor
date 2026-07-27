"""凭证驱动的自动登录 → 取订阅链接。

绝大多数机场是 v2board / Xboard，登录与取订阅 API 一致：
  POST /api/v1/passport/auth/login   {email, password}  → data.auth_data (+ token)
  GET  /api/v1/user/getSubscribe     Authorization: <auth_data>  → data.subscribe_url

拿到 subscribe_url 后用 Clash UA 抓即得节点。SSPanel 类走 cookie，另做；
muniu 客户端锁定型不适用。
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


class LoginError(Exception):
    pass


def _norm(base: str) -> str:
    """只保留 scheme://域名，剥掉路径/query/fragment。
    这样填 panel 时带了 /login、/#/login、/auth/login 等也没关系。"""
    from urllib.parse import urlparse
    base = base.strip()
    if not base.startswith("http"):
        base = "https://" + base
    u = urlparse(base)
    return f"{u.scheme}://{u.netloc}"


def v2board_login(panel: str, email: str, password: str,
                  timeout: int = 25) -> tuple[str, str]:
    """返回 (subscribe_url, auth_data)。失败抛 LoginError。"""
    base = _norm(panel)
    s = requests.Session()
    s.headers.update({"User-Agent": _UA_BROWSER, "Content-Type": "application/json"})
    try:
        r = s.post(f"{base}/api/v1/passport/auth/login",
                   json={"email": email, "password": password},
                   timeout=timeout, verify=False)
    except requests.RequestException as e:
        raise LoginError(f"登录请求失败: {e}")

    if r.status_code == 403 or "cf-mitigated" in {k.lower() for k in r.headers}:
        raise LoginError("被 Cloudflare/反爬拦截(可能需验证码)")
    try:
        data = r.json()
    except ValueError:
        raise LoginError(f"非 v2board 响应(HTTP {r.status_code}): {r.text[:120]}")

    if not isinstance(data, dict):
        raise LoginError(f"非 v2board 响应(登录返回非对象): {str(data)[:120]}")
    d = data.get("data")
    d = d if isinstance(d, dict) else {}
    auth = d.get("auth_data") or d.get("token")
    if not auth:
        msg = data.get("message") or data.get("errors") or r.text[:120]
        raise LoginError(f"登录被拒: {msg}")

    try:
        r2 = s.get(f"{base}/api/v1/user/getSubscribe",
                   headers={"Authorization": auth}, timeout=timeout, verify=False)
        j2 = r2.json()
        dd = j2.get("data") if isinstance(j2, dict) else None
        sub = dd.get("subscribe_url") if isinstance(dd, dict) else None
    except (requests.RequestException, ValueError) as e:
        raise LoginError(f"取订阅失败: {e}")
    if not sub:
        raise LoginError(f"登录成功但未拿到 subscribe_url；getSubscribe 返回: "
                         f"{str(j2)[:150] if 'j2' in dir() else '?'}")
    return sub, auth


def sspanel_login(panel: str, email: str, password: str,
                  timeout: int = 25) -> tuple[str, None]:
    """SSPanel-uim：cookie 会话登录 → 从 /user 页抠订阅链接 /link/<token>。

    字段是 passwd（非 password）；成功 JSON {"ret":1}。
    """
    base = _norm(panel)
    s = requests.Session()
    s.headers.update({"User-Agent": _UA_BROWSER,
                      "X-Requested-With": "XMLHttpRequest"})
    try:
        r = s.post(f"{base}/auth/login",
                   data={"email": email, "passwd": password,
                         "code": "", "remember_me": "week"},
                   timeout=timeout, verify=False)
    except requests.RequestException as e:
        raise LoginError(f"登录请求失败: {e}")

    try:
        j = r.json()
    except ValueError:
        raise LoginError(f"非 SSPanel 响应(HTTP {r.status_code}): {r.text[:120]}")
    if not isinstance(j, dict):
        raise LoginError(f"非 SSPanel 响应(返回非对象 {type(j).__name__}): {str(j)[:100]}")
    if j.get("ret") != 1:
        msg = j.get("msg") or j.get("message") or "登录被拒"
        if any(k in str(msg) for k in ("验证码", "captcha", "code")):
            raise LoginError(f"需验证码: {msg}")
        raise LoginError(f"登录被拒: {msg}")

    # 订阅链接在用户中心页 HTML 里
    try:
        r2 = s.get(f"{base}/user", timeout=timeout, verify=False)
    except requests.RequestException as e:
        raise LoginError(f"取用户中心失败: {e}")
    m = re.search(r"/link/([A-Za-z0-9]+)", r2.text)
    if not m:
        raise LoginError("登录成功但未找到 /link/<token> 订阅链接（面板可能非标准 SSPanel）")
    sub = f"{base}/link/{m.group(1)}?clash=1"
    return sub, None


def smart_login(panel: str, email: str, password: str,
                ptype: str = "auto") -> tuple[str, str, str]:
    """按面板类型登录。返回 (subscribe_url, auth, 识别到的类型)。

    ptype: v2board / sspanel / auto（先试 v2board，失败再试 sspanel）。
    """
    if ptype == "v2board":
        sub, auth = v2board_login(panel, email, password)
        return sub, auth, "v2board"
    if ptype == "sspanel":
        sub, auth = sspanel_login(panel, email, password)
        return sub, auth, "sspanel"
    # auto
    errors = []
    try:
        sub, auth = v2board_login(panel, email, password)
        return sub, auth, "v2board"
    except LoginError as e:
        errors.append(f"v2board:{e}")
    try:
        sub, auth = sspanel_login(panel, email, password)
        return sub, auth, "sspanel"
    except LoginError as e:
        errors.append(f"sspanel:{e}")
    raise LoginError(" | ".join(errors))


def probe_panel(host: str, timeout: int = 8) -> tuple[str, str] | None:
    """探测单个域名是不是可登录的面板。返回 (base_url, type) 或 None。"""
    base = _norm(host)
    try:
        r = requests.post(f"{base}/api/v1/passport/auth/login",
                          json={"email": "", "password": ""},
                          headers={"User-Agent": _UA_BROWSER},
                          timeout=timeout, verify=False, allow_redirects=False)
        if "json" in r.headers.get("content-type", ""):
            j = r.json()
            if isinstance(j, dict) and any(k in j for k in ("message", "errors", "data")):
                return base, "v2board"
    except Exception:
        pass
    try:
        r = requests.post(f"{base}/auth/login",
                          data={"email": "", "passwd": "", "code": ""},
                          headers={"User-Agent": _UA_BROWSER,
                                   "X-Requested-With": "XMLHttpRequest"},
                          timeout=timeout, verify=False, allow_redirects=False)
        if "json" in r.headers.get("content-type", ""):
            j = r.json()
            if isinstance(j, dict) and "ret" in j:
                return base, "sspanel"
    except Exception:
        pass
    return None


def detect_panel(hosts: list[str], timeout: int = 8) -> tuple[str, str] | None:
    """并发探测候选域名，返回第一个像面板的 (base_url, type)，优先 v2board。"""
    if not hosts:
        return None
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = [r for r in ex.map(lambda h: probe_panel(h, timeout), hosts) if r]
    for r in results:            # 优先 v2board
        if r[1] == "v2board":
            return r
    return results[0] if results else None


_BAD_HOST = ("google", "gstatic", "cloudflare", "jsdelivr", "bootcdn", "unpkg",
             "fontawesome", "font", "telegram", "t.me", "github", "youtube",
             "twitter", "x.com", "facebook", "gravatar", "w3.org", "schema.org",
             "abovedomains", "sedo", "cdn", "static", "analytics", "gtag",
             "baidu", "cloudflareinsights", "jquery", "bootstrapcdn",
             # 第三方客服/聊天挂件（会误判成面板）
             "crisp", "tawk", "zendesk", "intercom", "livechat", "meiqia",
             "udesk", "53kf", "sobot", "chatra", "tidio", "chatwoot", "hotjar")


def discover_panel(domains: list[str], timeout: int = 8) -> tuple[str, str] | None:
    """seed 域名直探无果时：抓官网页面 HTML，提取候选域名（登录/用户中心链接
    常指向真实后台），再逐个探测。返回 (base_url, type) 或 None。"""
    cands: set[str] = set()
    for d in domains:
        try:
            r = requests.get(_norm(d), headers={"User-Agent": _UA_BROWSER},
                             timeout=timeout, verify=False, allow_redirects=True)
        except Exception:
            continue
        # 落地页里出现的所有主机名 + 跳转后的最终域名
        for h in re.findall(r'https?://([a-zA-Z0-9.\-]+)', r.text):
            cands.add(h.lower().rstrip("."))
        if r.url:
            m = re.match(r'https?://([a-zA-Z0-9.\-]+)', r.url)
            if m:
                cands.add(m.group(1).lower())
    cands = [c for c in cands if "." in c and not any(b in c for b in _BAD_HOST)]
    # 优先与原域名同注册主域的候选（更可能是自家后台）
    roots = {".".join(d.replace("https://", "").replace("http://", "")
                      .split("/")[0].split(".")[-2:]) for d in domains}
    cands.sort(key=lambda c: 0 if any(c.endswith(r) for r in roots) else 1)
    return detect_panel(cands[:20], timeout)


def fetch_subscription(url: str, user_agent: str = "clash.meta",
                       timeout: int = 30) -> tuple[str, dict]:
    """用 Clash UA 抓订阅内容，返回 (text, 关键响应头)。5xx / SSL / 连接错误重试。"""
    import time
    r = None
    for attempt in range(3):
        try:
            r = requests.get(url, headers={"User-Agent": user_agent},
                             timeout=timeout, verify=False)
        except requests.RequestException as e:      # SSL/连接抖动（如 mojie 的 sub 服务器）
            if attempt < 2:
                time.sleep(2)
                continue
            raise
        if r.status_code < 500:
            break
        if attempt < 2:
            time.sleep(2)
    r.raise_for_status()
    meta = {h: r.headers[h] for h in
            ("subscription-userinfo", "profile-update-interval") if h in r.headers}
    return r.text, meta
