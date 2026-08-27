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
    """返回 (subscribe_url, auth_data)。失败抛 LoginError。

    支持标准v2board (/api/v1/passport/auth/login) 和 Xboard分支
    (/api/v1/identity/auth/login)，Xboard需 Bearer token。
    """
    base = _norm(panel)
    s = requests.Session()
    s.headers.update({"User-Agent": _UA_BROWSER, "Content-Type": "application/json"})

    # 尝试两种登录路径：标准v2board → Xboard
    for login_path, token_field in [
        ("/api/v1/passport/auth/login", "auth_data"),  # 标准v2board
        ("/api/v1/identity/auth/login", "token"),      # Xboard分支
    ]:
        try:
            r = s.post(f"{base}{login_path}",
                       json={"email": email, "password": password},
                       timeout=timeout, verify=False)
        except requests.RequestException as e:
            raise LoginError(f"登录请求失败: {e}")

        if r.status_code == 403 or "cf-mitigated" in {k.lower() for k in r.headers}:
            raise LoginError("被 Cloudflare/反爬拦截(可能需验证码)")
        # 检查是否是JSON（content-type可能标text/html但body是JSON）
        ct = r.headers.get("content-type", "")
        body = r.text[:512]
        if "json" not in ct and not body.lstrip().startswith("{"):
            continue  # 不是JSON，试下一个路径
        try:
            data = r.json()
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        d = data.get("data")
        d = d if isinstance(d, dict) else {}
        auth = d.get(token_field) or d.get("auth_data") or d.get("token")
        if not auth:
            msg = data.get("message") or data.get("errors") or r.text[:120]
            raise LoginError(f"登录被拒: {msg}")
        # 成功拿到auth
        sub, _ = _v2board_get_subscribe(base, auth, s, timeout)
        return sub, auth

    raise LoginError("非 v2board/Xboard 响应(两种登录路径都失败)")


def _v2board_get_subscribe(base: str, auth: str, session: requests.Session,
                           timeout: int = 25) -> tuple[str, str]:
    """取订阅链接。支持标准v2board和Xboard(Bearer token)。"""
    # 标准v2board: Authorization: <auth_data>
    # Xboard: Authorization: Bearer <token>
    for header_fmt, sub_path in [
        (f"{auth}", "/api/v1/user/getSubscribe"),           # 标准v2board
        (f"Bearer {auth}", "/api/v1/user/subscribe"),        # Xboard
    ]:
        try:
            r2 = session.get(f"{base}{sub_path}",
                             headers={"Authorization": header_fmt},
                             timeout=timeout, verify=False)
            j2 = r2.json()
            dd = j2.get("data") if isinstance(j2, dict) else None
            sub = dd.get("subscribe_url") if isinstance(dd, dict) else None
            if sub:
                return sub, auth
        except (requests.RequestException, ValueError):
            continue
    raise LoginError(f"登录成功但未拿到 subscribe_url")


def v2board_server_fetch(panel: str, email: str, password: str,
                         timeout: int = 25) -> tuple[list[dict], str]:
    """登录后调 /api/v1/user/server/fetch 直接拿节点列表（绕过订阅URL的客户端检测）。

    返回 (servers, auth_data)。servers 是 v2board 原始节点数组。
    订阅URL可能对非官方客户端返回占位节点(1.1.1.1)，但 server/fetch API
    只要登录就能拿到真实节点。"""
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

    d = data.get("data") if isinstance(data, dict) else {}
    d = d if isinstance(d, dict) else {}
    auth = d.get("auth_data") or d.get("token")
    if not auth:
        msg = data.get("message") or data.get("errors") or r.text[:120]
        raise LoginError(f"登录被拒: {msg}")

    try:
        r2 = s.get(f"{base}/api/v1/user/server/fetch",
                   headers={"Authorization": auth}, timeout=timeout, verify=False)
        j2 = r2.json()
        servers = j2.get("data") if isinstance(j2, dict) else None
    except (requests.RequestException, ValueError) as e:
        raise LoginError(f"取节点失败: {e}")
    if not servers:
        raise LoginError(f"登录成功但 server/fetch 返回空: {str(j2)[:150]}")
    return servers, auth


def sspanel_login(panel: str, email: str, password: str,
                  timeout: int = 25) -> tuple[str, None]:
    """SSPanel-uim：cookie 会话登录 → 从 /user 页抠订阅链接 /link/<token>。

    字段是 passwd（非 password）；成功 JSON {"ret":1}。
    标准路径 /auth/login，部分面板用 /user/login（Malio 主题等）。
    """
    base = _norm(panel)
    s = requests.Session()
    s.headers.update({"User-Agent": _UA_BROWSER,
                      "X-Requested-With": "XMLHttpRequest"})

    # 先试标准路径 /auth/login，失败试 /user/login
    for login_path in ("/auth/login", "/user/login"):
        try:
            r = s.post(f"{base}{login_path}",
                       data={"email": email, "passwd": password,
                             "code": "", "remember_me": "week"},
                       timeout=timeout, verify=False)
        except requests.RequestException as e:
            raise LoginError(f"登录请求失败: {e}")

        # 检查是否是JSON（有些面板content-type标text/html但body是JSON）
        ct = r.headers.get("content-type", "")
        body = r.text[:512]
        if "json" not in ct and not body.lstrip().startswith("{"):
            continue  # 不是JSON，试下一个路径

        try:
            j = r.json()
        except ValueError:
            continue

        if not isinstance(j, dict):
            continue
        if j.get("ret") != 1:
            msg = j.get("msg") or j.get("message") or "登录被拒"
            if any(k in str(msg) for k in ("验证码", "captcha", "code")):
                raise LoginError(f"需验证码: {msg}")
            raise LoginError(f"登录被拒: {msg}")
        break  # 登录成功
    else:
        raise LoginError(f"非 SSPanel 响应: /auth/login 和 /user/login 都返回非JSON")

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


def whmcs_login(panel: str, email: str, password: str,
                timeout: int = 25) -> tuple[str, None]:
    """WHMCS 面板登录：GET /login 抓 CSRF token → POST /login → 从产品详情页抠订阅链接。

    WHMCS 用 Lagom 等主题，表单字段是 username/password/token(CSRF)。
    订阅链接在 clientarea.php?action=productdetails&id=xxx 页面里。
    """
    base = _norm(panel)
    s = requests.Session()
    s.headers.update({"User-Agent": _UA_BROWSER})

    # 1. GET /login 抓 CSRF token
    try:
        r = s.get(f"{base}/login", timeout=timeout, verify=False)
    except requests.RequestException as e:
        raise LoginError(f"获取登录页失败: {e}")
    m = re.search(r'name=["\']token["\']\s+value=["\']([^"\']+)', r.text)
    if not m:
        raise LoginError("登录页未找到 CSRF token（可能不是 WHMCS）")
    csrf = m.group(1)

    # 2. POST /login
    try:
        r2 = s.post(f"{base}/login", data={
            "token": csrf,
            "username": email,
            "password": password,
            "rememberme": "on",
        }, timeout=timeout, verify=False, allow_redirects=False)
    except requests.RequestException as e:
        raise LoginError(f"登录请求失败: {e}")
    if r2.status_code not in (301, 302):
        raise LoginError(f"登录失败: HTTP {r2.status_code}（非302跳转）")
    if "WHMCS" not in str(s.cookies.keys()) and "login_auth" not in str(s.cookies.keys()):
        raise LoginError("登录后未获取到 WHMCS cookie")

    # 3. 从 clientarea.php 找产品列表
    try:
        r3 = s.get(f"{base}/clientarea.php", timeout=timeout, verify=False)
    except requests.RequestException as e:
        raise LoginError(f"取客户区失败: {e}")
    products = re.findall(r'clientarea\.php\?action=productdetails&id=(\d+)', r3.text)
    if not products:
        raise LoginError("登录成功但未找到产品（可能无订阅或已过期）")

    # 4. 逐个产品页找订阅链接
    for pid in products[:5]:
        try:
            r4 = s.get(f"{base}/clientarea.php?action=productdetails&id={pid}",
                       timeout=timeout, verify=False)
        except Exception:
            continue
        # 搜订阅URL（多种格式）
        for pattern in [
            r'(https?://[a-z0-9.-]+/subscribe/[A-Za-z0-9/]+)',
            r'(https?://[a-z0-9.-]+/link/[A-Za-z0-9]+)',
            r'(https?://[a-z0-9.-]+/api/v1/client/subscribe\?token=[A-Za-z0-9]+)',
        ]:
            m2 = re.search(pattern, r4.text, re.I)
            if m2:
                return m2.group(1), None
        # 也搜页面里的任意外部订阅链接
        all_urls = re.findall(r'https?://[a-z0-9.-]+\.[a-z]{2,}[^\s"\'<>]*', r4.text, re.I)
        for u in all_urls:
            if any(kw in u.lower() for kw in ["subscribe", "/sub?", "clashsub"]):
                return u, None

    raise LoginError("登录成功但未在产品页找到订阅链接")


def xlcc_login(panel: str, email: str, password: str,
               timeout: int = 15) -> tuple[str, str]:
    """飞鸟加速(XLCC)面板登录。返回 (subscribe_url, session_cookie)。

    面板特征（SSR 渲染页，非标准 SSPanel/v2board）：
      POST /passport/login  {account, password, remember_me, code}  → ret==1
      POST /user/sub        {}                                       → data.sub_prefix（一次性token）

    订阅链接是一次性的：每次 POST /user/sub 生成新 token 并立即作废旧 token，
    且该链接拉取一次后即失效。所以登录+取链接+拉节点必须连续完成。

    subscribe_url 形如:
      https://curr.5ysdejn.xyz{sub_prefix}/csh/%E9%A3%9E%E9%B8%9F%E5%8A%A0%E9%80%9F?route=0
    """
    base = _norm(panel)
    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": _UA_BROWSER})

    # 登录
    try:
        r = s.post(f"{base}/passport/login", data={
            "account": email,
            "password": password,
            "remember_me": True,
            "code": "",
        }, timeout=timeout)
    except requests.RequestException as e:
        raise LoginError(f"登录请求失败: {e}")

    try:
        j = r.json()
    except ValueError:
        raise LoginError(f"非 XLCC 响应(/passport/login 返回非JSON): {r.text[:120]}")

    if j.get("ret") != 1:
        raise LoginError(f"登录被拒: {j.get('msg', r.text[:120])}")

    # 取一次性订阅 token
    try:
        r2 = s.post(f"{base}/user/sub", data={}, timeout=timeout)
        j2 = r2.json()
    except (requests.RequestException, ValueError) as e:
        raise LoginError(f"取订阅链接失败(/user/sub): {e}")

    if j2.get("ret") != 1:
        raise LoginError(f"取订阅链接被拒: {j2.get('msg', '')}")

    sub_prefix = (j2.get("data") or {}).get("sub_prefix", "")
    if not sub_prefix:
        raise LoginError(f"登录成功但未拿到 sub_prefix: {str(j2)[:150]}")

    # 订阅域名: 优先从面板页面的 subHost 单选框读（curr.5ysdejn.xyz 等）
    sub_host = "https://curr.5ysdejn.xyz"
    try:
        r3 = s.get(f"{base}/user", timeout=timeout)
        m = re.search(r'name="subHost"\s+value="(https?://[^"]+)"', r3.text)
        if m:
            sub_host = m.group(1)
    except requests.RequestException:
        pass  # 用默认域名兜底

    # csh=clash格式; 飞鸟加速 URL-encoded 名称; route=0
    from urllib.parse import quote
    sub_url = f"{sub_host}{sub_prefix}/csh/{quote('飞鸟加速')}?route=0"
    cookie = "; ".join(f"{k}={v}" for k, v in s.cookies.get_dict().items())
    return sub_url, cookie


def smart_login(panel: str, email: str, password: str,
                ptype: str = "auto") -> tuple[str, str, str]:
    """按面板类型登录。返回 (subscribe_url, auth, 识别到的类型)。

    ptype: v2board / sspanel / whmcs / xlcc / auto（逐个试）。
    """
    if ptype == "v2board":
        sub, auth = v2board_login(panel, email, password)
        return sub, auth, "v2board"
    if ptype == "sspanel":
        sub, auth = sspanel_login(panel, email, password)
        return sub, auth, "sspanel"
    if ptype == "whmcs":
        sub, auth = whmcs_login(panel, email, password)
        return sub, auth, "whmcs"
    if ptype == "xlcc":
        sub, auth = xlcc_login(panel, email, password)
        return sub, auth, "xlcc"
    # auto: v2board → sspanel → whmcs → xlcc
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
    try:
        sub, auth = whmcs_login(panel, email, password)
        return sub, auth, "whmcs"
    except LoginError as e:
        errors.append(f"whmcs:{e}")
    try:
        sub, auth = xlcc_login(panel, email, password)
        return sub, auth, "xlcc"
    except LoginError as e:
        errors.append(f"xlcc:{e}")
    raise LoginError(" | ".join(errors))


def probe_panel(host: str, timeout: int = 8) -> tuple[str, str] | None:
    """探测单个域名是不是可登录的面板。返回 (base_url, type) 或 None。"""
    base = _norm(host)
    # 先试 v2board
    try:
        r = requests.post(f"{base}/api/v1/passport/auth/login",
                          json={"email": "", "password": ""},
                          headers={"User-Agent": _UA_BROWSER},
                          timeout=timeout, verify=False, allow_redirects=False)
        # content-type 可能是 application/json 也可能误标为 text/html，
        # 所以除了看 header 还尝试直接 parse body。
        ct = r.headers.get("content-type", "")
        body_text = r.text[:512]
        if "json" in ct or body_text.lstrip().startswith("{"):
            try:
                j = r.json()
                if isinstance(j, dict) and any(k in j for k in ("message", "errors", "data")):
                    return base, "v2board"
            except ValueError:
                pass
    except Exception:
        pass
    # 再试 SSPanel
    try:
        r = requests.post(f"{base}/auth/login",
                          data={"email": "", "passwd": "", "code": ""},
                          headers={"User-Agent": _UA_BROWSER,
                                   "X-Requested-With": "XMLHttpRequest"},
                          timeout=timeout, verify=False, allow_redirects=False)
        ct = r.headers.get("content-type", "")
        body_text = r.text[:512]
        if "json" in ct or body_text.lstrip().startswith("{"):
            try:
                j = r.json()
                if isinstance(j, dict) and "ret" in j:
                    return base, "sspanel"
            except ValueError:
                pass
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
