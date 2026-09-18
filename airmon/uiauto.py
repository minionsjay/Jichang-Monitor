"""Windows UI 自动登录采集辅助 — 解决"客户端停在登录页"的自动化断点。

背景（2026-09-16 实测）：
  QQT(全球通) 客户端登录页只"记住账号"(remember_email)，**不保存密码**，
  每次启动都停在登录页 → 无法自动登录 → 内存里只有 4 个 backendapi 域名，
  scan-memory 拿不到节点。

  根因不是客户端坏了，而是缺一步"输密码"。本模块用 Win32 API 模拟：
    1. 强制前台（Alt 键技巧 + GetForegroundWindow 验证 —— 直接
       SetForegroundWindow 会被 Windows 拒绝且**无报错**，密码会打进别的窗口）
    2. 点击密码输入框 → Ctrl+A 清空 → SendInput(UNICODE) 逐字符输入
    3. 点击"登录"按钮（3 种布局位移盲试）
    4. 点击"启动安全连接"（QQT 登录后 auto_connect 不会自动触发）

  **为什么是"盲操作"而不是截屏识别**（三种截屏方案全踩坑）：
    - PrintWindow(PW_RENDERFULLCONTENT): 对 QQT(Flutter/ANGLE) 状态依赖大，
      部分时候返回全白（即使返回成功）
    - BitBlt 屏幕截图: 硬件叠加层(MPO)渲染时截到白色，但用户屏幕显示正常
    - UI Automation: Flutter 语义树未启用，只暴露一个空 Pane
  → 固定坐标 + 前台强验证，登录成功与否由 _do_scan_memory 的内存扫描
    循环天然判定（登录后内存条目 ~13 → ~2000+，节点 4 → 40+）。

  依赖：仅 Windows + ctypes（无 PIL/pywinauto/easyocr）。
  坐标基于 QQT 1000x720 固定窗口布局。

用法（由 run.py 的 _do_scan_memory 在 ui_login 配置时调用）：
    from airmon.uiauto import qqt_login_and_connect
    qqt_login_and_connect(password="...", exe_path=r"E:\\...\\qqt.exe")
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Win32 基础
# ---------------------------------------------------------------------------

_IS_WIN = sys.platform == "win32" or os.name == "nt"

if _IS_WIN:
    import ctypes.wintypes as wt

    _user32 = ctypes.windll.user32
    _kernel32 = ctypes.windll.kernel32
    _gdi32 = ctypes.windll.gdi32
    _user32.SetProcessDPIAware()

    # 64 位下句柄是 64 位指针，ctypes 默认 int 返回会被截断 → 显式声明
    _H = ctypes.c_void_p
    _user32.GetWindowDC.restype = _H
    _user32.GetWindowDC.argtypes = [_H]
    _user32.GetDC.restype = _H
    _user32.GetDC.argtypes = [_H]
    _user32.ReleaseDC.argtypes = [_H, _H]
    _user32.SetForegroundWindow.argtypes = [_H]
    _user32.GetForegroundWindow.restype = _H
    _user32.PrintWindow.argtypes = [_H, _H, wt.UINT]
    _user32.SetCursorPos.argtypes = [wt.INT, wt.INT]
    _gdi32.CreateCompatibleDC.restype = _H
    _gdi32.CreateCompatibleDC.argtypes = [_H]
    _gdi32.CreateDIBSection.restype = _H
    # 注意: GDI 句柄是符号扩展的32位值(c_void_p 返回大无符号数), 必须显式 argtypes
    _gdi32.CreateDIBSection.argtypes = [_H, ctypes.c_void_p, wt.UINT,
                                        ctypes.POINTER(ctypes.c_void_p),
                                        ctypes.c_void_p, wt.DWORD]
    _gdi32.SelectObject.restype = _H
    _gdi32.SelectObject.argtypes = [_H, _H]
    _gdi32.BitBlt.argtypes = [_H, wt.INT, wt.INT, wt.INT, wt.INT, _H,
                              wt.INT, wt.INT, wt.DWORD]
    _gdi32.DeleteObject.argtypes = [_H]
    _gdi32.DeleteDC.argtypes = [_H]

    INPUT_KEYBOARD = 1
    KEYEVENTF_KEYUP = 0x0002
    KEYEVENTF_UNICODE = 0x0004
    VK_CONTROL = 0x11
    VK_MENU = 0x12  # Alt

    class _RECT(ctypes.Structure):
        _fields_ = [("Left", ctypes.c_long), ("Top", ctypes.c_long),
                    ("Right", ctypes.c_long), ("Bottom", ctypes.c_long)]

    class _KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD),
                    ("time", wt.DWORD), ("dwExtraInfo", ctypes.POINTER(wt.ULONG))]

    class _INPUT(ctypes.Structure):
        class _U(ctypes.Union):
            _fields_ = [("ki", _KEYBDINPUT)]
        _fields_ = [("type", wt.DWORD), ("union", _U)]

    WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def _win():
    if not _IS_WIN:
        raise RuntimeError("uiauto 仅支持 Windows")
    return _user32


def find_window_by_title(title: str, exe_name: str | None = None) -> int:
    """按窗口标题找可见顶层窗口，返回 hwnd（0=未找到）。"""
    u = _win()
    found = ctypes.c_void_p(0)

    @WNDENUMPROC
    def cb(hwnd, _l):
        if u.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(256)
            u.GetWindowTextW(hwnd, buf, 256)
            if buf.value == title:
                found.value = hwnd
                return False
        return True

    u.EnumWindows(cb, 0)
    return found.value or 0


def get_window_rect(hwnd: int) -> tuple[int, int, int, int]:
    r = _RECT()
    _win().GetWindowRect(hwnd, ctypes.byref(r))
    return r.Left, r.Top, r.Right, r.Bottom


# ---------------------------------------------------------------------------
# 截图 + 像素分类
# ---------------------------------------------------------------------------

def shot_rgb(hwnd: int) -> tuple[int, int, bytearray]:
    """截取窗口内容，返回 (w, h, BGRA bytes)。

    实现说明（2026-09-16 实测教训）：
      - PrintWindow(PW_RENDERFULLCONTENT) 对 QQT(Flutter/ANGLE/D3D) 返回全白，
        即使返回值=成功 —— 放弃。
      - 改用屏幕 BitBlt（GetDC(0) + 窗口坐标）。要求窗口前台且未被遮挡，
        调用方必须先 force_foreground()。CAPTUREBLT 兼容分层窗口。
      - GDI 句柄是符号扩展的32位值 → 所有 gdi32 调用必须显式 argtypes（见文件头）。
    """
    u, g = _user32, _gdi32
    left, top, right, bottom = get_window_rect(hwnd)
    w, h = right - left, bottom - top
    if w <= 0 or h <= 0:
        return 0, 0, bytearray()

    class BMIH(ctypes.Structure):
        _fields_ = [("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG),
                    ("biPlanes", wt.WORD), ("biBitCount", wt.WORD),
                    ("biCompression", wt.DWORD), ("biSizeImage", wt.DWORD),
                    ("biXPelsPerMeter", wt.LONG), ("biYPelsPerMeter", wt.LONG),
                    ("biClrUsed", wt.DWORD), ("biClrImportant", wt.DWORD)]
    bmi = BMIH()
    bmi.biSize = ctypes.sizeof(BMIH)
    bmi.biWidth, bmi.biHeight = w, -h          # top-down
    bmi.biPlanes, bmi.biBitCount = 1, 32
    bmi.biCompression = 0

    hdc_screen = u.GetDC(None)
    hdc_mem = g.CreateCompatibleDC(hdc_screen)
    ppv = ctypes.c_void_p(0)
    dib = g.CreateDIBSection(hdc_mem, ctypes.byref(bmi), 0,
                             ctypes.byref(ppv), None, 0)
    if not dib or not ppv.value:
        g.DeleteDC(hdc_mem)
        u.ReleaseDC(None, hdc_screen)
        return 0, 0, bytearray()
    old = g.SelectObject(hdc_mem, dib)
    SRCCOPY = 0x00CC0020
    CAPTUREBLT = 0x40000000
    g.BitBlt(hdc_mem, 0, 0, w, h, hdc_screen, left, top, SRCCOPY | CAPTUREBLT)
    pixels = bytearray((ctypes.c_ubyte * (w * h * 4)).from_address(ppv.value))
    g.SelectObject(hdc_mem, old)
    g.DeleteObject(dib)
    g.DeleteDC(hdc_mem)
    u.ReleaseDC(None, hdc_screen)
    return w, h, pixels


def _px(buf: bytearray, w: int, x: int, y: int) -> tuple[int, int, int]:
    off = (y * w + x) * 4
    return buf[off + 2], buf[off + 1], buf[off]  # BGRA → RGB


def is_login_page(hwnd: int) -> bool:
    """登录页判别：y=540 行 x∈[200,800] 有近黑(rgb 全 <15)色块 ≥30px。

    实测：登录页该行是黑色"登录"按钮(x≈472-526)；主页该行是背景色(11,13,17)。
    """
    w, h, buf = shot_rgb(hwnd)
    if not w or h < 600:
        return False
    run = best = 0
    for x in range(200, min(800, w - 1)):
        r, g, b = _px(buf, w, x, 540)
        if r < 15 and g < 15 and b < 15:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best >= 30


def window_exists(hwnd: int) -> bool:
    return bool(_win().IsWindow(hwnd))


def restore_window(hwnd: int):
    """还原+前台化窗口。最小化/后台窗口的 PrintWindow 会截到空白。

    QQT 带托盘插件，被 taskkill 后新实例可能以最小化状态启动。
    """
    u = _win()
    SW_RESTORE = 9
    if u.IsIconic(hwnd):
        u.ShowWindow(hwnd, SW_RESTORE)
        time.sleep(0.6)


# ---------------------------------------------------------------------------
# 输入模拟
# ---------------------------------------------------------------------------

def _send_key(vk: int = 0, unicode_ch: str = "", up: bool = False):
    inp = _INPUT()
    inp.type = INPUT_KEYBOARD
    if unicode_ch:
        inp.union.ki.wVk = 0
        inp.union.ki.wScan = ord(unicode_ch)
        inp.union.ki.dwFlags = KEYEVENTF_UNICODE | (KEYEVENTF_KEYUP if up else 0)
    else:
        inp.union.ki.wVk = vk
        inp.union.ki.wScan = 0
        inp.union.ki.dwFlags = KEYEVENTF_KEYUP if up else 0
    _user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(_INPUT))


def type_text(text: str):
    """逐字符 UNICODE 输入（不经过键盘布局，任意字符可用）。"""
    for ch in text:
        _send_key(unicode_ch=ch, up=False)
        _send_key(unicode_ch=ch, up=True)
        time.sleep(0.01)


def select_all():
    _send_key(vk=VK_CONTROL)
    _send_key(vk=0x41)          # A
    _send_key(vk=0x41, up=True)
    _send_key(vk=VK_CONTROL, up=True)
    time.sleep(0.1)


def click(x: int, y: int, hold_ms: int = 60):
    u = _win()
    u.SetCursorPos(x, y)
    time.sleep(0.15)
    u.mouse_event(2, 0, 0, 0, 0)     # LEFTDOWN
    time.sleep(hold_ms / 1000)
    u.mouse_event(4, 0, 0, 0, 0)     # LEFTUP
    time.sleep(0.3)


def force_foreground(hwnd: int, tries: int = 3) -> bool:
    """Alt 技巧抢前台并验证（直接 SetForegroundWindow 常被静默拒绝）。"""
    u = _win()
    for _ in range(tries):
        _send_key(vk=VK_MENU); _send_key(vk=VK_MENU, up=True)  # Alt press/release
        time.sleep(0.15)
        u.SetForegroundWindow(hwnd)
        time.sleep(0.5)
        if u.GetForegroundWindow() == hwnd:
            return True
        # 兜底：点一下标题栏激活
        left, top, _, _ = get_window_rect(hwnd)
        click(left + 500, top + 15)
        time.sleep(0.5)
        if u.GetForegroundWindow() == hwnd:
            return True
    return u.GetForegroundWindow() == hwnd


def _click_rel(hwnd: int, dx: int, dy: int):
    left, top, _, _ = get_window_rect(hwnd)
    click(left + dx, top + dy)


# ---------------------------------------------------------------------------
# QQT 登录 + 连接
# ---------------------------------------------------------------------------

# QQT 1000x720 登录页布局（2026-09-16 实测, 相对窗口左上角）
_PWD_FIELD = (520, 397)     # 密码输入框（占位符"密码"所在行）
_LOGIN_BTN = (498, 540)     # "登录 >" 按钮
_CONNECT_BTN = (300, 440)   # 主页"启动安全连接"按钮
_LAYOUT_SHIFTS = (0, -36, 36)   # 布局位移重试（出现过 -36 的横幅位移）


def wait_window(title: str, timeout: int = 60) -> int:
    t0 = time.time()
    while time.time() - t0 < timeout:
        hwnd = find_window_by_title(title)
        if hwnd and window_exists(hwnd):
            return hwnd
        time.sleep(1.5)
    return 0


def blind_login_once(password: str, title: str = "QQT") -> bool:
    """单次盲登录尝试（点击密码框→Ctrl+A→输入→点登录）。

    供 _do_scan_memory 的扫描循环在检测到"未登录签名"（内存里只有
    backendapi 域名节点）时反复调用 —— 覆盖客户端启动慢/UI 迟到的情况。
    布局位移由内部轮转。
    """
    try:
        hwnd = find_window_by_title(title)
        if not hwnd:
            return False
        restore_window(hwnd)
        if not force_foreground(hwnd):
            return False
        dy = _LAYOUT_SHIFTS[blind_login_once._dy_idx % len(_LAYOUT_SHIFTS)]
        blind_login_once._dy_idx += 1
        _click_rel(hwnd, _PWD_FIELD[0], _PWD_FIELD[1] + dy)
        select_all()
        type_text(password)
        time.sleep(0.4)
        _click_rel(hwnd, _LOGIN_BTN[0], _LOGIN_BTN[1] + dy)
        time.sleep(1.0)
        return True
    except Exception:
        return False
blind_login_once._dy_idx = 0


def qqt_login_and_connect(password: str, exe_path: str | None = None,
                          title: str = "QQT", connect: bool = True) -> str:
    """完整流程（无视觉版）：(启动) → 等窗口 → 盲输密码+点登录(3种布局位移) → 点连接。

    为什么不用截屏判断页面状态（2026-09-16 实测教训）：
      - PrintWindow 对 QQT(Flutter/ANGLE) 某些状态下返回全白（即使返回成功）
      - BitBlt 屏幕截图在硬件叠加层(MPO)渲染时也截到白色（用户屏幕显示正常）
      → 放弃视觉反馈，改用"固定坐标盲操作 + 前台强验证"，登录是否成功
        由调用方(_do_scan_memory)的内存扫描循环天然判定（登录后内存条目
        从 ~13 涨到 ~2000+，节点从 0 涨到 40+）。

    固定坐标基于 QQT 1000x720 布局（多次实测稳定），_LAYOUT_SHIFTS 覆盖
    登录页偶发的 ±36px 横幅位移。盲试在主页上多点的位置均为空白区域，安全。

    返回: 'blind_done' / 'already_running' / 'failed'
    """
    try:
        hwnd = find_window_by_title(title)
        if not hwnd and exe_path and os.path.exists(exe_path):
            subprocess.Popen([exe_path], cwd=os.path.dirname(exe_path))
            hwnd = wait_window(title, timeout=60)
        if not hwnd:
            print("    [uiauto] QQT 窗口未出现")
            return "failed"
        restore_window(hwnd)
        if not force_foreground(hwnd):
            print("    [uiauto] ✗ 无法置前台(密码会输错窗口)，放弃")
            return "failed"
        time.sleep(10)  # 等 bootstrap 完成登录页可交互

        for dy in _LAYOUT_SHIFTS:
            restore_window(hwnd)
            if not force_foreground(hwnd):
                continue
            # 输密码
            _click_rel(hwnd, _PWD_FIELD[0], _PWD_FIELD[1] + dy)
            select_all()
            type_text(password)
            time.sleep(0.5)
            # 点登录
            _click_rel(hwnd, _LOGIN_BTN[0], _LOGIN_BTN[1] + dy)
            time.sleep(6)

        # "点连接"不在这里做 —— 由 _do_scan_memory 的扫描循环在观察到
        # 未登录→已登录跃迁时点击，避免误断开已连接的实例
        print("    [uiauto] 初始盲登录完成，由内存扫描循环验证并驱动后续重试")
        return "blind_done"
    except Exception as e:
        print(f"    [uiauto] 异常: {e}")
        return "failed"


def click_connect_button(title: str = "QQT") -> bool:
    """主页上点'启动安全连接'。供扫描循环在 0 节点时兜底调用。"""
    try:
        hwnd = find_window_by_title(title)
        if not hwnd:
            return False
        _click_rel(hwnd, _CONNECT_BTN[0], _CONNECT_BTN[1])
        return True
    except Exception:
        return False


def graceful_shutdown(title: str = "QQT", core_process: str = "QQT",
                      gui_process: str = "qqt"):
    """优雅关闭：先断开连接 → WM_CLOSE 关 GUI → 超时才强杀。

    2026-09-16 教训：对"已连接"的 QQT 直接 taskkill /F 会让 wintun/内核
    状态悬挂，下次启动可能出现白屏/异常退出。断开+正常关闭可避免。
    """
    import subprocess as sp
    try:
        hwnd = find_window_by_title(title)
        if hwnd:
            _click_rel(hwnd, _CONNECT_BTN[0], _CONNECT_BTN[1])  # 断开(同一按钮)
            time.sleep(2)
            # WM_CLOSE 优雅关闭
        _user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
        time.sleep(5)
        # 还活着 → taskkill(不带/F, 再给一次WM_CLOSE)
        for name in (gui_process, core_process):
            r = sp.run(["tasklist", "/FI", f"IMAGENAME eq {name}.exe", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True, timeout=10)
            if name.lower() in (r.stdout or "").lower():
                sp.run(["taskkill", "/IM", f"{name}.exe"], capture_output=True, timeout=10)
        time.sleep(3)
        # 最后一招
        for name in (gui_process, core_process):
            sp.run(["taskkill", "/F", "/IM", f"{name}.exe"], capture_output=True, timeout=10)
    except Exception:
        pass
