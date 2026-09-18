Add-Type -AssemblyName System.Windows.Forms
Add-Type '
using System;
using System.Runtime.InteropServices;
public class WVL {
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint data, UIntPtr extra);
  [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint f, UIntPtr extra);
  public struct RECT { public int Left, Top, Right, Bottom; }
}'
[WVL]::SetProcessDPIAware() | Out-Null
$h = (Get-Process Velochron | Select-Object -First 1).MainWindowHandle
if ($h -eq [IntPtr]::Zero) { Write-Output "ERR no window"; exit 1 }
$r = New-Object WVL+RECT
[WVL]::GetWindowRect($h, [ref]$r) | Out-Null
Write-Output ("rect: " + $r.Left + "," + $r.Top)
# Alt trick + foreground
[WVL]::keybd_event(0x12,0,0,[UIntPtr]::Zero); [WVL]::keybd_event(0x12,0,2,[UIntPtr]::Zero)
[WVL]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 700
if ([WVL]::GetForegroundWindow() -ne $h) { Write-Output "WARN foreground fail" }
function ClickRel([int]$dx, [int]$dy) {
  [WVL]::SetCursorPos($r.Left + $dx, $r.Top + $dy) | Out-Null
  Start-Sleep -Milliseconds 150
  [WVL]::mouse_event(2,0,0,0,[UIntPtr]::Zero); [WVL]::mouse_event(4,0,0,0,[UIntPtr]::Zero)
  Start-Sleep -Milliseconds 350
}
# 1. 邮箱框 (590,335)
ClickRel 590 335
[System.Windows.Forms.SendKeys]::SendWait("211268240@qq.com")
Start-Sleep -Milliseconds 400
# 2. 密码框 (590,381)
ClickRel 590 381
[System.Windows.Forms.SendKeys]::SendWait("qwerhjkl123...")
Start-Sleep -Milliseconds 500
# 3. 登录按钮 (694,453)
ClickRel 694 453
Write-Output "login clicked"
