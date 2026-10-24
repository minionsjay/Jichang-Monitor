# 以管理员权限重扫某个客户端型机场的内存
#
# 为什么需要它：从客户端内核进程读内存要 OpenProcess(PROCESS_VM_READ)，
# 而 dovex / lingdian / wandacloud 这类内核常常以更高权限运行，
# 普通权限的 python 会拿到 error 5（需要管理员权限）。
#
# 用法（会弹一次 UAC，点「是」）：
#   powershell -ExecutionPolicy Bypass -File tools\elevated_scan.ps1 -Slug qingyunti
#
# 扫描结果照常写到 data\<slug>\<时间戳>.json，面板刷新即可看到。

param(
    [Parameter(Mandatory = $true)][string]$Slug,
    [string]$Root = "E:\Hermes-Agent\Jichang-Monitor"
)

$ErrorActionPreference = "Stop"

$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { throw "找不到 python，请确认它在 PATH 里" }

Write-Host "以管理员身份扫描 $Slug ..."
$args = @("-X", "utf8", "run.py", "scan-memory", "--airport", $Slug)
$p = Start-Process -FilePath $py -ArgumentList $args -WorkingDirectory $Root -Verb RunAs -PassThru -Wait
Write-Host ("退出码: " + $p.ExitCode)
if ($p.ExitCode -ne 0) { Write-Host "扫描未成功，看窗口里的提示（通常是没有客户端在运行）" }
