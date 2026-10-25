$ErrorActionPreference = "Stop"
$t = Get-ScheduledTask -TaskName "JichangMonitor"
$trg = $t.Triggers[0]
$trg.Repetition.Interval = "PT6H"
$trg.Repetition.Duration = "P365D"
Set-ScheduledTask -TaskName "JichangMonitor" -Trigger $trg | Out-Null
$t2 = Get-ScheduledTask -TaskName "JichangMonitor"
$info = Get-ScheduledTaskInfo -TaskName "JichangMonitor"
$out = "after=" + $t2.Triggers[0].Repetition.Interval + " next=" + $info.NextRunTime
Set-Content -Path "E:\Hermes-Agent\Jichang-Monitor\.tmp_scan\set6h.result.txt" -Value $out -Encoding ASCII
