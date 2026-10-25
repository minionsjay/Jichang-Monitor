try {
  $p = Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','E:\Hermes-Agent\Jichang-Monitor\.tmp_scan\set6h.ps1' -Verb RunAs -PassThru -WindowStyle Hidden -ErrorAction Stop
  Write-Output ("spawned pid=" + $p.Id + " : a UAC prompt needs your approval")
  $null = $p.WaitForExit(40000)
  Write-Output ("exited=" + $p.HasExited)
} catch {
  Write-Output ("UAC_FAIL: " + $_.Exception.Message)
}
