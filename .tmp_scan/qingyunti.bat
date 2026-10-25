@echo off
cd /d "E:\Hermes-Agent\Jichang-Monitor"
"C:\Users\minions\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe" -X utf8 run.py scan-memory --airport qingyunti > "E:\Hermes-Agent\Jichang-Monitor\.tmp_scan\qingyunti.log" 2>&1
