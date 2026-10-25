@echo off
cd /d "E:\Hermes-Agent\Jichang-Monitor"
"C:\Users\minions\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe" -X utf8 run.py scan-memory --airport wdy > "E:\Hermes-Agent\Jichang-Monitor\.tmp_scan\wdy.log" 2>&1
