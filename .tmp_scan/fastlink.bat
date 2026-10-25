@echo off
set HTTP_PROXY=http://127.0.0.1:10808
set HTTPS_PROXY=http://127.0.0.1:10808
cd /d "E:\Hermes-Agent\Jichang-Monitor"
"C:\Users\minions\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe" -X utf8 run.py scan-memory --airport fastlink > "E:\Hermes-Agent\Jichang-Monitor\.tmp_scan\fastlink.log" 2>&1
