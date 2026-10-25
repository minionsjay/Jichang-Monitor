@echo off
cd /d E:\Hermes-Agent\Jichang-Monitor
set HTTP_PROXY=http://[::1]:7890
set HTTPS_PROXY=http://[::1]:7890
set PYTHONIOENCODING=utf-8
python -X utf8 run.py scan-memory --airport wdy -v > .tmp_scan\wdy2.log 2>&1
exit /b %ERRORLEVEL%