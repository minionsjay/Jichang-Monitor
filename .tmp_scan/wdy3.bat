@echo off
cd /d E:\Hermes-Agent\Jichang-Monitor
set HTTP_PROXY=http://[::1]:7890
set HTTPS_PROXY=http://[::1]:7890
set PYTHONIOENCODING=utf-8
python -X utf8 run.py scan-memory --airport wdy > .tmp_scan\wdy3.log 2>&1
exit /b %ERRORLEVEL%