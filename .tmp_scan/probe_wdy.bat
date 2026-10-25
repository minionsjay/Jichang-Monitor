@echo off
cd /d E:\Hermes-Agent\Jichang-Monitor
set PYTHONIOENCODING=utf-8
python -X utf8 .tmp_ver\probe_wdy_mem.py > .tmp_scan\wdy_mem.log 2>&1
exit /b %ERRORLEVEL%