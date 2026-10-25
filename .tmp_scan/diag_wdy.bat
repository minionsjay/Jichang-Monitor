@echo off
cd /d E:\Hermes-Agent\Jichang-Monitor
set PYTHONIOENCODING=utf-8
python -X utf8 .tmp_ver\diag_wdy.py > .tmp_scan\wdy_diag.log 2>&1
exit /b %ERRORLEVEL%