@echo off
setlocal
cd /d E:\Hermes-Agent\Jichang-Monitor
set HTTP_PROXY=http://[::1]:7890
set HTTPS_PROXY=http://[::1]:7890
set PYTHONIOENCODING=utf-8
if "%~1"=="" (echo 用法: test_airport.bat ^<slug^>  [例如 ayucloud / qingyunti] & exit /b 2)
echo === 先按订阅拉取: %~1 ===
python -X utf8 run.py pull --airport %~1 -v
echo.
echo === 若上面没拿到节点，按客户端内存扫描再试一次 ===
python -X utf8 run.py scan-memory --airport %~1
echo.
echo === 完成后记得跑全量导出恢复 index.json ===
echo   python -X utf8 -m airmon.nodeset
