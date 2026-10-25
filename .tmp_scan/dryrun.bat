@echo off
cd /d E:\Hermes-Agent\Jichang-Monitor
set PYTHONIOENCODING=utf-8
rem Proxy is auto-detected inside run.py (Clash 7890 / v2rayN 10808 / ...).
rem See airmon\netcfg.py. Do not hardcode a port here.
rem Mark this round as scheduled (run.py writes it into data/runs.json).
set AIRMON_TRIGGER=scheduled
rem Rotate run.log when it exceeds 20MB (only safe while nobody holds it open).
python -m airmon.prune --runlog >> nul 2>&1
echo [dry-run] separator line
echo [dry-run] would start: python run.py all -v --trigger scheduled
set RC=%ERRORLEVEL%
echo [exit=%RC%] %date% %time% === >> run.log
exit /b %RC%
