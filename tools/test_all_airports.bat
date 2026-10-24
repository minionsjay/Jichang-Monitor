@echo off
setlocal enabledelayedexpansion
cd /d E:\Hermes-Agent\Jichang-Monitor
set HTTP_PROXY=http://[::1]:7890
set HTTPS_PROXY=http://[::1]:7890
set PYTHONIOENCODING=utf-8
if not exist reports mkdir reports
set LOG=reports\手动逐家-%date:~0,4%%date:~5,2%%date:~8,2%-%time:~0,2%%time:~3,2%.log
set LOG=!LOG: =0!
echo === 逐家测试开始 %date% %time% === > !LOG!
echo 日志: !LOG!
echo. >> !LOG!
echo ======== applegame ======== >> !LOG!
python -X utf8 run.py pull --airport applegame -v >> !LOG! 2>&1
echo [applegame done] %time%
echo. >> !LOG!
echo ======== ayucloud ======== >> !LOG!
python -X utf8 run.py pull --airport ayucloud -v >> !LOG! 2>&1
echo [ayucloud done] %time%
echo. >> !LOG!
echo ======== bygcloud ======== >> !LOG!
python -X utf8 run.py pull --airport bygcloud -v >> !LOG! 2>&1
echo [bygcloud done] %time%
echo. >> !LOG!
echo ======== bywave ======== >> !LOG!
python -X utf8 run.py pull --airport bywave -v >> !LOG! 2>&1
echo [bywave done] %time%
echo. >> !LOG!
echo ======== chaoyue ======== >> !LOG!
python -X utf8 run.py pull --airport chaoyue -v >> !LOG! 2>&1
echo [chaoyue done] %time%
echo. >> !LOG!
echo ======== cherryvpn ======== >> !LOG!
python -X utf8 run.py pull --airport cherryvpn -v >> !LOG! 2>&1
echo [cherryvpn done] %time%
echo. >> !LOG!
echo ======== cloudnx ======== >> !LOG!
python -X utf8 run.py pull --airport cloudnx -v >> !LOG! 2>&1
echo [cloudnx done] %time%
echo. >> !LOG!
echo ======== dovex ======== >> !LOG!
python -X utf8 run.py scan-memory --airport dovex >> !LOG! 2>&1
echo [dovex done] %time%
echo. >> !LOG!
echo ======== dualnet ======== >> !LOG!
python -X utf8 run.py pull --airport dualnet -v >> !LOG! 2>&1
echo [dualnet done] %time%
echo. >> !LOG!
echo ======== everlife ======== >> !LOG!
python -X utf8 run.py pull --airport everlife -v >> !LOG! 2>&1
echo [everlife done] %time%
echo. >> !LOG!
echo ======== fastlink ======== >> !LOG!
python -X utf8 run.py scan-memory --airport fastlink >> !LOG! 2>&1
echo [fastlink done] %time%
echo. >> !LOG!
echo ======== feiniao ======== >> !LOG!
python -X utf8 run.py pull --airport feiniao -v >> !LOG! 2>&1
echo [feiniao done] %time%
echo. >> !LOG!
echo ======== feiniao_1 ======== >> !LOG!
python -X utf8 run.py pull --airport feiniao_1 -v >> !LOG! 2>&1
echo [feiniao_1 done] %time%
echo. >> !LOG!
echo ======== flybar ======== >> !LOG!
python -X utf8 run.py pull --airport flybar -v >> !LOG! 2>&1
echo [flybar done] %time%
echo. >> !LOG!
echo ======== flyint ======== >> !LOG!
python -X utf8 run.py pull --airport flyint -v >> !LOG! 2>&1
echo [flyint done] %time%
echo. >> !LOG!
echo ======== hhy ======== >> !LOG!
python -X utf8 run.py scan-memory --airport hhy >> !LOG! 2>&1
echo [hhy done] %time%
echo. >> !LOG!
echo ======== hsyun ======== >> !LOG!
python -X utf8 run.py pull --airport hsyun -v >> !LOG! 2>&1
echo [hsyun done] %time%
echo. >> !LOG!
echo ======== jinglingxueyuan ======== >> !LOG!
python -X utf8 run.py pull --airport jinglingxueyuan -v >> !LOG! 2>&1
echo [jinglingxueyuan done] %time%
echo. >> !LOG!
echo ======== jsqpro ======== >> !LOG!
python -X utf8 run.py pull --airport jsqpro -v >> !LOG! 2>&1
echo [jsqpro done] %time%
echo. >> !LOG!
echo ======== ktm ======== >> !LOG!
python -X utf8 run.py pull --airport ktm -v >> !LOG! 2>&1
echo [ktm done] %time%
echo. >> !LOG!
echo ======== kuainiao ======== >> !LOG!
python -X utf8 run.py pull --airport kuainiao -v >> !LOG! 2>&1
echo [kuainiao done] %time%
echo. >> !LOG!
echo ======== letsvpn ======== >> !LOG!
python -X utf8 run.py scan-memory --airport letsvpn >> !LOG! 2>&1
echo [letsvpn done] %time%
echo. >> !LOG!
echo ======== liangxin ======== >> !LOG!
python -X utf8 run.py pull --airport liangxin -v >> !LOG! 2>&1
echo [liangxin done] %time%
echo. >> !LOG!
echo ======== lingdian ======== >> !LOG!
python -X utf8 run.py pull --airport lingdian -v >> !LOG! 2>&1
echo [lingdian done] %time%
echo. >> !LOG!
echo ======== maxiong ======== >> !LOG!
python -X utf8 run.py pull --airport maxiong -v >> !LOG! 2>&1
echo [maxiong done] %time%
echo. >> !LOG!
echo ======== mitce ======== >> !LOG!
python -X utf8 run.py pull --airport mitce -v >> !LOG! 2>&1
echo [mitce done] %time%
echo. >> !LOG!
echo ======== mojie ======== >> !LOG!
python -X utf8 run.py pull --airport mojie -v >> !LOG! 2>&1
echo [mojie done] %time%
echo. >> !LOG!
echo ======== muniu ======== >> !LOG!
python -X utf8 run.py pull --airport muniu -v >> !LOG! 2>&1
echo [muniu done] %time%
echo. >> !LOG!
echo ======== muniu-ninja ======== >> !LOG!
python -X utf8 run.py scan-memory --airport muniu-ninja >> !LOG! 2>&1
echo [muniu-ninja done] %time%
echo. >> !LOG!
echo ======== neko77 ======== >> !LOG!
python -X utf8 run.py pull --airport neko77 -v >> !LOG! 2>&1
echo [neko77 done] %time%
echo. >> !LOG!
echo ======== new-yiyuan ======== >> !LOG!
python -X utf8 run.py pull --airport new-yiyuan -v >> !LOG! 2>&1
echo [new-yiyuan done] %time%
echo. >> !LOG!
echo ======== no626 ======== >> !LOG!
python -X utf8 run.py pull --airport no626 -v >> !LOG! 2>&1
echo [no626 done] %time%
echo. >> !LOG!
echo ======== oixcloud ======== >> !LOG!
python -X utf8 run.py pull --airport oixcloud -v >> !LOG! 2>&1
echo [oixcloud done] %time%
echo. >> !LOG!
echo ======== pkq ======== >> !LOG!
python -X utf8 run.py pull --airport pkq -v >> !LOG! 2>&1
echo [pkq done] %time%
echo. >> !LOG!
echo ======== qiangda ======== >> !LOG!
python -X utf8 run.py pull --airport qiangda -v >> !LOG! 2>&1
echo [qiangda done] %time%
echo. >> !LOG!
echo ======== qingyunti ======== >> !LOG!
python -X utf8 run.py scan-memory --airport qingyunti >> !LOG! 2>&1
echo [qingyunti done] %time%
echo. >> !LOG!
echo ======== quqiuquan ======== >> !LOG!
python -X utf8 run.py scan-memory --airport quqiuquan >> !LOG! 2>&1
echo [quqiuquan done] %time%
echo. >> !LOG!
echo ======== selom ======== >> !LOG!
python -X utf8 run.py pull --airport selom -v >> !LOG! 2>&1
echo [selom done] %time%
echo. >> !LOG!
echo ======== speedcat ======== >> !LOG!
python -X utf8 run.py scan-memory --airport speedcat >> !LOG! 2>&1
echo [speedcat done] %time%
echo. >> !LOG!
echo ======== ss-id ======== >> !LOG!
python -X utf8 run.py pull --airport ss-id -v >> !LOG! 2>&1
echo [ss-id done] %time%
echo. >> !LOG!
echo ======== ssrdog ======== >> !LOG!
python -X utf8 run.py scan-memory --airport ssrdog >> !LOG! 2>&1
echo [ssrdog done] %time%
echo. >> !LOG!
echo ======== velochron ======== >> !LOG!
python -X utf8 run.py scan-memory --airport velochron >> !LOG! 2>&1
echo [velochron done] %time%
echo. >> !LOG!
echo ======== wandacloud ======== >> !LOG!
python -X utf8 run.py scan-memory --airport wandacloud >> !LOG! 2>&1
echo [wandacloud done] %time%
echo. >> !LOG!
echo ======== wdy ======== >> !LOG!
python -X utf8 run.py scan-memory --airport wdy >> !LOG! 2>&1
echo [wdy done] %time%
echo. >> !LOG!
echo ======== xm999 ======== >> !LOG!
python -X utf8 run.py pull --airport xm999 -v >> !LOG! 2>&1
echo [xm999 done] %time%
echo. >> !LOG!
echo ======== yiyuan ======== >> !LOG!
python -X utf8 run.py pull --airport yiyuan -v >> !LOG! 2>&1
echo [yiyuan done] %time%
echo.
echo === 全部完成 %date% %time% === >> !LOG!
echo 现在跑全量导出恢复 index.json ...
python -X utf8 -m airmon.nodeset >> !LOG! 2>&1
echo 完成。日志: !LOG!
pause