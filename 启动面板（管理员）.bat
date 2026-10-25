@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo 以管理员身份启动机场面板预览服务（端口 57010）
echo 之后点「获取节点」将不再弹 UAC。
python -X utf8 tools\panel_preview_server.py --port 57010
pause
