@echo off
chcp 65001 >nul
cd /d "%~dp0"
"D:\TG BOTE\runtime\Python312\python.exe" hosting.py stop
pause
