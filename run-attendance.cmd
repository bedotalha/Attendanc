@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-attend.ps1"
if errorlevel 1 echo Attend could not start. Check the message above.
pause
