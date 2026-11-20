@echo off
setlocal
if not defined PUBLIC_ORIGIN if exist "%LOCALAPPDATA%\Attend\public-origin.txt" set /p "PUBLIC_ORIGIN="<"%LOCALAPPDATA%\Attend\public-origin.txt"
cd /d "%~dp0site"
if not exist "node_modules\qrcode\package.json" call npm install --no-audit --no-fund
if errorlevel 1 (
  pause
  exit /b 1
)
rem Wait for the local API before opening the default browser.
start "" /b powershell.exe -NoProfile -WindowStyle Hidden -Command "$port = $env:PORT; if (-not $port) { $port = 4173 }; $url = 'http://127.0.0.1:' + $port; $deadline = (Get-Date).AddSeconds(30); while ((Get-Date) -lt $deadline) { try { $status = Invoke-RestMethod -Uri ($url + '/api/auth-status') -TimeoutSec 2; if ($null -ne $status.configured) { Start-Process ($url + '/'); exit } } catch {}; Start-Sleep -Milliseconds 500 }"
node --experimental-sqlite server.js
pause
