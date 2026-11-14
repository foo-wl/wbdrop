@echo off
setlocal
net session >nul 2>&1
if %errorlevel%==0 goto :run
echo Requesting administrator privileges...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:run
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0win-start-link.ps1"
echo.
pause
