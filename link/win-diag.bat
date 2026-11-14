@echo off
setlocal
REM WBDrop - Windows connectivity diagnostic (read-only, no admin needed).
REM Writes win-diag.txt next to this file. Send that file back for analysis.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0win-diag.ps1"
echo.
echo Report saved to: %~dp0win-diag.txt
echo.
pause
