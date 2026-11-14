@echo off
chcp 65001 >nul 2>&1
title WBDrop - Windows fix and self test
echo.
echo   WBDrop one-shot fix: detect version, verify pair code, fix config, send a 1KB test file.
echo   It will ask for the PAIR CODE shown on the Mac (press Enter to accept 123456).
echo   Output is saved to win-fix.txt next to this file.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0win-fix.ps1" %*
echo.
echo   Press any key to close ...
pause >nul
