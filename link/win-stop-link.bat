@echo off
setlocal
net session >nul 2>&1
if %errorlevel%==0 goto :run
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:run
echo Stopping WBDrop soft AP...
netsh wlan stop hostednetwork
netsh wlan set hostednetwork mode=disallow
netsh advfirewall firewall delete rule name="WBDrop" >nul 2>&1
echo.
echo Done. The virtual adapter is gone and the firewall rule is removed.
echo.
pause
