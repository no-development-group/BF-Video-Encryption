@echo off
:: BlueFlix Launcher
set PLAYER=%~dp0player.html
set CHROME=C:\Program Files\Google\Chrome\Application\chrome.exe
set TMPPROFILE=%TEMP%\blueflix_profile

"%CHROME%" --user-data-dir="%TMPPROFILE%" --allow-file-access-from-files --disable-web-security --no-first-run --no-default-browser-check --start-fullscreen "%PLAYER%"
