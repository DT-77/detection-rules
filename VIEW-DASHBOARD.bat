@echo off
setlocal EnableExtensions
title detection-rules-lab - Dashboard
color 0B

REM Portable: runs from the folder this script lives in, wherever the repo is cloned.
cd /d "%~dp0"

echo ============================================================
echo    detection-rules-lab  -  MONITORING DASHBOARD
echo ============================================================
echo.

echo Checking that Docker is running...
docker info >nul 2>&1
if errorlevel 1 goto :nodocker
echo       OK - Docker is running.
echo.

echo Building the dashboard from live status (about a minute)...
echo Your browser will open automatically when it is ready.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\Build-Dashboard.ps1" -Open
if errorlevel 1 goto :fail
echo.
echo Done. The dashboard opened in your browser.
echo If it did not open, double-click this file manually:
echo    %~dp0dashboard\index.html
echo.
pause
exit /b 0

:nodocker
echo.
echo    [X] Docker is NOT running.
echo        Start Docker Desktop, wait for the green "Engine running", then retry.
echo.
pause
exit /b 1

:fail
echo.
echo    [X] Dashboard build failed. Read the lines marked [x] above.
echo.
pause
exit /b 1
