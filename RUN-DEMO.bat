@echo off
setlocal EnableExtensions
title detection-rules-lab One-Click Demo
color 0B

REM Portable: run from the folder this script lives in, wherever the repo is cloned.
cd /d "%~dp0"

echo ============================================================
echo    detection-rules-lab  -  Detection Rules Validation DEMO
echo ============================================================
echo.

echo [1/3] Checking that Docker is running...
docker info >nul 2>&1
if errorlevel 1 goto :nodocker
echo       OK - Docker is running.
echo.

echo [2/3] Validating ALL rules: syntax + does-it-actually-detect.
echo       Please wait, this can take up to a minute...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\Invoke-Validation.ps1" -Full
if errorlevel 1 goto :validfail
echo.
echo       OK - All rules passed.  ==^> PROOF the system works
echo.

echo [3/3] Proving a BROKEN rule is correctly REJECTED...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\Validate-Syntax.ps1" -Engine suricata -Files "tests/fixtures/broken-suricata-example.rules"
if errorlevel 1 (
  echo.
  echo       OK - The broken rule was REJECTED.  safety net works
) else (
  echo.
  echo       WARNING - the broken rule was NOT rejected as expected.
)
echo.

echo ============================================================
echo    DEMO COMPLETE
echo    Step 2: good rules pass and actually detect.
echo    Step 3: bad rules are blocked.
echo ============================================================
echo.
pause
exit /b 0

:nodocker
echo.
echo    [X] Docker is NOT running.
echo        1. Open "Docker Desktop" from the Start menu.
echo        2. Wait for the green "Engine running" status.
echo        3. Double-click this file again.
echo.
pause
exit /b 1

:validfail
echo.
echo    [X] Validation found a problem. Read the lines marked [x] above.
echo.
pause
exit /b 1
