@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    py -3 bootstrap.py %*
) else (
    python bootstrap.py %*
)
if errorlevel 1 pause
