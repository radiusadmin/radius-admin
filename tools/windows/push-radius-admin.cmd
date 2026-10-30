@echo off
rem Starts push-radius-admin.ps1 without changing the PowerShell execution policy.
rem Usage: push-radius-admin.cmd [-Package file.tar.gz] [-WithFreeradius] [-Rollback] [-List]
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0push-radius-admin.ps1" %*
set rc=%ERRORLEVEL%
if "%~1"=="" pause
exit /b %rc%
