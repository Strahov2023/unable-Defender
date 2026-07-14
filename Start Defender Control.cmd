@echo off
set "SCRIPT=%~dp0DefenderControl.ps1"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -STA -ExecutionPolicy RemoteSigned -File "%SCRIPT%"
if errorlevel 1 (
  echo.
  echo Defender Control failed to start. Error code: %errorlevel%
  pause
)
