@echo off
title Hydra Auth
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is not installed.
  echo Opening the download page. Install the LTS version, then double-click start.bat again.
  start "" https://nodejs.org/en/download
  pause
  exit /b 1
)

if not exist node_modules (
  echo Installing dependencies, this takes a minute the first time...
  call npm install
  if errorlevel 1 (
    echo.
    echo npm install failed. Make sure you installed the Node.js LTS version.
    pause
    exit /b 1
  )
)

node scripts\setup-env.js
if errorlevel 1 (
  pause
  exit /b 1
)

echo Starting server. Keep this window open - closing it stops the server.
echo Dashboard: http://localhost:3000/dashboard/
start "" cmd /c "timeout /t 2 >nul & start http://localhost:3000/dashboard/"
call npm start
pause
