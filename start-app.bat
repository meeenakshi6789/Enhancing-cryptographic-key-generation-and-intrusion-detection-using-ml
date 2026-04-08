@echo off
taskkill /F /IM node.exe >nul 2>&1
start "" "%ProgramFiles%\nodejs\node.exe" "%CD%\node_modules\react-scripts\bin\react-scripts.js" start
