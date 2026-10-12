@echo off
rem Runs one live vulnerability sync and appends the output to data\live\task.log.
rem Used by the Windows scheduled task created by register_live_sync_task.ps1.
cd /d "%~dp0.."
if not exist data\live mkdir data\live
echo ==== %date% %time% ==== >> data\live\task.log
".venv\Scripts\python.exe" -m src.sync.live_sync >> data\live\task.log 2>&1
