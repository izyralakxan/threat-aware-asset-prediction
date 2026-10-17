@echo off
rem Runs two network checks 30 seconds apart (new or removed devices) and appends
rem the output to data\lab\watch.log. Started every minute by the Windows scheduled
rem task created by register_asset_watcher_task.ps1, so a check runs every 30 seconds.
cd /d "%~dp0.."
if not exist data\lab mkdir data\lab
".venv\Scripts\python.exe" -m src.asset_discovery.asset_watcher --checks 2 --interval 30 >> data\lab\watch.log 2>&1
