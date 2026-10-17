@echo off
rem Sends reminders for fixes still not applied 24 hours after the team was notified
rem (repeats every 24 hours until a scan proves the fix). Started every hour by the
rem Windows scheduled task created by register_fix_reminders_task.ps1.
cd /d "%~dp0.."
if not exist data\notifications mkdir data\notifications
".venv\Scripts\python.exe" -m src.notify.reminders >> data\notifications\reminders.log 2>&1
