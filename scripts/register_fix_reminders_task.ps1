# Registers a Windows scheduled task that checks every hour for fixes still not
# applied 24 hours after the owning team was notified, and emails them a reminder.
#
#     powershell -ExecutionPolicy Bypass -File scripts\register_fix_reminders_task.ps1
#
# Remove it again with:
#     Unregister-ScheduledTask -TaskName "ThreatAware Fix Reminders" -Confirm:$false

$runner = Join-Path $PSScriptRoot "run_fix_reminders.cmd"
if (-not (Test-Path $runner)) { throw "Cannot find $runner" }

$action  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$runner`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
           -RepetitionInterval (New-TimeSpan -Hours 1)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries `
            -AllowStartIfOnBatteries -MultipleInstances IgnoreNew `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask -TaskName "ThreatAware Fix Reminders" -Action $action -Trigger $trigger `
    -Settings $settings -Description "Threat-aware exposure prediction: remind teams about fixes still open 24 hours after notice" `
    -Force | Out-Null

Write-Host "Scheduled task 'ThreatAware Fix Reminders' registered: checks every hour, first run in 1 minute."
Write-Host "Output is written to data\notifications\reminders.log"
