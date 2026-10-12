# Registers a Windows scheduled task that runs the live vulnerability sync
# every 6 hours for the current user. Run once from the project folder:
#
#     powershell -ExecutionPolicy Bypass -File scripts\register_live_sync_task.ps1
#
# Remove it again with:
#     Unregister-ScheduledTask -TaskName "ThreatAware Live Sync" -Confirm:$false

param([int]$EveryHours = 6)

$runner = Join-Path $PSScriptRoot "run_live_sync.cmd"
if (-not (Test-Path $runner)) { throw "Cannot find $runner" }

$action  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$runner`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
           -RepetitionInterval (New-TimeSpan -Hours $EveryHours)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Hours 1)

Register-ScheduledTask -TaskName "ThreatAware Live Sync" -Action $action -Trigger $trigger `
    -Settings $settings -Description "Threat-aware exposure prediction: sync CISA KEV and NVD, score new CVEs, raise alerts" `
    -Force | Out-Null

Write-Host "Scheduled task 'ThreatAware Live Sync' registered: every $EveryHours hours, first run in 5 minutes."
Write-Host "Output is written to data\live\task.log"
