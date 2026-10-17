# Registers a Windows scheduled task that watches the network for devices joining or
# leaving. It starts every minute and runs two checks 30 seconds apart. If a run is
# still busy (e.g. scanning a new device), the next start is skipped.
#
#     powershell -ExecutionPolicy Bypass -File scripts\register_asset_watcher_task.ps1
#
# Remove it again with:
#     Unregister-ScheduledTask -TaskName "ThreatAware Asset Watcher" -Confirm:$false

$runner = Join-Path $PSScriptRoot "run_asset_watcher.cmd"
if (-not (Test-Path $runner)) { throw "Cannot find $runner" }

$action  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$runner`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
           -RepetitionInterval (New-TimeSpan -Minutes 1)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries `
            -AllowStartIfOnBatteries -MultipleInstances IgnoreNew `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask -TaskName "ThreatAware Asset Watcher" -Action $action -Trigger $trigger `
    -Settings $settings -Description "Threat-aware exposure prediction: detect devices joining or leaving the network every 30 seconds" `
    -Force | Out-Null

Write-Host "Scheduled task 'ThreatAware Asset Watcher' registered: checks every 30 seconds, first run in 1 minute."
Write-Host "Output is written to data\lab\watch.log"
