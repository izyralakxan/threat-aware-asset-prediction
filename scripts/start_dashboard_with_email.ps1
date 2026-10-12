# Starts the dashboard with real email sending (SMTP) for this session only.
# The app password is typed at the prompt, kept in memory and never written to disk.
#
# Gmail: turn on 2-Step Verification, then create an app password at
# https://myaccount.google.com/apppasswords (16 characters, not your normal password).
#
# Run from the project folder:
#     powershell -ExecutionPolicy Bypass -File scripts\start_dashboard_with_email.ps1

param(
    [string]$SmtpUser,
    [string]$SmtpHost = "smtp.gmail.com",
    [int]$SmtpPort = 587
)

if (-not $SmtpUser) { $SmtpUser = Read-Host "Gmail address to send from" }
$secure = Read-Host "App password for $SmtpUser" -AsSecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))

$env:SMTP_HOST = $SmtpHost
$env:SMTP_PORT = "$SmtpPort"
$env:SMTP_USER = $SmtpUser
$env:SMTP_PASSWORD = $plain.Replace(" ", "")

Write-Host "Email sending enabled for this session ($SmtpUser via ${SmtpHost}:$SmtpPort)."
Write-Host "Dashboard: http://localhost:8501   (Ctrl+C to stop)"
& "$PSScriptRoot\..\.venv\Scripts\python.exe" -m streamlit run "$PSScriptRoot\..\src\dashboard\app.py"
