# GOCODE SourceCraft self-hosted worker for Windows x86_64.
#
# Requirements: PowerShell, Git for Windows (Git Bash on PATH), rustup,
# python3 on PATH, and a SourceCraft PAT with Repository admin role.
#
# Usage (run once as the CI user):
#   powershell -ExecutionPolicy Bypass -File scripts\sourcecraft\setup-windows-worker.ps1 -Pat <PAT> [-RootDir C:\sourcecraft-worker]
#
# Registers the worker as a scheduled task that starts at logon and restarts
# on failure. Tag: gocode-windows-x86_64 (used by runtime-ci windows-* tasks).

param(
    [Parameter(Mandatory = $true)]
    [string]$Pat,
    [string]$RootDir = "$env:USERPROFILE\sourcecraft-worker"
)

$ErrorActionPreference = "Stop"

$processorUrl = "https://storage.yandexcloud.net/src-processor-downloads/self-hosted-processor-latest/windows/amd64/self-hosted-processor.exe"
$processorExe = Join-Path $RootDir "self-hosted-processor.exe"
$configPath = Join-Path $RootDir "config.yaml"

New-Item -ItemType Directory -Force -Path $RootDir | Out-Null
if (-not (Test-Path $processorExe)) {
    Invoke-WebRequest -Uri $processorUrl -OutFile $processorExe
}

# Generate the worker config (init prints the config to stdout).
$initArgs = @("init", "-t", $Pat, "-c", "1", "-r", (Join-Path $RootDir "root"), "--tags", "gocode-windows-x86_64")
$config = & $processorExe @initArgs | Out-String
$config = $config -replace "(?m)^(\s*known_secrets): false", '$1: true'
$config = $config -replace "(?m)^(\s*iam_token): false", '$1: true'
$config = $config -replace "(?m)^(\s*ssh_private_key): false", '$1: true'
Set-Content -Path $configPath -Value $config -NoNewline

# Register as a scheduled task that survives reboots.
$taskName = "gocode-sourcecraft-worker"
$action = New-ScheduledTaskAction -Execute $processorExe `
    -Argument "run -c `"$configPath`"" -WorkingDirectory $RootDir
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -ExecutionTimeLimit (New-TimeSpan -Days 3650)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

Write-Host "Worker installed: $processorExe"
Write-Host "Config: $configPath (mode 0600 equivalent: restrict NTFS ACLs to the CI user)"
Write-Host "Scheduled task: $taskName"
Write-Host "Tags: gocode-windows-x86_64"
