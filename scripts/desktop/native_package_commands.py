"""Native commands used only by the protected packaged-artifact probe."""
from __future__ import annotations

import shlex


def _posix_runtime(app: str, *, macos: bool) -> str:
    data = (
        'profile_root="$HOME/Library/Application Support/com.runne.desktop"\n'
        if macos
        else 'export XDG_DATA_HOME="$probe_root/data"\n'
        'export XDG_CONFIG_HOME="$probe_root/config"\n'
        'export XDG_STATE_HOME="$probe_root/state"\n'
        'profile_root="$probe_root"\n'
    )
    return f'''set -eu
root="$NATIVE_PROBE_INSTALL_ROOT"
probe_root="$root/.runne-native-probe"
mkdir -p "$probe_root" "$probe_root/home" "$probe_root/data" "$probe_root/config" "$probe_root/state"
main="{app}"
test -f "$main" && test -x "$main"
{data}app_pid=""
daemon_pid=""
log="$probe_root/desktop.log"
cleanup() {{
  if [ -n "$app_pid" ] && kill -0 "$app_pid" 2>/dev/null; then kill -KILL "$app_pid" 2>/dev/null || true; fi
  if [ -n "$daemon_pid" ] && kill -0 "$daemon_pid" 2>/dev/null; then kill -KILL "$daemon_pid" 2>/dev/null || true; fi
}}
trap cleanup EXIT
launch_once() {{
  "$main" --bundled-runtime >"$log" 2>&1 &
  app_pid=$!
  for _ in $(seq 1 60); do
    if ! kill -0 "$app_pid" 2>/dev/null; then return 1; fi
    daemon_pid="$(pgrep -P "$app_pid" -f 'runned' | head -n 1 || true)"
    if [ -n "$daemon_pid" ]; then return 0; fi
    sleep 0.25
  done
  return 1
}}
stop_once() {{
  kill -TERM "$app_pid" 2>/dev/null || true
  for _ in $(seq 1 40); do
    if ! kill -0 "$app_pid" 2>/dev/null; then break; fi
    sleep 0.25
  done
  if kill -0 "$app_pid" 2>/dev/null; then return 1; fi
  for _ in $(seq 1 40); do
    if ! kill -0 "$daemon_pid" 2>/dev/null; then app_pid=""; daemon_pid=""; return 0; fi
    sleep 0.25
  done
  return 1
}}
'''


def _posix_command(operation: str, app: str, *, macos: bool) -> str:
    runtime = _posix_runtime(app, macos=macos)
    if operation == "protected-launch":
        body = "launch_once\nstop_once\n"
    elif operation == "protected-relaunch":
        body = "launch_once\nstop_once\nlaunch_once\nstop_once\n"
    elif operation == "secure-store-writer-reader":
        body = (
            "launch_once\nstop_once\n"
            'find "$profile_root" -type f -name profile.sqlite3 -print -quit | grep -q .\n'
            "launch_once\nstop_once\n"
        )
    elif operation == "secure-store-third-process-deny":
        body = '''launch_once
lock="$(find "$profile_root" -type f -name profile.lock -print -quit)"
test -n "$lock"
python3 - "$lock" <<'PY'
import fcntl
import os
import sys

fd = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    raise SystemExit(0)
raise SystemExit(1)
PY
'''
    else:
        raise ValueError(f"unsupported runtime operation: {operation}")
    return runtime + body


def _windows_runtime() -> str:
    return r'''$ErrorActionPreference = 'Stop'
$root = $env:NATIVE_PROBE_INSTALL_ROOT
$probe = Join-Path $root '.runne-native-probe'
$home = Join-Path $probe 'home'
New-Item -ItemType Directory -Force -Path $probe, $home | Out-Null
$env:APPDATA = Join-Path $home 'Roaming'
$env:LOCALAPPDATA = Join-Path $home 'Local'
New-Item -ItemType Directory -Force -Path $env:APPDATA, $env:LOCALAPPDATA | Out-Null
$main = (Get-ChildItem $env:ProgramFiles -Filter 'runne-desktop.exe' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
if ([string]::IsNullOrWhiteSpace($main)) { throw 'installed main executable not found' }
$log = Join-Path $probe 'desktop.log'
$errorLog = Join-Path $probe 'desktop.error.log'
$appProcess = $null
$daemonProcess = $null
function Stop-ProbeProcesses {
  if ($script:appProcess -and -not $script:appProcess.HasExited) { Stop-Process -Id $script:appProcess.Id -Force -ErrorAction SilentlyContinue }
  if ($script:daemonProcess -and -not $script:daemonProcess.HasExited) { Stop-Process -Id $script:daemonProcess.ProcessId -Force -ErrorAction SilentlyContinue }
}
trap { Stop-ProbeProcesses; exit 1 }
function Start-ProbeApp {
  $script:appProcess = Start-Process -FilePath $main -ArgumentList '--bundled-runtime' -PassThru -RedirectStandardOutput $log -RedirectStandardError $errorLog
  for ($i = 0; $i -lt 60; $i++) {
    if ($script:appProcess.HasExited) { throw 'desktop exited before protected daemon appeared' }
    $script:daemonProcess = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($script:appProcess.Id)" | Where-Object { $_.Name -match '^runned.*\.exe$' } | Select-Object -First 1
    if ($script:daemonProcess) { return }
    Start-Sleep -Milliseconds 250
  }
  throw 'protected daemon did not appear under desktop owner'
}
function Stop-ProbeApp {
  if ($script:appProcess -and -not $script:appProcess.HasExited) { taskkill.exe /PID $script:appProcess.Id /T /F | Out-Null }
  if ($script:appProcess) { $script:appProcess.WaitForExit(10000) }
  for ($i = 0; $i -lt 40; $i++) {
    if (-not $script:daemonProcess -or -not (Get-Process -Id $script:daemonProcess.ProcessId -ErrorAction SilentlyContinue)) { $script:appProcess = $null; $script:daemonProcess = $null; return }
    Start-Sleep -Milliseconds 250
  }
  throw 'protected daemon survived desktop shutdown'
}
'''


def _windows_command(operation: str) -> str:
    runtime = _windows_runtime()
    if operation == "protected-launch":
        body = "Start-ProbeApp\nStop-ProbeApp\n"
    elif operation == "protected-relaunch":
        body = "Start-ProbeApp\nStop-ProbeApp\nStart-ProbeApp\nStop-ProbeApp\n"
    elif operation == "secure-store-writer-reader":
        body = (
            "Start-ProbeApp\nStop-ProbeApp\n"
            "if (-not (Get-ChildItem $probe -Filter 'profile.sqlite3' -Recurse -File | Select-Object -First 1)) { throw 'profile database was not created' }\n"
            "Start-ProbeApp\nStop-ProbeApp\n"
        )
    elif operation == "secure-store-third-process-deny":
        body = r'''Start-ProbeApp
$lock = (Get-ChildItem $probe -Filter 'profile.lock' -Recurse -File | Select-Object -First 1).FullName
if ([string]::IsNullOrWhiteSpace($lock)) { throw 'profile lock was not created' }
try {
  $stream = [System.IO.File]::Open($lock, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
  $stream.Dispose()
  throw 'third process acquired profile lock'
} catch [System.IO.IOException] {
  Stop-ProbeApp
}
'''
    else:
        raise ValueError(f"unsupported runtime operation: {operation}")
    return runtime + body


def command(pair: str, operation: str, package: str, main_binary_name: str) -> list[str]:
    """Return one command that probes the installed artifact on its native host."""
    quoted = shlex.quote(package)
    windows_package = package.replace("'", "''")
    app = "$NATIVE_PROBE_INSTALL_ROOT/Runne.app"
    daemon = f"{app}/Contents/MacOS/runned"
    writer = f"{app}/Contents/MacOS/runne"
    main = f"{app}/Contents/MacOS/{main_binary_name}"
    linux_identity = f'''set -eu
for binary in '{main_binary_name}' runne runned; do
  path="$(find "$NATIVE_PROBE_INSTALL_ROOT" -type f -name "$binary" -print -quit)"
  test -n "$path"
  sha256sum "$path"
done'''
    windows_components = (
        f"$main = Get-ChildItem $env:ProgramFiles -Filter '{main_binary_name}.exe' -Recurse -File | Select-Object -First 1; "
        "if ($null -eq $main) { throw 'installed main executable not found' }; "
        "$componentRoot = Split-Path -Parent $main.FullName; "
        "$components = @($main.FullName, (Join-Path $componentRoot 'runne.exe'), (Join-Path $componentRoot 'runned.exe')); "
        "$components | ForEach-Object { if (-not (Test-Path -PathType Leaf $_)) { throw \"installed component not found: $_\" } }"
    )
    mac = {
        "install": f"ditto {quoted} \"{app}\"",
        "discover-installed-artifact": f"test -d \"{app}\"",
        "executable-identity": f"codesign -dvv \"{main}\" && codesign -dvv \"{writer}\" && codesign -dvv \"{daemon}\"",
        "protected-launch": _posix_command(operation, main, macos=True) if operation == "protected-launch" else None,
        "protected-relaunch": _posix_command(operation, main, macos=True) if operation == "protected-relaunch" else None,
        "secure-store-writer-reader": _posix_command(operation, main, macos=True) if operation == "secure-store-writer-reader" else None,
        "secure-store-third-process-deny": _posix_command(operation, main, macos=True) if operation == "secure-store-third-process-deny" else None,
        "signing-notarization": f"codesign --verify --strict \"{writer}\" && codesign --verify --strict \"{daemon}\" && codesign --verify --strict \"{app}\" && spctl --assess --type execute \"{app}\"",
        "uninstall": f"rm -rf \"{app}\"",
    }
    linux = {
        "install": f"dpkg --root \"$NATIVE_PROBE_INSTALL_ROOT\" --admindir \"$NATIVE_PROBE_INSTALL_ROOT/var/lib/dpkg\" --instdir \"$NATIVE_PROBE_INSTALL_ROOT\" -i {quoted}",
        "discover-installed-artifact": f"find \"$NATIVE_PROBE_INSTALL_ROOT\" -type f -name '{main_binary_name}' -print -quit | grep -q .",
        "executable-identity": linux_identity,
        "protected-launch": _posix_command(operation, f"$(find \"$NATIVE_PROBE_INSTALL_ROOT\" -type f -name '{main_binary_name}' -perm -u+x -print -quit)", macos=False) if operation == "protected-launch" else None,
        "protected-relaunch": _posix_command(operation, f"$(find \"$NATIVE_PROBE_INSTALL_ROOT\" -type f -name '{main_binary_name}' -perm -u+x -print -quit)", macos=False) if operation == "protected-relaunch" else None,
        "secure-store-writer-reader": _posix_command(operation, f"$(find \"$NATIVE_PROBE_INSTALL_ROOT\" -type f -name '{main_binary_name}' -perm -u+x -print -quit)", macos=False) if operation == "secure-store-writer-reader" else None,
        "secure-store-third-process-deny": _posix_command(operation, f"$(find \"$NATIVE_PROBE_INSTALL_ROOT\" -type f -name '{main_binary_name}' -perm -u+x -print -quit)", macos=False) if operation == "secure-store-third-process-deny" else None,
        "signing-notarization": "true",
        "uninstall": "find \"$NATIVE_PROBE_INSTALL_ROOT\" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +",
    }
    windows = {
        "install": f"$process = Start-Process -Wait -PassThru -FilePath '{windows_package}' -ArgumentList '/S'; exit $process.ExitCode",
        "discover-installed-artifact": f"Get-ChildItem $env:ProgramFiles -Filter '{main_binary_name}.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object {{$_.FullName}}",
        "executable-identity": windows_components + "; $components | ForEach-Object { Get-AuthenticodeSignature $_ }",
        "protected-launch": _windows_command(operation) if operation == "protected-launch" else None,
        "protected-relaunch": _windows_command(operation) if operation == "protected-relaunch" else None,
        "secure-store-writer-reader": _windows_command(operation) if operation == "secure-store-writer-reader" else None,
        "secure-store-third-process-deny": _windows_command(operation) if operation == "secure-store-third-process-deny" else None,
        "signing-notarization": windows_components + "; $components | ForEach-Object { if ((Get-AuthenticodeSignature $_).Status -ne 'Valid') { throw \"invalid signature: $_\" } }",
        "uninstall": "$uninstaller = Get-ChildItem $env:ProgramFiles -Filter unins*.exe -Recurse | Select-Object -First 1; if ($null -eq $uninstaller) { exit 1 }; $process = Start-Process -Wait -PassThru -FilePath $uninstaller.FullName -ArgumentList '/S'; exit $process.ExitCode",
    }
    values = windows if pair.startswith("windows") else mac if pair.startswith("macos") else linux
    value = values.get(operation)
    if not isinstance(value, str):
        raise ValueError(f"unsupported packaged operation: {operation}")
    if pair.startswith("macos") or pair.startswith("ubuntu"):
        return ["/usr/bin/env", "bash", "-lc", value]
    return ["powershell", "-NoProfile", "-Command", value]
