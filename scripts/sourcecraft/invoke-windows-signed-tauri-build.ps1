param(
    [Parameter(Mandatory = $true)]
    [string]$Bundles
)
$ErrorActionPreference = "Stop"

foreach ($name in @(
    "WINDOWS_CERTIFICATE",
    "WINDOWS_CERTIFICATE_PASSWORD",
    "WINDOWS_CERTIFICATE_THUMBPRINT"
)) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        throw "missing required protected signing input: $name"
    }
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("runne-signing-" + [Guid]::NewGuid().ToString("N"))
$pfx = Join-Path $temporary "certificate.pfx"
$config = Join-Path $root "apps/desktop/src-tauri/tauri.windows.conf.json"
$thumbprint = ($env:WINDOWS_CERTIFICATE_THUMBPRINT -replace "\s", "").ToUpperInvariant()
if ($thumbprint -notmatch '^[0-9A-F]{40}$') {
    throw "protected Windows signing certificate thumbprint is invalid"
}

try {
    New-Item -ItemType Directory -Path $temporary -Force | Out-Null
    [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:WINDOWS_CERTIFICATE))
    $password = ConvertTo-SecureString $env:WINDOWS_CERTIFICATE_PASSWORD -AsPlainText -Force
    Import-PfxCertificate -FilePath $pfx -CertStoreLocation Cert:\CurrentUser\My -Password $password | Out-Null
    $certificate = Get-ChildItem ("Cert:\CurrentUser\My\" + $thumbprint)
    if ($null -eq $certificate -or $certificate.Thumbprint -ne $thumbprint) {
        throw "protected Windows signing certificate identity mismatch"
    }
    $json = ConvertTo-Json -InputObject @{ bundle = @{ windows = @{ certificateThumbprint = $thumbprint } } } -Depth 4
    [IO.File]::WriteAllText($config, $json, [Text.UTF8Encoding]::new($false))
    & pnpm --filter @runne/desktop tauri build --bundles $Bundles
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Remove-Item -LiteralPath $config -Force -ErrorAction SilentlyContinue
    if ($thumbprint) {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $thumbprint) -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
