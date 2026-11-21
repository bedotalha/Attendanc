$ErrorActionPreference = 'Stop'
$site = Join-Path $PSScriptRoot 'site'
$tailscale = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
$tailscaleApp = Join-Path $env:ProgramFiles 'Tailscale\tailscale-ipn.exe'
$port = if ($env:PORT) { [int]$env:PORT } else { 4173 }
$localUrl = "http://127.0.0.1:$port"

try {
    $existing = Invoke-RestMethod -Uri "$localUrl/api/auth-status" -TimeoutSec 2
    if ($null -ne $existing.configured) {
        Write-Host "Attend is already running: $localUrl"
        Start-Process "$localUrl/"
        return
    }
} catch {
    # No Attend server is listening yet.
}

if (-not (Test-Path -LiteralPath $tailscale)) {
    throw 'Tailscale is not installed. Install and sign in to Tailscale before starting Attend.'
}

Push-Location $site
try {
    if (-not (Test-Path 'node_modules\qrcode\package.json')) {
        & npm install --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw 'npm install failed.' }
    }

    $service = Get-Service Tailscale -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Running') {
        Write-Host 'Starting Tailscale service...'
        Start-Service Tailscale
    }
    $statusDeadline = (Get-Date).AddSeconds(120)
    $appLaunchAfter = (Get-Date).AddSeconds(10)
    $appLaunchAttempted = $false
    do {
        $statusText = & $tailscale status --json 2>&1
        $statusCode = $LASTEXITCODE
        $state = $null
        if ($statusCode -eq 0) {
            try { $state = ($statusText -join "`n" | ConvertFrom-Json).BackendState } catch {}
        }
        if ($state -eq 'Running') { break }
        if (($statusText -join "`n") -match 'Access is denied|permission denied') {
            throw 'Tailscale denied access to its local service. Run Attend from a Windows account authorized to use Tailscale, or open PowerShell as Administrator and retry.'
        }
        if (-not $appLaunchAttempted -and (Get-Date) -ge $appLaunchAfter -and
            (Test-Path -LiteralPath $tailscaleApp) -and
            -not (Get-Process tailscale-ipn -ErrorAction SilentlyContinue)) {
            Write-Host 'Opening Tailscale to restore the connection...'
            $tailscaleLog = Join-Path $env:TEMP 'attend-tailscale-ui.log'
            Start-Process -FilePath $tailscaleApp -RedirectStandardOutput $tailscaleLog -RedirectStandardError (Join-Path $env:TEMP 'attend-tailscale-ui-error.log')
            $appLaunchAttempted = $true
        }
        if ((Get-Date) -ge $statusDeadline) {
            throw "Tailscale did not become ready within 120 seconds (state: $state). Check Tailscale sign-in and connectivity. $statusText"
        }
        Start-Sleep -Seconds 2
    } while ($true)

    $funnelText = & $tailscale funnel --bg --yes $port 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Could not start Tailscale Funnel: $funnelText" }

    $funnelStatus = & $tailscale funnel status 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Could not read Funnel URL: $funnelStatus" }
    $publicUrl = [regex]::Match(($funnelStatus -join "`n"), 'https://[a-zA-Z0-9.-]+\.ts\.net(?=/|\s|$)').Value
    if (-not $publicUrl) { throw "Funnel did not report a public URL: $funnelStatus" }

    $env:PUBLIC_ORIGIN = $publicUrl
    Write-Host "Attend student URL: $publicUrl"
    Write-Host "Attend teacher URL: $localUrl"

    $openBrowser = Start-Job -ScriptBlock {
        param($url)
        for ($attempt = 0; $attempt -lt 60; $attempt++) {
            try {
                $reply = Invoke-RestMethod -Uri "$url/api/auth-status" -TimeoutSec 2
                if ($null -ne $reply.configured) { Start-Process "$url/"; return }
            } catch {}
            Start-Sleep -Milliseconds 500
        }
    } -ArgumentList $localUrl

    try {
        & node --experimental-sqlite server.js
        if ($LASTEXITCODE -ne 0) { throw "Attend server exited with code $LASTEXITCODE." }
    } finally {
        Stop-Job $openBrowser -ErrorAction SilentlyContinue
        Remove-Job $openBrowser -Force -ErrorAction SilentlyContinue
    }
} finally {
    Pop-Location
}
