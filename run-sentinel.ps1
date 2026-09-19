[CmdletBinding()]
param (
    [int]$Port = 8080,     [int]$WarmupTimeoutSec = 15
)

$ErrorActionPreference = "Stop"
$ServerProcess =$null

Write-Host ">>> [ZeroLabz Sentinel] Initializing Automation Pipeline..." -ForegroundColor Cyan

try {
    if (-not (Test-Path "node_modules")) {
        Write-Host ">>> Installing dependencies..." -ForegroundColor Yellow
        npm install
    }

    Write-Host ">>> Compiling TypeScript..." -ForegroundColor Yellow
    npm run build

    Write-Host ">>> Starting Sentinel Proxy on port $Port..." -ForegroundColor Yellow
    $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $StartInfo.FileName = "node"
    $StartInfo.Arguments = "dist/server.js"
    $StartInfo.EnvironmentVariables["PORT"] = "$Port"
    $StartInfo.UseShellExecute =$false
    $StartInfo.RedirectStandardOutput =$false
    $StartInfo.RedirectStandardError =$false
    $ServerProcess = [System.Diagnostics.Process]::Start($StartInfo)

    Write-Host ">>> Waiting for proxy health check..." -ForegroundColor Yellow
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $IsHealthy =$false

    while ($Stopwatch.Elapsed.TotalSeconds -lt$WarmupTimeoutSec) {
        try {
            $Response = Invoke-RestMethod -Uri "http://localhost:$Port/healthz" -Method Get -TimeoutSec 1
            if ($Response.status -eq "ok") {
                $IsHealthy =$true
                break
            }
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }

    if (-not $IsHealthy) {
        throw "Sentinel Proxy failed to become healthy within $WarmupTimeoutSec seconds."
    }

    Write-Host ">>> Proxy healthy! ($([math]::Round($Stopwatch.Elapsed.TotalMilliseconds))ms warm-up)" -ForegroundColor Green

    Write-Host "`n>>> Executing Adversarial Load & Latency Benchmark..." -ForegroundColor Cyan
    node benchmark/load_test.js

    if ($LASTEXITCODE -ne 0) {
        throw "Benchmark failed: p99 latency threshold (>4.0ms) exceeded or test failure."
    }

    Write-Host "`n>>> [SUCCESS] All latency targets and security assertions passed!" -ForegroundColor Green

} catch {
    Write-Error "`n>>> [PIPELINE FAILED]: $_"
    exit 1
} finally {
    Write-Host "`n>>> Cleaning up processes..." -ForegroundColor Gray
    if ($ServerProcess -and -not$ServerProcess.HasExited) {
        $ServerProcess.Kill(); $ServerProcess.Dispose()
    }
}

