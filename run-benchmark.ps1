param (
    [string]\$ServiceUrl = "https://sentinel-proxy-798917645637.us-west2.run.app",
    [string]\$InspectPath = "/v1/chat/completions",
    [string]\$HealthPath = "/v1/healthz",
    [int]$DurationMs = 10000, [switch]$UseGcloudAuth
)

\$ErrorActionPreference = "Stop"

Write-Host "[ZeroLabz Sentinel v1.1.2] Running Cloud Run Guardrail Benchmark..." -ForegroundColor Cyan

\$env:SENTINEL_URL = $ServiceUrl$env:INSPECT_PATH = $InspectPath$env:HEALTH_PATH  = $HealthPath$env:DURATION_MS  = $DurationMs.ToString()$env:SLA_P50_MS   = "65.0"
\$env:SLA_P99_MS   = "110.0"

if (\$UseGcloudAuth) {
    Write-Host "Fetching GCP Identity Token via gcloud..." -ForegroundColor Yellow
    \$token = (gcloud auth print-identity-token).Trim()
    $env:GCP_IDENTITY_TOKEN =$token
} else {
    \$env:GCP_IDENTITY_TOKEN = ""
}

node .\scripts\benchmark-cloudrun.mjs
