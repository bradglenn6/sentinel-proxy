# Anti-Rogue Agent Guardrail Preset

Intercepts autonomous agent breakout attempts, unconstrained shell execution, reverse shell creation, and tool-call loops in under 0.4 milliseconds.

## Configuration (`config.json`)
Enforces maximum tool-call thresholds per cycle and applies deterministic regex scanners to `tool_calls[].function.arguments`.

## Verification (PowerShell)
```powershell
.\test.ps1 -Endpoint "https://sentinel-proxy-798917645637.us-west2.run.app/v1/chat/completions"
```
