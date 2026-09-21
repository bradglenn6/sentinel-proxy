# Strict Safety Guardrails Preset

High-assurance security preset designed for sensitive production pipelines (healthcare, finance, enterprise SaaS) requiring zero-tolerance PII leakage and aggressive prompt injection interception.

## Threat Vector Coverage
* **OWASP LLM01:** Delimiter injection, system prompt extraction, persona hijacking.
* **OWASP LLM02:** Credit cards, SSNs, raw API keys, bearer tokens, private keys.

## Verification (PowerShell)
```powershell
.\test.ps1 -Endpoint "https://sentinel-proxy-798917645637.us-west2.run.app/v1/chat/completions"
```
