<div align="center">

# 🛡️ ZeroLabz Sentinel & Xero-Core
### Deterministic Post-Quantum AI Guardrail, Autonomous Runtime EDR & Zero-Trust Industrial HAL

[![npm version](https://img.shields.io/npm/v/zerolabz-sentinel.svg?style=flat-square&color=blue)](https://www.npmjs.com/package/zerolabz-sentinel)
[![Inspect AI Audit](https://img.shields.io/badge/Inspect_AI_Eval-1.000_(100%25)-brightgreen?style=flat-square)](#3-empirical-verification--benchmarks)
[![L7 DFA Latency](https://img.shields.io/badge/L7_Sentinel_DFA-2.48_µs-success?style=flat-square)](#3-empirical-verification--benchmarks)
[![L4 Xero Latency](https://img.shields.io/badge/L4_Xero_Core-7.51_ns-success?style=flat-square)](#3-empirical-verification--benchmarks)
[![PQC Compliance](https://img.shields.io/badge/NIST_PQC-FIPS_203_%2F_204_(ML--KEM--1024)-orange?style=flat-square)](#2-dual-tier-defense--industrial-hal-architecture)
[![DoD Zero Trust](https://img.shields.io/badge/DoD_ZTA-Pillars_4%2C_5%2C_7-informational?style=flat-square)](#5-dod-zero-trust--siem-observability)

**[Live Telemetry Dashboard](https://bradglenn6.github.io/sentinel-proxy/) • [Cloud Run Proxy Endpoint](https://sentinel.zrolabz.com/v1/chat/completions) • [ZeroLabz Portal](https://zrolabz.com)**

</div>

---

## 1. Overview: Zero-Trust Security at the Theoretical Limits of Hardware

Modern AI orchestration and industrial Operational Technology (OT) face a fatal latency paradox:
1. **At the Cloud / Agent Layer (L7):** Secondary LLM-based guardrails introduce **50–200 ms** of latency and massive GPU overhead, while remaining vulnerable to probabilistic jailbreaks, delimiter injections, and ReDoS attacks.
2. **At the Runtime & Industrial Edge Layer (L4 / OT):** Legacy field protocols (**Modbus RTU/TCP, CANopen, PROFINET**) require deterministic **< 350 µs** execution budgets, making standard Post-Quantum Cryptography (**NIST FIPS 203 ML-KEM-1024**, which takes ~85.7 ms on edge MCUs) impossible to deploy directly without breaking real-time safety loops.

**ZeroLabz** permanently resolves both bottlenecks. Engineered in **Node.js (Fastify)** and **Native Rust (`NAPI-RS` / AVX2 SIMD / `liboqs`)**, this repository provides a coordinated, dual-tier defense mesh and zero-copy Hardware Abstraction Layer (HAL) that intercepts adversarial AI threats in **2.48 µs**, evaluates runtime behavioral drift in **7.51 ns**, and encapsulates industrial telemetry inside **ML-KEM-1024** post-quantum tunnels with **Open Policy Agent (OPA) Rego** verification in **0.29 ms**.

---

## 2. Dual-Tier Defense & Industrial HAL Architecture

| Defense Tier | Component | Target Layer | Core Engine & Cryptography | Verified SLA / Performance |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Pre-Execution Interception** | `sentinel-core` / `sentinel-proxy` | **Layer 7** (Application / LLM API Boundary) | Native Rust $O(1)$ Deterministic Finite Automaton (DFA) `RegexSet` via `NAPI-RS` | **2.48 µs** Strict block (**378,847 req/s/core**)<br>**6.06 µs** Inline PII Redaction<br>**100% TPR / 0% FPR** (`inspect_ai`) |
| **Tier 2: Runtime Containment & Self-Healing** | `crates/xero-core` | **Layer 4** (OS Runtime / Agent Execution) | AVX2 SIMD Telemetry Evaluator + Out-of-Band **eBPF** Socket Isolation + SHA-256 Checkpointing | **7.51 ns – 8.28 ns** baseline (~133M evals/s)<br>**456 ns** 5-mode full drift & SIEM check<br>**3.7 s** autonomous 4-stage node recovery |
| **Tier 3: Post-Quantum Industrial HAL** | ZeroLabz HAL & Telemetry Broker | **Layer 1–4** (Modbus, CANopen, PROFINET, MQTT) | Zero-Copy Memory-Mapped Proxy + **NIST FIPS 203/204 (`ML-KEM-1024` / `ML-DSA`)** + **OPA Rego** | **0.29 ms** unified PQC + OPA Rego loop<br>**28 µs** rogue AI physical write intercept<br>**34,600 msg/s** HNDL-shielded MQTT |
| **Tier 4: Unified SOC Observability** | Shared SIEM Pipeline | **Telemetry** (Enterprise SecOps) | Native **ArcSight/Splunk (`CEF:0`)** & **Elastic/Datadog (`JSON-ECS`)** serializers | **864,953 req/s** peak parallel validation across 4 lock-free worker threads |

### Transactional Pipeline Topology

```text
[Legacy Field Device / AI Agent]      [ZeroLabz HAL / Proxy]           [xero-core Engine]          [Upstream LLM / MQTT Broker]
 (Modbus / CANopen / HTTP JSON)       (Memory-Mapped / NAPI-RS)        (O(1) DFA + SIMD + OPA)       (ML-KEM-1024 Shielded)
               |                                  |                                |                             |
               |--- 1. Ingress Payload ---------->|                                |                             |
               |                                  |--- 2. SIMD Telemetry Check --->|                             |
               |                                  |    (7.51 ns - 456 ns)          |                             |
               |                                  |<-- Nominal / Drift Status -----|                             |
               |                                  |                                |                             |
               |===================================================================|                             |
               |        UNIFIED DETERMINISTIC PIPELINE (2.48 µs L7 / 0.29 ms PQC)  |                             |
               |        - Single-Pass O(1) DFA Jailbreak & Delimiter Preemption    |                             |
               |        - Inline Single-Pass PII Masking ([REDACTED_SSN/KEY])      |                             |
               |        - Asynchronous ML-KEM-1024 Decapsulation + OPA Rego Eval   |                             |
               |===================================================================|                             |
               |                                  |                                |                             |
               |                                  |--- 3. Verified / Redacted Payload -------------------------->|
               |                                  |    (34,600 MQTT msg/s | 5,032 HTTP RPS)                      |
               |                                  |                                |                             |
               |===================================================================|                             |
               |        ADVERSARIAL / ROGUE AGENT INTERCEPT (Short-Circuit)        |                             |
               |<-- HTTP 400/403 Drop (28 µs) ----|<-- ROGUE_AGENT_CALL_DETECTED --|                             |
               |X-- Physical Memory Write Blocked |--- eBPF Isolate & CEF/ECS Log -> [4-Stage Auto-Recovery]     |