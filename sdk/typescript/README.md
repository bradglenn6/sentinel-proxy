# ZeroLabz Sentinel

[![Sentinel Continuous Integration & Deployment](https://github.com/bradglenn6/sentinel-proxy/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/bradglenn6/sentinel-proxy/actions/workflows/ci-cd.yml)
[![npm version](https://img.shields.io/npm/v/zerolabz-sentinel.svg)](https://www.npmjs.com/package/zerolabz-sentinel)
[![PyPI version](https://img.shields.io/pypi/v/zerolabz-sentinel.svg)](https://pypi.org/project/zerolabz-sentinel/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Latency SLA](https://img.shields.io/badge/p99_latency-%3C0.35ms-brightgreen)](https://docs.google.com/document/d/1dGFWRzoBd9nVlU-M8-ilLVsIw1-31Me4KVpjtxM_Bg4/edit)

Sub-millisecond stateless AI guardrail reverse proxy and inference security gateway. Intercepts prompt injections, persona overrides, and credential leaks before model invocation with inline PII sanitization.

---

## Production Endpoints

* **Base Ingress URL:** `https://sentinel.zrolabz.com/v1`
* **Inference Endpoint:** `https://sentinel.zrolabz.com/v1/chat/completions`
* **Health Check:** `https://sentinel.zrolabz.com/v1/healthz`
* **Status Dashboard:** `https://sentinel.zrolabz.com/`

---

## Client SDK Installation

Install the official drop-in client SDK across Python and JavaScript/TypeScript ecosystems:

### Python
```bash
pip install zerolabz-sentinel
from zerolabz_sentinel import Sentinel

# 1. Initialize client
sentinel = Sentinel(base_url="[https://sentinel.zrolabz.com/v1](https://sentinel.zrolabz.com/v1)")

# 2. Get pre-configured OpenAI client
client = sentinel.create_openai_client()

# 3. Invoke model
response = client.chat.completions.create(
    model="gemini-1.5-flash",
    messages=[{"role": "user", "content": "Explain zero-trust architecture"}]
)

print(response.choices[0].message.content)
import { SentinelClient } from 'zerolabz-sentinel';

const sentinel = new SentinelClient({
  baseUrl: '[https://sentinel.zrolabz.com/v1](https://sentinel.zrolabz.com/v1)',
  policy: 'redact'
});

const config = sentinel.getOpenAIConfig();
// Use with official OpenAI SDK or direct fetch
