use std::sync::Arc;
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::stream::StreamExt;
use reqwest::Client;
use serde_json::{json, Value};
use sentinel_core::{SentinelAction, SentinelPolicy, StatelessEngine};
use tracing::{error, info, warn};

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ZeroLabz Sentinel | Native Rust AI Guardrail Proxy</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --accent: #10b981;
      --accent-glow: rgba(16, 185, 129, 0.2);
      --code-bg: #030712;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background-color: var(--bg); color: var(--text); padding: 2.5rem 1rem; display: flex; justify-content: center; }
    .container { max-width: 860px; width: 100%; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; }
    .logo { font-size: 1.4rem; font-weight: 700; letter-spacing: -0.025em; }
    .logo span { color: var(--accent); }
    .badge { display: flex; align-items: center; gap: 0.5rem; font-size: 0.875rem; background: var(--accent-glow); color: var(--accent); padding: 0.35rem 0.85rem; border-radius: 9999px; border: 1px solid rgba(16, 185, 129, 0.4); }
    .dot { width: 8px; height: 8px; background: var(--accent); border-radius: 50%; box-shadow: 0 0 8px var(--accent); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
    .card-label { font-size: 0.75rem; text-transform: uppercase; color: var(--muted); font-weight: 600; margin-bottom: 0.5rem; }
    .card-val { font-size: 1.6rem; font-weight: 700; color: #fff; }
    .card-sub { font-size: 0.75rem; color: var(--accent); margin-top: 0.25rem; }
    .section-title { font-size: 1.05rem; font-weight: 600; margin-bottom: 0.75rem; color: #e5e7eb; }
    pre { background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.1rem; overflow-x: auto; font-family: monospace; font-size: 0.875rem; color: #e5e7eb; margin-bottom: 2rem; line-height: 1.5; }
    footer { display: flex; justify-content: space-between; font-size: 0.875rem; color: var(--muted); border-top: 1px solid var(--border); padding-top: 1.5rem; }
    a { color: #60a5fa; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">ZeroLabz <span>Sentinel</span></div>
      <div class="badge"><div class="dot"></div> Native Rust DFA Active</div>
    </header>
    <div class="grid">
      <div class="card">
        <div class="card-label">Core DFA Latency</div>
        <div class="card-val">2.7 µs</div>
        <div class="card-sub">p50: 0.0027 ms | p99: 5.7 µs</div>
      </div>
      <div class="card">
        <div class="card-label">Throughput (Concurrent)</div>
        <div class="card-val">864.9k/s</div>
        <div class="card-sub">3.32x Speedup (4 Threads)</div>
      </div>
      <div class="card">
        <div class="card-label">Single-Threaded Peak</div>
        <div class="card-val">334.9k/s</div>
        <div class="card-sub">17.4x over Node.js Baseline</div>
      </div>
      <div class="card">
        <div class="card-label">Cloud Edge SLA</div>
        <div class="card-val">&lt; 0.3 ms</div>
        <div class="card-sub">Target &le; 4.0 ms (Pass)</div>
      </div>
    </div>
    <div class="section-title">Drop-in Integration (OpenAI & Gemini Compatible)</div>
    <pre><code>import OpenAI from 'openai';

const client = new OpenAI({
  apiKey: process.env.MODEL_API_KEY,
  baseURL: 'https://sentinel-proxy-798917645637.us-west2.run.app/v1' // Routed through ZeroLabz Sentinel
});

const response = await client.chat.completions.create({
  model: 'gpt-4o',
  stream: true, // Streaming SSE verified with sliding-window circuit breaker
  messages: [{ role: 'user', content: 'Ultra-low-latency secure inference' }]
});</code></pre>
    <footer>
      <div>Version: v0.2.0-rust | ZeroLabz R&amp;D (Louisiana, USA)</div>
      <div>
        <a href="https://github.com/bradglenn6/sentinel-proxy" target="_blank">GitHub</a> &bull;
        <a href="/healthz">Healthz</a> &bull;
        <a href="/v1/healthz">v1/Healthz</a>
      </div>
    </footer>
  </div>
</body>
</html>"#;

struct AppState {
    engine: StatelessEngine,
    client: Client,
    upstream_url: String,
    default_policy: SentinelPolicy,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let upstream_url = std::env::var("UPSTREAM_URL")
        .unwrap_or_else(|_| "https://api.openai.com".to_string())
        .trim_matches(|c| c == '"' || c == '\'' || c == ' ' || c == '/')
        .to_string();

    let default_policy = match std::env::var("SENTINEL_POLICY").as_deref() {
        Ok("REDACT") => SentinelPolicy::Redact,
        Ok("AUDIT") => SentinelPolicy::Audit,
        _ => SentinelPolicy::Strict,
    };

    let state = Arc::new(AppState {
        engine: StatelessEngine::load_or_default(
            std::env::var("SENTINEL_CONFIG").unwrap_or_else(|_| "sentinel.toml".to_string()),
        ),
        client: Client::builder().build().expect("Failed to build HTTP client"),
        upstream_url,
        default_policy,
    });

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/dashboard", get(dashboard))
        .route("/health", get(health_check))
        .route("/healthz", get(healthz_check))
        .route("/v1/healthz", get(healthz_check))
        .route("/v1/chat/completions", post(chat_completions))
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    info!("🛡️  Sentinel Proxy running on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}

async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn health_check() -> &'static str {
    "OK"
}

async fn healthz_check() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "engine": "stateless-dfa-rust",
        "version": "0.2.0"
    }))
}

async fn chat_completions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut payload): Json<Value>,
) -> Response {
    let policy = match headers.get("x-sentinel-policy").and_then(|v| v.to_str().ok()) {
        Some(p) if p.eq_ignore_ascii_case("redact") => SentinelPolicy::Redact,
        Some(p) if p.eq_ignore_ascii_case("audit") => SentinelPolicy::Audit,
        Some(p) if p.eq_ignore_ascii_case("strict") => SentinelPolicy::Strict,
        _ => state.default_policy,
    };

    if let Some(messages) = payload.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for msg in messages {
            if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                let inspection = state.engine.inspect(content, policy);

                match inspection.action {
                    SentinelAction::Block(reason) => {
                        warn!("⛔ Inbound violation blocked: '{}' | Violations: {:?}", reason, inspection.violations);
                        return (
                            StatusCode::FORBIDDEN,
                            Json(json!({
                                "error": {
                                    "message": format!("Guardrail violation: {}", reason),
                                    "type": "sentinel_policy_violation",
                                    "code": "content_policy_violation",
                                    "violations": inspection.violations
                                }
                            })),
                        ).into_response();
                    }
                    SentinelAction::Redact(ref redacted) => {
                        info!("✏️ Inbound redacted terms: {:?}", redacted);
                        msg["content"] = json!(inspection.sanitized_text);
                    }
                    SentinelAction::Pass => {}
                }
            }
        }
    }

    let is_streaming = payload.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);

    let clean_upstream = state.upstream_url.trim_matches(|c| c == '"' || c == '\'' || c == ' ' || c == '/');
    let upstream_target = format!("{}/v1/chat/completions", clean_upstream);
    let mut req_builder = state.client.post(&upstream_target);

    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        req_builder = req_builder.header("authorization", auth);
    }
    if let Some(org) = headers.get("openai-organization").and_then(|v| v.to_str().ok()) {
        req_builder = req_builder.header("openai-organization", org);
    }
    if let Some(proj) = headers.get("openai-project").and_then(|v| v.to_str().ok()) {
        req_builder = req_builder.header("openai-project", proj);
    }
    if let Some(key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        req_builder = req_builder.header("x-api-key", key);
    }

    let upstream_res = match req_builder.json(&payload).send().await {
        Ok(res) => res,
        Err(err) => {
            error!("Upstream connection failed: {:?} | source: {:?}", err, std::error::Error::source(&err));
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": {
                        "message": format!("Sentinel Proxy: upstream connection failed ({})", err),
                        "type": "bad_gateway"
                    }
                })),
            ).into_response();
        }
    };

    let status = upstream_res.status();

    if is_streaming && status.is_success() {
        let state_clone = Arc::clone(&state);
        let upstream_stream = upstream_res.bytes_stream();
        let mut sliding_window = String::with_capacity(1024);

        let sse_stream = async_stream::stream! {
            tokio::pin!(upstream_stream);

            while let Some(chunk_result) = upstream_stream.next().await {
                match chunk_result {
                    Ok(bytes) => {
                        if let Ok(text) = std::str::from_utf8(&bytes) {
                            sliding_window.push_str(text);

                            if sliding_window.len() > 512 {
                                let trim_idx = sliding_window.len() - 512;
                                sliding_window.drain(..trim_idx);
                            }

                            let inspection = state_clone.engine.inspect(&sliding_window, policy);
                            if let SentinelAction::Block(reason) = inspection.action {
                                warn!("🚨 Outbound streaming leak intercepted: '{}'. Tripping circuit breaker!", reason);
                                yield Ok::<_, std::io::Error>(bytes::Bytes::from(format!(
                                    "data: {}\n\ndata: [DONE]\n\n",
                                    json!({
                                        "error": {
                                            "message": format!("Outbound guardrail triggered: {}", reason),
                                            "type": "sentinel_stream_violation",
                                            "code": "leak_detected"
                                        }
                                    })
                                )));
                                break;
                            }
                        }
                        yield Ok(bytes);
                    }
                    Err(e) => {
                        error!("Error reading upstream chunk: {}", e);
                        break;
                    }
                }
            }
        };

        return (
            status,
            [
                (header::CONTENT_TYPE, "text/event-stream"),
                (header::CACHE_CONTROL, "no-cache"),
                (header::CONNECTION, "keep-alive"),
            ],
            Body::from_stream(sse_stream),
        ).into_response();
    }

    let body_bytes = upstream_res.bytes().await.unwrap_or_default();
    (status, body_bytes).into_response()
}