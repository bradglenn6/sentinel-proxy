use std::sync::Arc;
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::stream::StreamExt;
use reqwest::Client;
use serde_json::{json, Value};
use sentinel_core::{SentinelAction, SentinelPolicy, StatelessEngine};
use tracing::{error, info, warn};

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
        .unwrap_or_else(|_| "https://api.openai.com".to_string());

    let default_policy = match std::env::var("SENTINEL_POLICY").as_deref() {
        Ok("REDACT") => SentinelPolicy::Redact,
        Ok("AUDIT") => SentinelPolicy::Audit,
        _ => SentinelPolicy::Strict,
    };

    let state = Arc::new(AppState {
        engine: StatelessEngine::load_or_default(
            std::env::var("SENTINEL_CONFIG").unwrap_or_else(|_| "sentinel.toml".to_string())
        ),
        client: Client::builder().build().expect("Failed to build HTTP client"),
        upstream_url,
        default_policy,
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/v1/chat/completions", post(chat_completions))
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    info!("🛡️  Sentinel Proxy running on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> &'static str {
    "OK"
}

async fn chat_completions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut payload): Json<Value>,
) -> Response {
    // 1. Determine policy (header override or server default)
    let policy = match headers.get("x-sentinel-policy").and_then(|v| v.to_str().ok()) {
        Some(p) if p.eq_ignore_ascii_case("redact") => SentinelPolicy::Redact,
        Some(p) if p.eq_ignore_ascii_case("audit") => SentinelPolicy::Audit,
        Some(p) if p.eq_ignore_ascii_case("strict") => SentinelPolicy::Strict,
        _ => state.default_policy,
    };

    // 2. Inbound inspection: scan messages
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

    // Check if the client requested streaming
    let is_streaming = payload.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);

    // 3. Build upstream request
    let upstream_target = format!("{}/v1/chat/completions", state.upstream_url.trim_end_matches('/'));
    let mut req_builder = state.client.post(&upstream_target);

    // Explicitly pass authentication and client headers
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

    // 4. Handle Streaming Response
    if is_streaming && status.is_success() {
        let state_clone = Arc::clone(&state);
        let upstream_stream = upstream_res.bytes_stream();

        // 512-byte sliding window ring buffer across chunk boundaries
        let mut sliding_window = String::with_capacity(1024);

        let sse_stream = async_stream::stream! {
            tokio::pin!(upstream_stream);

            while let Some(chunk_result) = upstream_stream.next().await {
                match chunk_result {
                    Ok(bytes) => {
                        if let Ok(text) = std::str::from_utf8(&bytes) {
                            sliding_window.push_str(text);

                            // Keep sliding window at maximum ~512 characters
                            if sliding_window.len() > 512 {
                                let trim_idx = sliding_window.len() - 512;
                                sliding_window.drain(..trim_idx);
                            }

                            // Run DFA scan over the sliding window
                            let inspection = state_clone.engine.inspect(&sliding_window, policy);
                            if let SentinelAction::Block(reason) = inspection.action {
                                warn!("🚨 Outbound streaming leak intercepted: '{}'. Tripping circuit breaker!", reason);
                                
                                // Emit structured SSE violation and terminate stream
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

                        // Emit safe chunk downstream immediately
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

    // 5. Non-streaming fallback
    let body_bytes = upstream_res.bytes().await.unwrap_or_default();
    (status, body_bytes).into_response()
}