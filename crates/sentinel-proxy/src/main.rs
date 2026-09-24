use std::sync::Arc;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
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

    // Policy can be set globally via environment variable: STRICT, REDACT, or AUDIT
    let default_policy = match std::env::var("SENTINEL_POLICY").as_deref() {
        Ok("REDACT") => SentinelPolicy::Redact,
        Ok("AUDIT") => SentinelPolicy::Audit,
        _ => SentinelPolicy::Strict, // Default to Strict (block jailbreaks)
    };

    let state = Arc::new(AppState {
        engine: StatelessEngine::new(),
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
    // 1. Determine policy (per-request header override "x-sentinel-policy", or fallback to server default)
    let policy = match headers.get("x-sentinel-policy").and_then(|v| v.to_str().ok()) {
        Some(p) if p.eq_ignore_ascii_case("redact") => SentinelPolicy::Redact,
        Some(p) if p.eq_ignore_ascii_case("audit") => SentinelPolicy::Audit,
        Some(p) if p.eq_ignore_ascii_case("strict") => SentinelPolicy::Strict,
        _ => state.default_policy,
    };

    // 2. Inbound inspection: scan messages array
    if let Some(messages) = payload.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for msg in messages {
            if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                let inspection = state.engine.inspect(content, policy);

                match inspection.action {
                    SentinelAction::Block(reason) => {
                        warn!("⛔ Guardrail violation blocked: '{}' | Violations: {:?}", reason, inspection.violations);
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
                    SentinelAction::Redact(ref redacted_terms) => {
                        info!("✏️ Guardrail redacted terms: {:?} | Replacing content in-place", redacted_terms);
                        msg["content"] = json!(inspection.sanitized_text);
                    }
                    SentinelAction::Pass => {
                        // Prompt passed inspection cleanly
                    }
                }
            }
        }
    }

    // 3. Forward clean/redacted request to upstream provider
    let upstream_target = format!("{}/v1/chat/completions", state.upstream_url.trim_end_matches('/'));

    let mut req_builder = state.client.post(&upstream_target);
    for (key, value) in &headers {
        // Forward authentication, custom headers, etc. (skipping host)
        if key != "host" {
            req_builder = req_builder.header(key, value);
        }
    }

    match req_builder.json(&payload).send().await {
        Ok(res) => {
            let status = res.status();
            let body_bytes = res.bytes().await.unwrap_or_default();
            (status, body_bytes).into_response()
        }
        Err(err) => {
            error!("Failed to forward request to upstream: {}", err);
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": {
                        "message": "Sentinel Proxy: upstream connection failed",
                        "type": "bad_gateway"
                    }
                })),
            ).into_response()
        }
    }
}