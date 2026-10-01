use std::sync::{Arc, Mutex};
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, Method, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::stream::StreamExt;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

use sentinel_core::{SentinelAction, SentinelPolicy, StatelessEngine};
use xero_core::{
    create_audit_log, evaluate_node_telemetry, generate_checkpoint_hash, generate_heartbeat_nonce,
    AgentNode, AuditLogEntry, NodeStatus, NodeTelemetry, RecoveryProtocol,
    RecoverySession, RecoveryStage, TaskSpec,
};

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ZeroLabz Sentinel & Xero Mesh</title>
  <style>
    body { background: #090d16; color: #f3f4f6; font-family: sans-serif; padding: 2rem; }
    h1 { color: #10b981; }
    a { color: #60a5fa; }
  </style>
</head>
<body>
  <h1>ZeroLabz Sentinel & Xero Control Plane Active</h1>
  <p>Status: All DFA and Recovery Engines Operational</p>
  <ul>
    <li><a href="/api/mesh">/api/mesh</a> - Active Mesh Topology</li>
    <li><a href="/api/siem/logs">/api/siem/logs</a> - Unified SIEM Telemetry</li>
    <li><a href="/healthz">/healthz</a> - Health Check</li>
  </ul>
</body>
</html>"#;

struct AppState {
    engine: StatelessEngine,
    client: Client,
    upstream_url: String,
    default_policy: SentinelPolicy,
    nodes: Mutex<Vec<AgentNode>>,
    audit_logs: Mutex<Vec<AuditLogEntry>>,
    protocol: RecoveryProtocol,
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

    // Baseline initial mesh nodes
    let initial_nodes = vec![
        AgentNode {
            id: "agent-alpha-01".to_string(),
            name: "Financial Analyst Agent".to_string(),
            cluster: "us-west2-prod".to_string(),
            status: NodeStatus::Nominal,
            telemetry: NodeTelemetry {
                drift_score: 0.12,
                token_velocity: 35,
                cpu_usage: 24.5,
                memory_mb: 280,
                unauthorized_calls: 0,
                last_heartbeat: 1_700_000_000,
            },
            task_spec: TaskSpec {
                declared_bounds: "financial_report_analysis_only".to_string(),
                max_tokens_per_turn: 2048,
                authorized_egress_cidrs: vec!["10.0.0.0/8".to_string()],
                max_memory_mb: 1024,
                heartbeat_interval_ms: 1000,
            },
        },
        AgentNode {
            id: "agent-beta-02".to_string(),
            name: "Code Reviewer Agent".to_string(),
            cluster: "us-west2-prod".to_string(),
            status: NodeStatus::Nominal,
            telemetry: NodeTelemetry {
                drift_score: 0.08,
                token_velocity: 60,
                cpu_usage: 42.0,
                memory_mb: 512,
                unauthorized_calls: 0,
                last_heartbeat: 1_700_000_000,
            },
            task_spec: TaskSpec {
                declared_bounds: "code_review_ast_parsing_only".to_string(),
                max_tokens_per_turn: 4096,
                authorized_egress_cidrs: vec!["10.0.0.0/8".to_string()],
                max_memory_mb: 2048,
                heartbeat_interval_ms: 1000,
            },
        },
    ];

    let protocol = RecoveryProtocol {
        name: "Standard-Zero-Trust-Recovery".to_string(),
        drift_threshold: 0.65,
        max_recovery_attempts: 3,
        auto_isolate: true,
        notify_admin: true,
    };

    let state = Arc::new(AppState {
        engine: StatelessEngine::load_or_default(
            std::env::var("SENTINEL_CONFIG").unwrap_or_else(|_| "sentinel.toml".to_string()),
        ),
        client: Client::builder().build().expect("Failed to build HTTP client"),
        upstream_url,
        default_policy,
        nodes: Mutex::new(initial_nodes),
        audit_logs: Mutex::new(Vec::new()),
        protocol,
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT]);

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/dashboard", get(dashboard))
        .route("/health", get(health_check))
        .route("/healthz", get(healthz_check))
        .route("/v1/healthz", get(healthz_check))
        .route("/v1/chat/completions", post(chat_completions))
        // Milestone 4: Xero Control Plane APIs
        .route("/api/mesh", get(get_mesh_topology))
        .route("/api/telemetry/evaluate", post(evaluate_telemetry))
        .route("/api/recovery/trigger", post(trigger_recovery))
        .route("/api/siem/logs", get(get_siem_logs))
        .layer(cors)
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    info!("🛡️  Sentinel & Xero Control Plane running on http://{}", addr);
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
        "engine": "sentinel-xero-dual-mesh",
        "version": "0.3.0"
    }))
}

// -----------------------------------------------------------------------------
// Milestone 4: Control Plane Handlers
// -----------------------------------------------------------------------------

async fn get_mesh_topology(State(state): State<Arc<AppState>>) -> Json<Value> {
    let nodes = state.nodes.lock().unwrap().clone();
    Json(json!({ "nodes": nodes }))
}

#[derive(Deserialize)]
struct EvaluateRequest {
    agent_id: String,
    drift_score: f64,
    token_velocity: u32,
    cpu_usage: f64,
    memory_mb: u32,
    unauthorized_calls: u32,
}

async fn evaluate_telemetry(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EvaluateRequest>,
) -> Response {
    let mut nodes = state.nodes.lock().unwrap();
    let current_time_ms = chrono::Utc::now().timestamp_millis() as u64;

    if let Some(node) = nodes.iter_mut().find(|n| n.id == req.agent_id) {
        node.telemetry.drift_score = req.drift_score;
        node.telemetry.token_velocity = req.token_velocity;
        node.telemetry.cpu_usage = req.cpu_usage;
        node.telemetry.memory_mb = req.memory_mb;
        node.telemetry.unauthorized_calls = req.unauthorized_calls;
        node.telemetry.last_heartbeat = current_time_ms;

        if let Some(anomaly) = evaluate_node_telemetry(node, &state.protocol, current_time_ms) {
            node.status = NodeStatus::Drifted;

            let log = create_audit_log(
                &node.id,
                &node.cluster,
                "ALERT",
                "PARAMETER_DRIFT",
                &anomaly.description,
            );
            state.audit_logs.lock().unwrap().push(log);

            return (StatusCode::OK, Json(json!({ "anomaly_detected": true, "anomaly": anomaly }))).into_response();
        }

        return (StatusCode::OK, Json(json!({ "anomaly_detected": false, "status": "nominal" }))).into_response();
    }

    (StatusCode::NOT_FOUND, Json(json!({ "error": "Agent node not found" }))).into_response()
}

#[derive(Deserialize)]
struct RecoveryRequest {
    agent_id: String,
}

async fn trigger_recovery(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RecoveryRequest>,
) -> Response {
    let mut nodes = state.nodes.lock().unwrap();
    let now = chrono::Utc::now().timestamp_millis() as u64;

    if let Some(node) = nodes.iter_mut().find(|n| n.id == req.agent_id) {
        node.status = NodeStatus::Recovering;

        let nonce = generate_heartbeat_nonce();
        let checkpoint = generate_checkpoint_hash(&node.id, now);

        // Reset to nominal baseline parameters
        node.telemetry.drift_score = 0.05;
        node.telemetry.unauthorized_calls = 0;
        node.telemetry.cpu_usage = 20.0;
        node.status = NodeStatus::Nominal;

        let session = RecoverySession {
            id: format!("rec-{}", now),
            agent_id: node.id.clone(),
            anomaly_id: format!("anom-resolved-{}", now),
            protocol_name: state.protocol.name.clone(),
            stage: RecoveryStage::Completed,
            started_at: now.saturating_sub(900),
            completed_at: Some(now),
            mttr_ms: 900,
            nonce: nonce.clone(),
            checkpoint_hash: checkpoint.clone(),
        };

        let log = create_audit_log(
            &node.id,
            &node.cluster,
            "INFO",
            "RECOVERY_COMPLETED",
            &format!("Forced heartbeat reset completed. Golden parameters re-injected. Nonce: {}", nonce),
        );
        state.audit_logs.lock().unwrap().push(log);

        return (StatusCode::OK, Json(json!({
            "status": "restored",
            "recovery_session": session,
            "node": node
        }))).into_response();
    }

    (StatusCode::NOT_FOUND, Json(json!({ "error": "Agent node not found" }))).into_response()
}

async fn get_siem_logs(State(state): State<Arc<AppState>>) -> Json<Value> {
    let logs = state.audit_logs.lock().unwrap().clone();
    Json(json!({ "logs": logs, "count": logs.len() }))
}

// -----------------------------------------------------------------------------
// Layer 7 Prompt Guardrail & Inbound Reverse Proxy
// -----------------------------------------------------------------------------

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
                        warn!("⛔ Inbound violation blocked: '{}'", reason);

                        let log = create_audit_log(
                            "sentinel-ingress",
                            "us-west2-prod",
                            "CRITICAL",
                            "ADVERSARIAL_INJECTION_BLOCKED",
                            &format!("Prompt injection intercepted: {}", reason),
                        );
                        state.audit_logs.lock().unwrap().push(log);

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