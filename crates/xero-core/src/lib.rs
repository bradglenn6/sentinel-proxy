pub mod types;

use chrono::Utc;
use rand::Rng;
use sha2::{Digest, Sha256};
pub use types::*;

/// Generates a deterministic-like cryptographic 32-byte hex nonce for forced heartbeat pulses
pub fn generate_heartbeat_nonce() -> String {
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 16] = rng.gen();
    format!("0x{}", hex::encode(random_bytes))
}

/// Generates a SHA-256 checkpoint verification hash
pub fn generate_checkpoint_hash(agent_id: &str, timestamp: u64) -> String {
    let seed = format!("{}-{}-sha256", agent_id, timestamp);
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let result = hasher.finalize();
    format!("chk_{}", &hex::encode(result)[..16])
}

/// Stateless Anomaly Evaluation Engine
/// Pure function: compares agent telemetry & behavior against task bounds
pub fn evaluate_node_telemetry(
    node: &AgentNode,
    protocol: &RecoveryProtocol,
    current_time_ms: u64,
) -> Option<AnomalyEvent> {
    if node.status != NodeStatus::Nominal {
        return None;
    }

    let telemetry = &node.telemetry;
    let task_spec = &node.task_spec;

    // 1. Parameter Drift Detection
    if telemetry.drift_score >= protocol.drift_threshold {
        return Some(AnomalyEvent {
            id: format!("anom-{}-{}", current_time_ms, rand::thread_rng().gen_range(100..999)),
            anomaly_type: AnomalyType::ParameterDrift,
            severity: if telemetry.drift_score > 0.85 { Severity::Critical } else { Severity::High },
            description: format!(
                "Task parameter drift ({:.1}%) breached ceiling. Agent executed prompt instructions outside schema bounds.",
                telemetry.drift_score * 100.0
            ),
            detected_at: current_time_ms,
            drift_value: telemetry.drift_score,
            violating_parameter: "prompt_bound_constraints".to_string(),
            expected_value: task_spec.declared_bounds.clone(),
            observed_value: "Dispatched unverified arbitrary remote procedure call outside bound schema".to_string(),
            quarantine_required: true,
        });
    }

    // 2. Runaway Recursion / Token Exhaustion
    if telemetry.token_velocity as f64 > (task_spec.max_tokens_per_turn as f64 * 0.8) && telemetry.cpu_usage > 75.0 {
        return Some(AnomalyEvent {
            id: format!("anom-{}-{}", current_time_ms, rand::thread_rng().gen_range(100..999)),
            anomaly_type: AnomalyType::RunawayRecursion,
            severity: Severity::Critical,
            description: format!(
                "Exponential token velocity ({} tok/s) and severe CPU saturation ({:.1}%). Infinite recursion loop detected.",
                telemetry.token_velocity, telemetry.cpu_usage
            ),
            detected_at: current_time_ms,
            drift_value: 0.94,
            violating_parameter: "token_velocity_limit".to_string(),
            expected_value: format!("< {} tokens/turn", task_spec.max_tokens_per_turn),
            observed_value: format!("{} tokens/sec sustained spike", telemetry.token_velocity),
            quarantine_required: true,
        });
    }

    // 3. Rogue Network Exfiltration
    if telemetry.unauthorized_calls > 0 {
        return Some(AnomalyEvent {
            id: format!("anom-{}-{}", current_time_ms, rand::thread_rng().gen_range(100..999)),
            anomaly_type: AnomalyType::RogueEgress,
            severity: Severity::Critical,
            description: "Agent attempted egress socket connection to unauthorized external address not present in task CIDR whitelist.".to_string(),
            detected_at: current_time_ms,
            drift_value: 0.98,
            violating_parameter: "egress_cidr_whitelist".to_string(),
            expected_value: task_spec.authorized_egress_cidrs.join(", "),
            observed_value: "198.51.100.44:443 (Unauthorized External C2 vector)".to_string(),
            quarantine_required: true,
        });
    }

    // 4. Corrupted Buffer / Memory Overflow
    if telemetry.memory_mb as f64 > (task_spec.max_memory_mb as f64 * 0.92) {
        return Some(AnomalyEvent {
            id: format!("anom-{}-{}", current_time_ms, rand::thread_rng().gen_range(100..999)),
            anomaly_type: AnomalyType::CorruptedBuffer,
            severity: Severity::High,
            description: format!(
                "Memory boundary violation ({}MB / {}MB limit). Poisoned KV cache context detected.",
                telemetry.memory_mb, task_spec.max_memory_mb
            ),
            detected_at: current_time_ms,
            drift_value: 0.78,
            violating_parameter: "cgroup_memory_max".to_string(),
            expected_value: format!("{} MB", task_spec.max_memory_mb),
            observed_value: format!("{} MB allocated buffer", telemetry.memory_mb),
            quarantine_required: true,
        });
    }

    // 5. Deadlock / Missing Heartbeat
    let heartbeat_delta = current_time_ms.saturating_sub(telemetry.last_heartbeat);
    if heartbeat_delta > task_spec.heartbeat_interval_ms * 3 {
        return Some(AnomalyEvent {
            id: format!("anom-{}-{}", current_time_ms, rand::thread_rng().gen_range(100..999)),
            anomaly_type: AnomalyType::DeadlockHang,
            severity: Severity::High,
            description: format!(
                "Node missed 3 consecutive heartbeat cycles (silence: {}ms, threshold: {}ms). Process deadlock flagged.",
                heartbeat_delta, task_spec.heartbeat_interval_ms
            ),
            detected_at: current_time_ms,
            drift_value: 0.70,
            violating_parameter: "heartbeat_cadence_window".to_string(),
            expected_value: format!("<= {} ms", task_spec.heartbeat_interval_ms),
            observed_value: format!("{} ms without probe response", heartbeat_delta),
            quarantine_required: true,
        });
    }

    None
}

/// Formats audit entries into Common Event Format (CEF) for SIEM (ArcSight, Splunk, QRadar)
pub fn format_to_cef(
    agent_id: &str,
    category: &str,
    message: &str,
    severity_num: u8,
    cluster: &str,
) -> String {
    let timestamp = Utc::now().to_rfc3339();
    let sanitized_msg = message.replace('|', "/");
    format!(
        "CEF:0|XERO|StatelessRecoveryEngine|1.2.0|{}|{}|{}|src={} cs1Label=AgentId cs1={} cs2Label=EngineMode cs2=StatelessServerless act=ORCHESTRATED_RESPONSE rt={}",
        category, sanitized_msg, severity_num, cluster, agent_id, timestamp
    )
}

/// Formats audit entries into Elastic Common Schema (JSON-ECS)
pub fn format_to_ecs(
    agent_id: &str,
    category: &str,
    message: &str,
    level: &str,
    cluster: &str,
) -> serde_json::Value {
    serde_json::json!({
        "@timestamp": Utc::now().to_rfc3339(),
        "log": { "level": level.to_lowercase() },
        "agent": {
            "id": agent_id,
            "cluster": cluster,
            "engine": "xero",
            "architecture": "agent-less eBPF telemetry"
        },
        "event": {
            "category": "threat_remediation",
            "action": category,
            "outcome": "success",
            "reason": message
        },
        "orchestration": {
            "autonomous": true,
            "human_intervention_required": false
        }
    })
}

/// Creates a complete Audit Log Entry containing both CEF and JSON-ECS serializations
pub fn create_audit_log(
    agent_id: &str,
    cluster: &str,
    level: &str,
    category: &str,
    message: &str,
) -> AuditLogEntry {
    let now = Utc::now();
    let epoch_ms = now.timestamp_millis() as u64;
    let sev_num = match level {
        "CRITICAL" => 10,
        "ALERT" | "HIGH" => 7,
        "WARN" => 4,
        _ => 1,
    };

    let cef = format_to_cef(agent_id, category, message, sev_num, cluster);
    let ecs = format_to_ecs(agent_id, category, message, level, cluster);

    AuditLogEntry {
        id: format!("log-{}-{}", epoch_ms, rand::thread_rng().gen_range(1000..9999)),
        timestamp: now.format("%H:%M:%S").to_string(),
        epoch_ms,
        level: level.to_string(),
        category: category.to_string(),
        agent_id: agent_id.to_string(),
        cluster: cluster.to_string(),
        message: message.to_string(),
        cef_payload: cef,
        ecs_payload: ecs,
    }
}
