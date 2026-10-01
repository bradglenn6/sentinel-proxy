use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    Nominal,
    Drifted,
    Isolated,
    Recovering,
    Quarantined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeTelemetry {
    pub drift_score: f64,
    pub token_velocity: u32,
    pub cpu_usage: f64,
    pub memory_mb: u32,
    pub unauthorized_calls: u32,
    pub last_heartbeat: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSpec {
    pub declared_bounds: String,
    pub max_tokens_per_turn: u32,
    pub authorized_egress_cidrs: Vec<String>,
    pub max_memory_mb: u32,
    pub heartbeat_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentNode {
    pub id: String,
    pub name: String,
    pub cluster: String,
    pub status: NodeStatus,
    pub telemetry: NodeTelemetry,
    pub task_spec: TaskSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    ParameterDrift,
    RunawayRecursion,
    RogueEgress,
    CorruptedBuffer,
    DeadlockHang,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warn,
    High,
    Critical,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvent {
    pub id: String,
    pub anomaly_type: AnomalyType,
    pub severity: Severity,
    pub description: String,
    pub detected_at: u64,
    pub drift_value: f64,
    pub violating_parameter: String,
    pub expected_value: String,
    pub observed_value: String,
    pub quarantine_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryProtocol {
    pub name: String,
    pub drift_threshold: f64,
    pub max_recovery_attempts: u32,
    pub auto_isolate: bool,
    pub notify_admin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryStage {
    Detect,
    Isolate,
    Return,
    HeartbeatReset,
    Reinit,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySession {
    pub id: String,
    pub agent_id: String,
    pub anomaly_id: String,
    pub protocol_name: String,
    pub stage: RecoveryStage,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub mttr_ms: u64,
    pub nonce: String,
    pub checkpoint_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: String,
    pub epoch_ms: u64,
    pub level: String,
    pub category: String,
    pub agent_id: String,
    pub cluster: String,
    pub message: String,
    pub cef_payload: String,
    pub ecs_payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminNotification {
    pub id: String,
    pub timestamp: u64,
    pub agent_id: String,
    pub cluster: String,
    pub severity: String,
    pub notif_type: String,
    pub title: String,
    pub summary: String,
    pub recipient: String,
    pub mttr_ms: u64,
    pub delivery_status: String,
    pub verification_hash: String,
}
