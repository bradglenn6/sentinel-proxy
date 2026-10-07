use criterion::{black_box, criterion_group, criterion_main, Criterion};
use xero_core::{evaluate_node_telemetry, AgentNode, NodeTelemetry, RecoveryProtocol, NodeStatus, TaskSpec};

fn bench_anomaly_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Xero Core Evaluation");
    
    // 1. Fully populated Recovery Protocol
    let protocol = RecoveryProtocol {
        name: "ZeroTrust_ETL_Protocol".to_string(),
        drift_threshold: 0.65,
        max_recovery_attempts: 3,
        auto_isolate: true,
        notify_admin: true,
    };

    // 2. Fully populated Agent Node mapped to your structs
    let nominal_node = AgentNode {
        id: "agent-001".to_string(),
        name: "etl-ingestion-node".to_string(),
        cluster: "us-west2-prod".to_string(),
        status: NodeStatus::Nominal,
        telemetry: NodeTelemetry {
            drift_score: 0.12,
            token_velocity: 150,
            cpu_usage: 22.4,
            memory_mb: 256,
            unauthorized_calls: 0,
            last_heartbeat: 1000,
        },
        task_spec: TaskSpec {
            declared_bounds: "Data_Ingestion_Boundary".to_string(),
            max_tokens_per_turn: 2000,
            authorized_egress_cidrs: vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()],
            max_memory_mb: 1024,
            heartbeat_interval_ms: 500,
        }
    };

    let current_time: u64 = 1500; // Simulated current time in milliseconds

    // 3. Benchmark the pure evaluation function
    group.bench_function("Nominal Telemetry Parsing", |b| {
        b.iter(|| {
            let result = evaluate_node_telemetry(
                black_box(&nominal_node),
                black_box(&protocol),
                black_box(current_time)
            );
            black_box(result);
        })
    });
    
    group.finish();
}

criterion_group!(benches, bench_anomaly_evaluation);
criterion_main!(benches);