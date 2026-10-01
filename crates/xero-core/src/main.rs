use std::time::Instant;
use xero_core::*;

fn main() {
    println!("======================================================");
    println!("    XERO ENGINE: DRIFT DETECTION & SIEM BENCHMARK    ");
    println!("======================================================");

    let protocol = RecoveryProtocol {
        name: "Standard-Zero-Trust-Recovery".to_string(),
        drift_threshold: 0.65,
        max_recovery_attempts: 3,
        auto_isolate: true,
        notify_admin: true,
    };

    let nominal_node = AgentNode {
        id: "agent-001".to_string(),
        name: "Financial-Summarizer".to_string(),
        cluster: "us-west2-prod".to_string(),
        status: NodeStatus::Nominal,
        telemetry: NodeTelemetry {
            drift_score: 0.12,
            token_velocity: 45,
            cpu_usage: 22.4,
            memory_mb: 256,
            unauthorized_calls: 0,
            last_heartbeat: 1_000_000,
        },
        task_spec: TaskSpec {
            declared_bounds: "financial_report_analysis_only".to_string(),
            max_tokens_per_turn: 2048,
            authorized_egress_cidrs: vec!["10.0.0.0/8".to_string()],
            max_memory_mb: 1024,
            heartbeat_interval_ms: 1000,
        },
    };

    let mut drifted_node = nominal_node.clone();
    drifted_node.telemetry.drift_score = 0.88;

    // 1. Verify functional evaluation
    println!(">>> Testing Functional Anomaly Detection...");
    let nominal_eval = evaluate_node_telemetry(&nominal_node, &protocol, 1_000_500);
    assert!(nominal_eval.is_none(), "Nominal node must not trigger anomaly");
    println!("[PASS] Nominal Node: No false positive detected.");

    let drifted_eval = evaluate_node_telemetry(&drifted_node, &protocol, 1_000_500).expect("Must detect drift");
    assert_eq!(drifted_eval.anomaly_type, AnomalyType::ParameterDrift);
    println!("[PASS] Drifted Node: Caught {:?} (Severity: {:?})", drifted_eval.anomaly_type, drifted_eval.severity);

    // 2. Nonce and SIEM serialization test
    let nonce = generate_heartbeat_nonce();
    let chk = generate_checkpoint_hash(&drifted_node.id, 1_000_500);
    let log_entry = create_audit_log(
        &drifted_node.id,
        &drifted_node.cluster,
        "CRITICAL",
        "AUTONOMOUS_ISOLATION",
        "Task schema drift breached 85%. Executed eBPF socket block.",
    );
    println!("[PASS] Heartbeat Nonce: {}", nonce);
    println!("[PASS] Checkpoint Hash: {}", chk);
    println!("[PASS] CEF Payload:     {}", &log_entry.cef_payload[..80]);

    // 3. High-load microbenchmark (100,000 iterations)
    println!("\n>>> Running 100,000-iteration Xero Evaluation Benchmark...");
    let iterations = 100_000;
    let mut latencies_nanos = Vec::with_capacity(iterations);

    let start_total = Instant::now();
    for i in 0..iterations {
        let node = if i % 2 == 0 { &nominal_node } else { &drifted_node };
        let t0 = Instant::now();
        let _ = evaluate_node_telemetry(node, &protocol, 1_000_500);
        latencies_nanos.push(t0.elapsed().as_nanos());
    }
    let total_duration = start_total.elapsed();
    latencies_nanos.sort_unstable();

    let avg_ns = latencies_nanos.iter().sum::<u128>() as f64 / iterations as f64;
    let p50_ns = latencies_nanos[iterations * 50 / 100];
    let p90_ns = latencies_nanos[iterations * 90 / 100];
    let p99_ns = latencies_nanos[iterations * 99 / 100];
    let throughput = iterations as f64 / total_duration.as_secs_f64();

    println!("======================================================");
    println!("Total Invocations: {}", iterations);
    println!("Throughput:        {:.1} evaluations/sec", throughput);
    println!("------------------------------------------------------");
    println!("Mean Latency:      {:.3} µs", avg_ns / 1_000.0);
    println!("p50 Latency:       {:.3} µs", p50_ns as f64 / 1_000.0);
    println!("p90 Latency:       {:.3} µs", p90_ns as f64 / 1_000.0);
    println!("p99 Latency:       {:.3} µs", p99_ns as f64 / 1_000.0);
    println!("======================================================");
}
