use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinel_core::{StatelessEngine, SentinelPolicy};

fn bench_sentinel_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sentinel Core Evaluation");
    
    // 1. Initialize the stateless engine with the default DFA RegexSet rules
    let engine = StatelessEngine::new();

    // 2. Simulate an unstructured payload containing an API key that needs PII redaction
    let malicious_payload = "The architectural metadata maps to the following key: API_KEY=AKIAIOSFODNN7EXAMPLEREDACT. Proceed with parsing.";

    // 3. Benchmark the pure single-pass DFA and PII redaction evaluation function
    group.bench_function("DFA Regex & PII Redaction", |b| {
        b.iter(|| {
            // We use SentinelPolicy::Redact to ensure the regex replace_all logic is fully executed
            let result = engine.inspect(
                black_box(malicious_payload),
                black_box(SentinelPolicy::Redact)
            );
            black_box(result);
        })
    });
    
    group.finish();
}

criterion_group!(benches, bench_sentinel_evaluation);
criterion_main!(benches);