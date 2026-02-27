//! Benchmarks for core EdgeClaw operations.
//!
//! Run with: `cargo bench`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use edgeclaw_agent::protocol::MessageType;

fn bench_ecnp_encode_decode(c: &mut Criterion) {
    let payload = vec![0xABu8; 256];

    c.bench_function("ecnp_encode", |b| {
        b.iter(|| {
            edgeclaw_agent::ecnp::EcnpCodec::encode(
                black_box(MessageType::Data),
                black_box(&payload),
            )
        })
    });

    let encoded = edgeclaw_agent::ecnp::EcnpCodec::encode(MessageType::Data, &payload).unwrap();
    c.bench_function("ecnp_decode", |b| {
        b.iter(|| edgeclaw_agent::ecnp::EcnpCodec::decode(black_box(&encoded)))
    });
}

fn bench_policy_evaluate(c: &mut Criterion) {
    let engine = edgeclaw_agent::policy::PolicyEngine::new();

    c.bench_function("policy_evaluate_owner", |b| {
        b.iter(|| engine.evaluate(black_box("owner"), black_box("shell_exec")))
    });

    c.bench_function("policy_evaluate_viewer", |b| {
        b.iter(|| engine.evaluate(black_box("viewer"), black_box("status_query")))
    });
}

fn bench_metrics_operations(c: &mut Criterion) {
    let reg = edgeclaw_agent::metrics::MetricsRegistry::with_defaults();

    c.bench_function("metrics_inc_counter", |b| {
        b.iter(|| {
            reg.inc_counter(black_box("edgeclaw_commands_total"), 1.0);
        })
    });

    c.bench_function("metrics_set_gauge", |b| {
        b.iter(|| {
            reg.set_gauge(black_box("edgeclaw_cpu_usage_percent"), 42.0);
        })
    });

    c.bench_function("metrics_observe_histogram", |b| {
        b.iter(|| {
            reg.observe_histogram(black_box("edgeclaw_command_duration_seconds"), 0.5);
        })
    });

    // Populate some data then bench rendering
    for _ in 0..100 {
        reg.inc_counter("edgeclaw_commands_total", 1.0);
        reg.observe_histogram("edgeclaw_command_duration_seconds", 0.123);
    }
    c.bench_function("metrics_render_prometheus", |b| {
        b.iter(|| {
            black_box(reg.render_prometheus());
        })
    });
}

criterion_group!(
    benches,
    bench_ecnp_encode_decode,
    bench_policy_evaluate,
    bench_metrics_operations,
);
criterion_main!(benches);
