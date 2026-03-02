//! Benchmarks for core EdgeClaw operations.
//!
//! Run with: `cargo bench`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use edgeclaw_agent::protocol::MessageType;

// ─── Helper: build sample ActivityEntry ───────────────────

fn sample_activity_entry(i: usize) -> edgeclaw_agent::activity_log::ActivityEntry {
    use chrono::Utc;
    use uuid::Uuid;
    edgeclaw_agent::activity_log::ActivityEntry {
        id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        agent_id: "dev-1".into(),
        agent_role: "admin".into(),
        agent_name: "agent-1".into(),
        activity_type: edgeclaw_agent::activity_log::ActivityType::FileEdit {
            before_snippet: Some("old".into()),
            after_snippet: Some("new".into()),
            lines_changed: 10,
        },
        project: "edgeclaw".into(),
        file_path: Some("src/main.rs".into()),
        content: format!("Activity entry {} with description", i),
        tags: vec!["rust".into(), "perf".into()],
        importance: (i % 4) as u8,
        timestamp: Utc::now(),
        lamport_clock: i as u64,
        prev_hash: "0".repeat(64),
        hash: format!("hash_{}", i),
        signature: String::new(),
    }
}

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

fn bench_cbor_vs_json(c: &mut Criterion) {
    use edgeclaw_agent::cbor_encoding::{
        decode_activities_cbor, encode_activities_cbor, PayloadEncoding,
    };
    use edgeclaw_agent::team_sync::TeamSyncMessage;

    // Build 100 sample entries
    let entries: Vec<edgeclaw_agent::activity_log::ActivityEntry> =
        (0..100).map(sample_activity_entry).collect();

    // ── Encoding speed ──────────────────────────────────

    c.bench_function("json_encode_100_entries", |b| {
        b.iter(|| serde_json::to_vec(black_box(&entries)).unwrap())
    });

    c.bench_function("cbor_encode_100_entries", |b| {
        b.iter(|| encode_activities_cbor(black_box(&entries)).unwrap())
    });

    // ── Decoding speed ──────────────────────────────────

    let json_bytes = serde_json::to_vec(&entries).unwrap();
    let cbor_bytes = encode_activities_cbor(&entries).unwrap();

    c.bench_function("json_decode_100_entries", |b| {
        b.iter(|| {
            serde_json::from_slice::<Vec<edgeclaw_agent::activity_log::ActivityEntry>>(black_box(
                &json_bytes,
            ))
            .unwrap()
        })
    });

    c.bench_function("cbor_decode_100_entries", |b| {
        b.iter(|| decode_activities_cbor(black_box(&cbor_bytes)).unwrap())
    });

    // ── TeamSyncMessage encode/decode ───────────────────

    let msg = TeamSyncMessage::ActivityBroadcast {
        entries: entries.clone(),
    };

    c.bench_function("team_sync_json_encode", |b| {
        b.iter(|| black_box(&msg).encode(PayloadEncoding::Json).unwrap())
    });

    c.bench_function("team_sync_cbor_encode", |b| {
        b.iter(|| black_box(&msg).encode(PayloadEncoding::Cbor).unwrap())
    });

    let msg_json = msg.encode(PayloadEncoding::Json).unwrap();
    let msg_cbor = msg.encode(PayloadEncoding::Cbor).unwrap();

    c.bench_function("team_sync_json_decode", |b| {
        b.iter(|| {
            TeamSyncMessage::decode(black_box(&msg_json), PayloadEncoding::Json).unwrap()
        })
    });

    c.bench_function("team_sync_cbor_decode", |b| {
        b.iter(|| {
            TeamSyncMessage::decode(black_box(&msg_cbor), PayloadEncoding::Cbor).unwrap()
        })
    });

    // ── Size comparison (printed once) ──────────────────

    eprintln!(
        "\n[bench] 100 entries: JSON = {} bytes, CBOR = {} bytes, saving = {:.1}%",
        json_bytes.len(),
        cbor_bytes.len(),
        (1.0 - cbor_bytes.len() as f64 / json_bytes.len() as f64) * 100.0
    );
}

criterion_group!(
    benches,
    bench_ecnp_encode_decode,
    bench_policy_evaluate,
    bench_metrics_operations,
    bench_cbor_vs_json,
);
criterion_main!(benches);
