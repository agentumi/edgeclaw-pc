#![no_main]
use libfuzzer_sys::fuzz_target;
use edgeclaw_agent::transport::{TransportConfig, TransportProtocol, ConnectionMigration};
use edgeclaw_agent::ecnp::FrameCodec;

fuzz_target!(|data: &[u8]| {
    // Fuzz QUIC/transport frame parsing — must never panic
    let _ = FrameCodec::decode(data);
    let _ = serde_json::from_slice::<TransportConfig>(data);
    let _ = serde_json::from_slice::<TransportProtocol>(data);
    let _ = serde_json::from_slice::<ConnectionMigration>(data);

    // Try encode→decode roundtrip with fuzzed payload
    if data.len() >= 2 {
        let msg_type = data[0];
        let payload = &data[1..];
        if let Ok(frame) = FrameCodec::encode(msg_type, payload) {
            let _ = FrameCodec::decode(&frame);
        }
    }
});
