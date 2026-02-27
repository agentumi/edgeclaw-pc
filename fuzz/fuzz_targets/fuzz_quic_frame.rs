#![no_main]
use libfuzzer_sys::fuzz_target;
use edgeclaw_agent::transport::{TransportConfig, TransportProtocol, ConnectionMigration};
use edgeclaw_agent::ecnp::EcnpCodec;
use edgeclaw_agent::protocol::MessageType;

fuzz_target!(|data: &[u8]| {
    // Fuzz QUIC/transport frame parsing — must never panic
    let _ = EcnpCodec::decode(data);
    let _ = serde_json::from_slice::<TransportConfig>(data);
    let _ = serde_json::from_slice::<TransportProtocol>(data);
    let _ = serde_json::from_slice::<ConnectionMigration>(data);

    // Try encode→decode roundtrip with fuzzed payload
    if data.len() >= 2 {
        let msg_type_raw = data[0];
        let payload = &data[1..];
        if let Ok(mt) = MessageType::try_from(msg_type_raw) {
            if let Ok(frame) = EcnpCodec::encode(mt, payload) {
                let _ = EcnpCodec::decode(&frame);
            }
        }
    }
});
