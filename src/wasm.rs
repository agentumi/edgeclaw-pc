//! WebAssembly protocol bridge.
//!
//! Provides WASM-compatible wrappers around the ECNP protocol codec and
//! message types. When compiled to `wasm32-unknown-unknown`, these functions
//! are exported for use from JavaScript or other WASM hosts.
//!
//! # Usage (native)
//!
//! ```
//! use edgeclaw_agent::wasm::{wasm_ecnp_encode, wasm_ecnp_decode};
//!
//! let frame = wasm_ecnp_encode(0x04, b"heartbeat-payload");
//! assert!(!frame.is_empty());
//! let (msg_type, payload) = wasm_ecnp_decode(&frame).unwrap();
//! assert_eq!(msg_type, 0x04);
//! assert_eq!(payload, b"heartbeat-payload");
//! ```

use crate::ecnp::EcnpCodec;
use crate::error::AgentError;
use crate::protocol::MessageType;

/// Encode a payload into an ECNP binary frame.
///
/// Returns the full frame bytes (header + payload).
/// `msg_type_raw`: 0x01=Handshake, 0x02=Data, 0x03=Control, 0x04=Heartbeat,
///                 0x05=Error, 0x06=Auth, 0x07=Telemetry, 0x08=PolicyUpdate.
pub fn wasm_ecnp_encode(msg_type_raw: u8, payload: &[u8]) -> Vec<u8> {
    let msg_type = match msg_type_raw {
        0x01 => MessageType::Handshake,
        0x02 => MessageType::Data,
        0x03 => MessageType::Control,
        0x04 => MessageType::Heartbeat,
        0x05 => MessageType::Error,
        0x06 => MessageType::Auth,
        0x07 => MessageType::Telemetry,
        0x08 => MessageType::PolicyUpdate,
        _ => MessageType::Data, // fallback
    };
    EcnpCodec::encode(msg_type, payload).unwrap_or_default()
}

/// Decode an ECNP binary frame into (msg_type, payload).
pub fn wasm_ecnp_decode(data: &[u8]) -> Result<(u8, Vec<u8>), AgentError> {
    let msg = EcnpCodec::decode(data)?;
    Ok((msg.msg_type, msg.payload))
}

/// Validate an ECNP frame without extracting payload.
pub fn wasm_ecnp_validate(data: &[u8]) -> bool {
    EcnpCodec::decode(data).is_ok()
}

/// Get the ECNP protocol version string.
pub fn wasm_protocol_version() -> &'static str {
    "ECNP/1.1"
}

/// Supported WASM export format info.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WasmBridgeInfo {
    /// Protocol version.
    pub protocol: &'static str,
    /// Bridge version.
    pub bridge_version: &'static str,
    /// Supported message types.
    pub message_types: Vec<&'static str>,
    /// Target triple.
    pub target: &'static str,
}

/// Get WASM bridge metadata.
pub fn wasm_bridge_info() -> WasmBridgeInfo {
    WasmBridgeInfo {
        protocol: wasm_protocol_version(),
        bridge_version: "1.0.0",
        message_types: vec![
            "Handshake",
            "Data",
            "Control",
            "Heartbeat",
            "Error",
            "Auth",
            "Telemetry",
            "PolicyUpdate",
        ],
        target: if cfg!(target_arch = "wasm32") {
            "wasm32-unknown-unknown"
        } else {
            std::env::consts::ARCH
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_encode_decode_roundtrip() {
        let payload = b"hello WASM";
        let frame = wasm_ecnp_encode(0x04, payload);
        assert!(!frame.is_empty());
        let (msg_type, decoded_payload) = wasm_ecnp_decode(&frame).unwrap();
        assert_eq!(msg_type, 0x04);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_wasm_encode_all_types() {
        for t in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] {
            let frame = wasm_ecnp_encode(t, b"test");
            assert!(!frame.is_empty());
            let (decoded_type, _) = wasm_ecnp_decode(&frame).unwrap();
            assert_eq!(decoded_type, t);
        }
    }

    #[test]
    fn test_wasm_validate() {
        let frame = wasm_ecnp_encode(0x04, b"test");
        assert!(wasm_ecnp_validate(&frame));
        assert!(!wasm_ecnp_validate(&[0xff, 0x00]));
    }

    #[test]
    fn test_wasm_decode_invalid() {
        assert!(wasm_ecnp_decode(&[]).is_err());
        assert!(wasm_ecnp_decode(&[0xff]).is_err());
    }

    #[test]
    fn test_wasm_protocol_version() {
        assert_eq!(wasm_protocol_version(), "ECNP/1.1");
    }

    #[test]
    fn test_wasm_bridge_info() {
        let info = wasm_bridge_info();
        assert_eq!(info.protocol, "ECNP/1.1");
        assert_eq!(info.message_types.len(), 8);
        assert!(info.message_types.contains(&"Heartbeat"));
    }

    #[test]
    fn test_wasm_bridge_info_serialize() {
        let info = wasm_bridge_info();
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("ECNP/1.1"));
    }

    #[test]
    fn test_wasm_fallback_type() {
        // Unknown type → fallback to Data (0x02)
        let frame = wasm_ecnp_encode(0xFF, b"unknown");
        let (msg_type, _) = wasm_ecnp_decode(&frame).unwrap();
        assert_eq!(msg_type, 0x02); // Data type
    }
}
